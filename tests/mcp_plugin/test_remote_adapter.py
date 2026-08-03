"""Tests for the remote (SSE/HTTP) MCP adapter + transport-aware factory.

The transport-specific surface is small: the ``_session`` seam, the host-only
descriptor strings (no header leakage), transport dispatch, and the target-file
validator. The shared attack body (``invoke``/plant/judge) is exercised by the
stdio adapter tests — it is the same base method.

Following the stdio tests, the SSE/HTTP client boundary is stubbed so no real
server or network is needed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import Tool as MCPTool

from mylonite.plugins._mcp import remote_adapter, target_registry
from mylonite.plugins._mcp.factory import build_mcp_adapter
from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter, _host_only
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec


class _FakeSession:
    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[MCPTool(name="do_thing", description="does a thing", inputSchema={})]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return SimpleNamespace(content=f"{name} ok", isError=False)


@asynccontextmanager
async def _fake_remote_open(*_args: Any, **_kwargs: Any):
    yield _FakeSession()


def _register_remote(family: str = "remote-app", *, transport: str = "sse") -> None:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family=family,
        transport=transport,  # type: ignore[arg-type]
        url="https://target.example/mcp?token=SECRET",
        headers={"Authorization": "Bearer SUPERSECRET"},
        weakness_classes=["W4"],
    )
    target_registry.register_target(build_target_spec(tf))


@pytest.fixture(autouse=True)
def _clean_registry():
    yield
    target_registry.clear_runtime_targets()


async def test_describe_reports_host_only_never_headers_or_token() -> None:
    _register_remote()
    adapter = MCPRemoteAdapter(family="remote-app", scope=None)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(remote_adapter, "_open_remote_session", _fake_remote_open)
        descriptor = await adapter.describe()
    blob = " ".join(descriptor.data_sources) + " " + (descriptor.notes or "")
    assert "target.example" in blob  # host present
    assert "SUPERSECRET" not in blob  # header secret never leaks
    assert "SECRET" not in blob  # url query token never leaks
    assert "token=" not in blob
    assert [t.name for t in descriptor.tools] == ["do_thing"]
    assert descriptor.weakness_classes == ["W4"]


def _register_remote_with_userinfo(family: str = "remote-app-creds") -> None:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family=family,
        transport="sse",  # type: ignore[arg-type]
        url="https://sk-live-abc123@target.example/mcp",
        weakness_classes=["W4"],
    )
    target_registry.register_target(build_target_spec(tf))


async def test_describe_never_leaks_url_embedded_userinfo_credentials() -> None:
    # RB-DCR-0001: `urlsplit(...).netloc` includes userinfo (`user:pass@host` or
    # `token@host`); a bearer-token-in-URL target must never surface it via the
    # host-only descriptor.
    _register_remote_with_userinfo()
    adapter = MCPRemoteAdapter(family="remote-app-creds", scope=None)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(remote_adapter, "_open_remote_session", _fake_remote_open)
        descriptor = await adapter.describe()
    blob = " ".join(descriptor.data_sources) + " " + (descriptor.notes or "")
    assert "target.example" in blob
    assert "sk-live-abc123" not in blob


def test_host_only_degrades_gracefully_on_a_malformed_out_of_range_port() -> None:
    # Code-review followup (Important #1): `urlsplit(url).port` is lazily
    # validated and raises `ValueError` for an out-of-range/non-numeric port.
    # A remote target's `url` comes from an operator-supplied target file with
    # no port-range validation, so a malformed configured URL must not crash
    # `describe()` — `_host_only` must degrade gracefully (omit the port),
    # the same way it already handles `hostname=None`.
    result = _host_only("https://host:99999/sse")
    assert result == "host"


def test_host_only_brackets_ipv6_host_with_a_port() -> None:
    # Code-review followup (Important #2): the host+port string must stay
    # unambiguous. Without bracketing, "::1:8080" can't be parsed back into
    # address vs. port (IPv6 addresses themselves contain ":").
    result = _host_only("https://[::1]:8080/sse")
    assert result == "[::1]:8080"


def test_host_only_bare_ipv6_with_no_port_is_unbracketed() -> None:
    # No port -> no ambiguity, so the bare address is fine as-is.
    result = _host_only("https://[::1]/sse")
    assert result == "::1"


def test_factory_dispatches_on_transport() -> None:
    _register_remote(transport="sse")
    assert isinstance(build_mcp_adapter(family="remote-app", scope=None), MCPRemoteAdapter)

    target_registry.clear_runtime_targets()
    tf = TargetFile(family="stdio-app", command="echo", weakness_classes=["W4"])
    target_registry.register_target(build_target_spec(tf))
    assert isinstance(build_mcp_adapter(family="stdio-app", scope=None), MCPStdioAdapter)


async def test_open_remote_session_selects_sse_and_passes_headers() -> None:
    captured: dict[str, Any] = {}

    @asynccontextmanager
    async def fake_sse_client(url: str, headers: Any = None):
        captured["url"] = url
        captured["headers"] = headers
        yield ("READ", "WRITE")  # 2-tuple, like the real sse_client

    class _FakeCS:
        def __init__(self, read: Any, write: Any, **kwargs: Any) -> None:
            captured["streams"] = (read, write)

        async def __aenter__(self):
            return _FakeSession()

        async def __aexit__(self, *exc: Any) -> None:
            return None

    import mcp.client.sse as sse_mod

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sse_mod, "sse_client", fake_sse_client)
        mp.setattr(remote_adapter, "ClientSession", _FakeCS)
        async with remote_adapter._open_remote_session(
            "sse", "https://h/mcp", {"Authorization": "Bearer X"}
        ) as session:
            assert isinstance(session, _FakeSession)
    assert captured["url"] == "https://h/mcp"
    assert captured["headers"] == {"Authorization": "Bearer X"}
    assert captured["streams"] == ("READ", "WRITE")


async def test_open_remote_session_handles_http_three_tuple() -> None:
    @asynccontextmanager
    async def fake_http_client(url: str, headers: Any = None):
        yield ("READ", "WRITE", lambda: "session-id")  # 3-tuple, like streamablehttp_client

    class _FakeCS:
        def __init__(self, read: Any, write: Any, **kwargs: Any) -> None:
            assert (read, write) == ("READ", "WRITE")

        async def __aenter__(self):
            return _FakeSession()

        async def __aexit__(self, *exc: Any) -> None:
            return None

    import mcp.client.streamable_http as http_mod

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(http_mod, "streamablehttp_client", fake_http_client)
        mp.setattr(remote_adapter, "ClientSession", _FakeCS)
        async with remote_adapter._open_remote_session("http", "https://h/mcp", None) as session:
            assert isinstance(session, _FakeSession)


async def test_open_remote_session_passes_read_timeout_to_client_session() -> None:
    # RB-DCR-0002: a non-responding remote server must not hang
    # `session.initialize()` forever — `ClientSession` must be constructed with
    # a bounded `read_timeout_seconds`.
    import datetime as _dt

    captured: dict[str, Any] = {}

    @asynccontextmanager
    async def fake_sse_client(url: str, headers: Any = None):
        yield ("READ", "WRITE")

    class _FakeCS:
        def __init__(self, read: Any, write: Any, *args: Any, **kwargs: Any) -> None:
            captured["kwargs"] = kwargs
            captured["args"] = args

        async def __aenter__(self):
            return _FakeSession()

        async def __aexit__(self, *exc: Any) -> None:
            return None

    import mcp.client.sse as sse_mod

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sse_mod, "sse_client", fake_sse_client)
        mp.setattr(remote_adapter, "ClientSession", _FakeCS)
        async with remote_adapter._open_remote_session("sse", "https://h/mcp", None):
            pass

    read_timeout = captured["kwargs"].get("read_timeout_seconds")
    if read_timeout is None and captured["args"]:
        read_timeout = captured["args"][0]
    assert read_timeout is not None, (
        "ClientSession must be given a bounded read_timeout_seconds so a "
        "non-responding remote server cannot hang initialize() forever"
    )
    assert isinstance(read_timeout, _dt.timedelta)
    # Bounded on both ends: > 0 (must actually time out) and a sane upper
    # bound (catches a future accidental huge-timeout regression, e.g. a
    # typo'd `timedelta(seconds=6000)`).
    assert 0 < read_timeout.total_seconds() <= 300


def test_remote_classify_failure_maps_httpx_errors() -> None:
    assert MCPRemoteAdapter._classify_failure(type("ConnectError", (Exception,), {})()) == (
        "init_failure"
    )
    assert MCPRemoteAdapter._classify_failure(type("HTTPStatusError", (Exception,), {})()) == (
        "mcp_protocol_error"
    )


def test_target_file_validates_transport() -> None:
    # remote requires url
    with pytest.raises(ValueError, match="requires a 'url'"):
        TargetFile(family="x", transport="sse")
    # stdio rejects url
    with pytest.raises(ValueError, match="only valid for transport"):
        TargetFile(family="x", command="echo", url="https://h")
    # stdio requires command
    with pytest.raises(ValueError, match="requires a 'command'"):
        TargetFile(family="x")
    # valid remote: command optional
    tf = TargetFile(family="x", transport="http", url="https://h/mcp")
    assert tf.command == ""
    spec = build_target_spec(tf)
    assert spec.transport == "http"
    assert spec.url == "https://h/mcp"
