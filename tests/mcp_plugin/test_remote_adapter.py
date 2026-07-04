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
from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter
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
        def __init__(self, read: Any, write: Any) -> None:
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
        def __init__(self, read: Any, write: Any) -> None:
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
