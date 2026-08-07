"""Redaction gap tests for ``plugins/_mcp/_session_adapter.py`` (DCR-0022, DCR-0023).

Part of the coordinated "redact at the write/forward boundary" pass across
``cli.py`` / ``scan/engine.py`` / ``_session_adapter.py`` — see
``docs/reviews/2026-08-07-0.7.9-any-provider-review.md``.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp._session_adapter import _RecordingServerShim
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.scan._types import AdapterInvocationSkipped

_SECRET = "sk-ant-" + "f" * 40


class _ResultStub:
    def __init__(self, content: Any, *, is_error: bool = False) -> None:
        self.content = content
        self.isError = is_error


class _InnerServerStub:
    """Minimal ``_ServerLike`` double whose call_tool result carries a secret."""

    async def list_tools(self) -> list[Any]:
        return []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        del name, arguments
        return _ResultStub(f"tool output leaked: {_SECRET}")


@pytest.mark.asyncio
async def test_recording_server_shim_redacts_result_same_as_args() -> None:
    """DCR-0022: `entry["args"]` is redacted via `redact_value` before the entry
    is appended to the sink; `entry["result"]` must be redacted the same way --
    a target's tool result is exactly as capable of carrying a live secret
    (e.g. a planner-triggered read of a credential) as a call argument, and
    this sink is what `mcp_trace_planner` (persisted to scan_report.json /
    exploit_*.json) is built from."""
    sink: list[dict[str, Any]] = []
    shim = _RecordingServerShim(_InnerServerStub(), sink)  # type: ignore[arg-type]

    await shim.call_tool("read_secret", {"id": "note-1"})

    assert len(sink) == 1
    assert _SECRET not in sink[0]["result"]


class _RaisingSessionCM:
    """Async context manager whose __aenter__ raises with a secret-shaped message."""

    async def __aenter__(self) -> Any:
        raise RuntimeError(f"connection failed: Authorization: Bearer {_SECRET}")

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


@pytest.mark.asyncio
async def test_invoke_adapter_failure_skip_reason_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DCR-0023: the generic `except Exception as exc` branch in `invoke()`
    embeds `{exc!r}` verbatim into the `AdapterInvocationSkipped` reason, which
    ScanEngine stores unredacted as `ScanAttempt.verdict_reason` -- a secret
    surfaced through a raised exception (e.g. an auth header echoed by a
    transport error) must not survive into that skip reason."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _RaisingSessionCM())

    payload = Payload(pattern_id="p", channel="tool-result", body="x")

    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(payload)

    assert _SECRET not in excinfo.value.reason
