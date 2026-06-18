"""Live: real MCP-subprocess AttackSession lifecycle (no network).

Launches a tiny local Python stdio MCP server as a subprocess and verifies the
one thing the offline fake harness cannot: that opening the real
``stdio_client``/``ClientSession`` in ``open_session`` and exiting it in
``close`` — within a single coroutine, as the adaptive driver's ``_attempt``
does — round-trips a tool call and does NOT raise anyio's "cancel scope in a
different task" error. Gated behind MYLONITE_LIVE_E2E (spawns a subprocess);
needs no network (uses the bundled tiny server, not an npm/uvx download).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="Live e2e (spawns a subprocess); set MYLONITE_LIVE_E2E=1 to run",
)

_SERVER = str(Path(__file__).parent / "_tiny_mcp_server.py")


@pytest.mark.asyncio
async def test_open_session_lifecycle_against_real_subprocess() -> None:
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec

    target_registry.clear_runtime_targets()
    spec = build_target_spec(TargetFile(family="tinytest", command=sys.executable, args=[_SERVER]))
    target_registry.register_target(spec)
    try:
        adapter = MCPStdioAdapter(family="tinytest", scope=None)
        session = await adapter.open_session()
        try:
            outcome = await session.call_tool("ping", {})
            assert outcome.tool == "ping"
            assert outcome.is_error is False
            assert "pong" in outcome.result
        finally:
            # The load-bearing check: open + use + close on a REAL subprocess in
            # one coroutine must not raise the anyio cancel-scope error.
            await session.close()
    finally:
        target_registry.clear_runtime_targets()
