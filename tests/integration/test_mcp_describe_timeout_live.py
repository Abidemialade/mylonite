"""Live: describe()'s first-contact timeout against a real slow subprocess.

A fake-session double that raises a bare ``TimeoutError``/``McpError``
directly (see ``tests/mcp_plugin/test_stdio_adapter.py``) never reproduces
the actual shape a timeout takes against the real SDK: the MCP SDK's own
session plumbing wraps whatever escapes its ``asyncio.TaskGroup``s, so a real
hung/slow server's timeout arrives nested two ``ExceptionGroup`` layers deep
around the ``McpError`` (confirmed empirically against the real
``stdio_client``/``ClientSession`` while diagnosing the bug this test
guards). This test spawns a real subprocess that delays before it ever opens
the stdio transport -- standing in for a slow `npx -y`/`uvx` package
download -- with a short ``mcp_read_timeout_s``, so the real wrapping
happens, and checks the resulting ``AdapterDescribeFailed`` carries the
operator-ready first-contact message, not the generic "could not launch"
fallback the wrapping used to cause it to fall through to.

Gated behind MYLONITE_LIVE_E2E (spawns a subprocess); needs no network (uses
the bundled sleepy server, not an npm/uvx download).
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

_SERVER = str(Path(__file__).parent / "_sleepy_mcp_server.py")


@pytest.mark.asyncio
async def test_describe_timeout_against_a_real_slow_server_names_seconds_and_remedies() -> None:
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
    from mylonite.scan._types import AdapterDescribeFailed

    target_registry.clear_runtime_targets()
    spec = build_target_spec(
        TargetFile(family="sleepy-live", command=sys.executable, args=[_SERVER, "5"])
    )
    target_registry.register_target(spec)
    try:
        # A short connect budget -- the server sleeps 5s before it even opens
        # the transport, so a 1s timeout here reliably fires without this
        # test itself taking anywhere near 5s.
        adapter = MCPStdioAdapter(family="sleepy-live", scope=None, mcp_read_timeout_s=1.0)
        with pytest.raises(AdapterDescribeFailed) as excinfo:
            await adapter.describe()
    finally:
        target_registry.clear_runtime_targets()

    message = str(excinfo.value)
    lowered = message.lower()
    # Plainly names the effective timeout...
    assert "1s" in message
    # ...names the first-run npx/uvx download as the likely cause...
    assert "npx" in lowered and "uvx" in lowered
    # ...and gives both remedies: run the command once (or install), or raise
    # the timeout, naming the knob.
    assert "run the server's launch command once" in lowered
    assert "install the package" in lowered
    assert "timeout_s" in message
    # Must NOT have fallen through to the generic launch-failure message --
    # that is exactly the bug this test guards (the ExceptionGroup-wrapped
    # timeout bypassing the operator-ready message entirely).
    assert "could not launch or connect to the target" not in lowered
