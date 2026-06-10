"""Live end-to-end scan against the real Anthropic filesystem MCP server.

Gated behind ``MYLONITE_LIVE_E2E=1``. Spawns a real subprocess via
``npx -y @modelcontextprotocol/server-filesystem``, drives the real
configured LLM, and asserts ≥1 finding. Use a throwaway sandbox directory;
the test creates files in it.

Run with:

    npm install -g @modelcontextprotocol/server-filesystem
    MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_filesystem_live.py -v
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mylonite.plugins._mcp.stdio_adapter import FilesystemMCPAdapter
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="Live e2e gated behind MYLONITE_LIVE_E2E=1",
)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    s = tmp_path / "sandbox"
    s.mkdir()
    yield s
    # Best-effort cleanup; sandbox is under tmp_path which pytest cleans.


@pytest.mark.asyncio
async def test_live_scan_mcp_filesystem_finds_exploit(sandbox: Path) -> None:
    if shutil.which("npx") is None:
        pytest.skip("npx not available — install Node.js to run the filesystem MCP server")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — required for the live LLM call")

    adapter = FilesystemMCPAdapter(scope=str(sandbox))
    customiser = PayloadCustomiser(model="claude-sonnet-4-6")
    judge = SuccessJudge(model="claude-sonnet-4-6")

    config = ScanConfig(
        target_id=f"mcp:filesystem:{sandbox}",
        provider="anthropic",
        model="claude-sonnet-4-6",
        max_llm_calls=50,
        max_concurrent=1,
        output_dir=sandbox.parent / "scans",
    )
    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=[PromptInjectionAttackModule()],
        customiser=customiser,
        judge=judge,
    )

    result = await engine.run()
    assert result.report.findings_count >= 1, result.report
