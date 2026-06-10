"""Live end-to-end scan against the real fetch MCP server.

Gated behind ``MYLONITE_LIVE_E2E=1``. Spawns ``uvx mcp-server-fetch``.
Uses a benign attacker-shaped marker URL (``httpbin.org/anything``) so we
don't actually try to egress to ``attacker.example.com`` (DNS would fail).

Run with:

    pip install uv mcp-server-fetch
    MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_fetch_live.py -v
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mylonite.plugins._mcp.stdio_adapter import FetchMCPAdapter
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="Live e2e gated behind MYLONITE_LIVE_E2E=1",
)


@pytest.mark.asyncio
async def test_live_scan_mcp_fetch_finds_exploit(tmp_path: Path) -> None:
    if shutil.which("uvx") is None:
        pytest.skip("uvx not available — install uv (https://github.com/astral-sh/uv)")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — required for the live LLM call")

    adapter = FetchMCPAdapter()
    customiser = PayloadCustomiser(model="claude-sonnet-4-6")
    judge = SuccessJudge(model="claude-sonnet-4-6")

    config = ScanConfig(
        target_id="mcp:fetch",
        provider="anthropic",
        model="claude-sonnet-4-6",
        max_llm_calls=30,
        max_concurrent=1,
        output_dir=tmp_path / "scans",
    )
    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=[ExcessiveAgencyAttackModule()],
        customiser=customiser,
        judge=judge,
    )

    result = await engine.run()
    assert result.report.findings_count >= 1, result.report
