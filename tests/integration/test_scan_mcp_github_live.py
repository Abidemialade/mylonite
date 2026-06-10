"""Live end-to-end scan against the real GitHub MCP server.

Gated behind ``MYLONITE_LIVE_E2E=1`` AND requires both ``GITHUB_TOKEN`` and
``MYLONITE_TEST_GITHUB_REPO`` env vars. The repo MUST be a throwaway —
this test creates real issues in it.

After the test, the issues are NOT auto-closed (the MCP server doesn't
expose ``close_issue`` in v1; teardown is the user's responsibility).
Limit: max 3 issues created per run.

Run with:

    npm install -g @modelcontextprotocol/server-github
    export GITHUB_TOKEN=ghp_throwaway_token
    export MYLONITE_TEST_GITHUB_REPO=myhandle/mylonite-test-repo
    MYLONITE_LIVE_E2E=1 pytest tests/integration/test_scan_mcp_github_live.py -v
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mylonite.plugins._mcp.stdio_adapter import GitHubMCPAdapter
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="Live e2e gated behind MYLONITE_LIVE_E2E=1",
)


@pytest.mark.asyncio
async def test_live_scan_mcp_github_finds_exploit(tmp_path: Path) -> None:
    if shutil.which("npx") is None:
        pytest.skip("npx not available — install Node.js to run the github MCP server")
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN not set — required for the live github MCP server")
    repo = os.environ.get("MYLONITE_TEST_GITHUB_REPO")
    if not repo:
        pytest.skip("MYLONITE_TEST_GITHUB_REPO not set — required as scope")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — required for the live LLM call")

    adapter = GitHubMCPAdapter(scope=repo)
    customiser = PayloadCustomiser(model="claude-sonnet-4-6")
    judge = SuccessJudge(model="claude-sonnet-4-6")

    config = ScanConfig(
        target_id=f"mcp:github:{repo}",
        provider="anthropic",
        model="claude-sonnet-4-6",
        # Hard cap to limit issue creation rate per plan-eng-review T3.
        max_llm_calls=20,
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
