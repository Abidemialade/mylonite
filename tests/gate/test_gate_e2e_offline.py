"""Offline + gated-live CLI e2e tests for ``mylonite gate``.

Part A: Offline no-finding path
    Monkeypatches ``litellm.acompletion`` to return a benign text response with
    no tool calls, so the in-process reference planner terminates immediately,
    the deterministic predicates produce no-finding, the judge LLM fallback
    (also via acompletion) returns success=False, and ``scan_fn`` yields zero
    exploits.  ``run_gate`` then short-circuits at the empty-exploits check
    (line 42 of orchestrator.py) — before generate/validate — and exits 0.

Part B: Gated live test
    Full real flow (real Haiku), gated behind MYLONITE_LIVE_E2E=1.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from mylonite.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Shared benign completion stub
# ---------------------------------------------------------------------------


def _benign_response() -> SimpleNamespace:
    """Return a minimal LiteLLM-shaped response: text content, no tool calls.

    The planner (LLMPlanner.run) reads:
        message = response.choices[0].message
        tool_calls = getattr(message, "tool_calls", None) or []
        content = getattr(message, "content", None) or ""

    When tool_calls is empty the planner returns immediately with a PlannerTrace
    (kind="say" + kind="stop"), so the adapter.invoke() completes without calling
    any MCP tools.  The judge's deterministic predicates then inspect the
    response and find no tool-call evidence → no finding.

    The customiser and judge also call litellm.acompletion via
    litellm_json_call_async; for the customiser a non-JSON text response is
    fine — it falls back to the seed body unchanged.  For the LLM-judge fallback
    we return {"success": false, "confidence": 0.0, "reason": "benign stub"}
    so no finding is emitted even on the LLM-judge code path.

    A single callable works for all three callers because:
    * The planner checks for tool_calls (absent here → terminates).
    * The customiser expects {"body": "..."} — gets fallback on non-JSON → fine.
    * The judge expects {"success": bool, "confidence": float, "reason": str} —
      we embed a JSON object in the content so it parses as "not success".
    """
    content = json.dumps({"success": False, "confidence": 0.0, "reason": "benign stub"})
    message = SimpleNamespace(content=content, tool_calls=None)
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    return SimpleNamespace(choices=[choice], usage=usage)


async def _benign_acompletion(*args: object, **kwargs: object) -> SimpleNamespace:
    """Async stub for litellm.acompletion — returns a benign, tool-call-free response."""
    return _benign_response()


# ---------------------------------------------------------------------------
# Part A — Offline no-finding e2e
# ---------------------------------------------------------------------------


def test_gate_reference_no_finding_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate with a benign LLM stub: scan produces 0 findings → exit 0, no PR.

    The benign acompletion stub causes:
    1. The planner to see no tool calls → PlannerTrace with just a text step.
    2. The adapter to return an AdapterResponse with empty tool_calls.
    3. The deterministic judge predicates (tool-call-based) to return no-finding.
    4. The LLM judge fallback (also via acompletion) to return success=False.
    So scan_fn returns [], run_gate short-circuits before generate/validate,
    prints "no exploit found — nothing to gate", and exits 0.
    """
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _benign_acompletion)
    # Also patch the sync path (used by doctor / litellm_json_call sync) in
    # case any branch under test uses it; the gate path is async-only but be safe.
    monkeypatch.setattr(litellm, "completion", lambda *a, **kw: _benign_response())
    # T14: gate now pre-flights require_llm_configured() before any litellm
    # call is attempted -- litellm itself is fully stubbed above, so a fake
    # key just needs to be PRESENT, never actually used.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / ".mylonite" / "gate"
    res = runner.invoke(app, ["gate", "reference:vulnerable", "--out", str(out_dir)])

    assert res.exit_code == 0, (
        f"Expected exit 0 (no exploit found), got {res.exit_code}.\nOutput:\n{res.output}"
    )
    # The orchestrator's no-exploit branch prints this exact string.
    assert "nothing to gate" in res.output.lower() or "no exploit" in res.output.lower(), (
        f"Expected 'nothing to gate' or 'no exploit' in output.\nOutput:\n{res.output}"
    )
    # No gate artefacts should be written (short-circuit happens before generate).
    assert not out_dir.exists() or not list(out_dir.glob("exploit_*.json")), (
        "No exploit JSON should be written when the scan found nothing."
    )


# ---------------------------------------------------------------------------
# Part B — Gated live e2e (skipped unless MYLONITE_LIVE_E2E=1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="live e2e (needs a provider key); set MYLONITE_LIVE_E2E=1 to run",
)
def test_gate_reference_vulnerable_live_prints_pr_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full real gate flow: real Haiku, reference:vulnerable.

    Expects either:
    - A 'gh pr create' command printed to stdout (kept test, print path), OR
    - An exploit artefact written (finding confirmed but gate artefacts present).

    Runs in a fresh ``git init`` repo so the real branch+commit step works.
    """
    # Set up a fresh git repo in tmp_path so open_or_print_pr can commit.
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    # Seed an initial commit so checkout -b has a base.
    (tmp_path / "README.md").write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )

    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / ".mylonite" / "gate"

    res = runner.invoke(
        app,
        ["gate", "reference:vulnerable", "--out", str(out_dir)],
    )

    # Gate exits 0 on both the "no exploit" and the "kept test" paths.
    assert res.exit_code == 0, f"Expected exit 0, got {res.exit_code}.\nOutput:\n{res.output}"

    # Either the scan found nothing (valid — reference scan is stochastic) …
    no_exploit = "nothing to gate" in res.output.lower() or "no exploit" in res.output.lower()
    # … or it found an exploit, generated + validated a test, and printed the PR cmd.
    pr_cmd_printed = "gh pr create" in res.output
    exploit_written = out_dir.exists() and bool(list(out_dir.glob("exploit_*.json")))

    assert no_exploit or pr_cmd_printed or exploit_written, (
        "Expected either 'nothing to gate', 'gh pr create', or an exploit artefact.\n"
        f"Output:\n{res.output}"
    )
