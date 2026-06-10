"""Tests for the ``mylonite demo`` differential renderer (PR A, Task A2).

``render_demo`` takes the two ScanResults the demo runner produced
(reference:vulnerable / reference:guarded), aggregates the 8 kitchen-sink
seed attempts into the 4 weakness rows W1-W4, and prints the safety banner,
differential table, computed headline, Phase 2 teaser, next-step line, and
mode/elapsed footer through a ``rich.Console``.

The ScanResults are built from the real dataclasses / Pydantic models — no
mocks — so these tests pin the renderer to the actual engine output shape.
"""

from __future__ import annotations

import io

from rich.console import Console

from mylonite.contracts._types import ScanAttempt, ScanAttemptOutcome, ScanReport
from mylonite.demo.render import render_demo
from mylonite.scan.engine import ScanResult

# The eight kitchen-sink pattern_ids, grouped by seeded weakness (must match
# SEED_CATALOGUE / reference_targets/mcp_kitchen_sink/seeds/seeds.yaml).
_W1 = ("tool-description-summary-smuggle",)
_W2 = (
    "indirect-injection-note-body-direct",
    "indirect-injection-note-body-roleplay",
    "indirect-injection-note-body-tool-chain",
)
_W3 = (
    "excessive-agency-fetch-attacker-url-direct",
    "excessive-agency-fetch-via-note-body",
)
_W4 = (
    "excessive-agency-send-email-direct-unconfirmed",
    "excessive-agency-send-email-via-note-injection",
)
_ALL_PATTERNS = _W1 + _W2 + _W3 + _W4


def _attempt(pattern_id: str, outcome: ScanAttemptOutcome) -> ScanAttempt:
    return ScanAttempt(
        seed_id=pattern_id,
        pattern_id=pattern_id,
        outcome=outcome,
        verdict_mechanism="predicate" if outcome in ("finding", "no_finding") else None,
        verdict_reason="synthetic verdict for renderer tests",
        error_detail="RuntimeError" if outcome == "error" else None,
    )


def _result(target_id: str, outcomes: dict[str, ScanAttemptOutcome]) -> ScanResult:
    attempts = [_attempt(pattern_id, outcome) for pattern_id, outcome in outcomes.items()]
    report = ScanReport(
        target_id=target_id,
        attack_modules=["mylonite.prompt-injection", "mylonite.excessive-agency"],
        provider="anthropic",
        model="synthetic-model",
        elapsed_seconds=0.4,
        attempts=attempts,
        findings_count=sum(1 for outcome in outcomes.values() if outcome == "finding"),
        aborted=None,
        single_run=True,
        mylonite_version="0.0.0-test",
    )
    return ScanResult(report=report, exploits=[])


def _outcomes(
    overrides: dict[str, ScanAttemptOutcome] | None = None,
) -> dict[str, ScanAttemptOutcome]:
    outcomes: dict[str, ScanAttemptOutcome] = dict.fromkeys(_ALL_PATTERNS, "no_finding")
    outcomes.update(overrides or {})
    return outcomes


def _render(
    vulnerable: ScanResult,
    guarded: ScanResult,
    *,
    mode: str = "replay (offline)",
    elapsed_s: float = 0.8,
) -> str:
    console = Console(file=io.StringIO(), record=True, width=240)
    render_demo(vulnerable, guarded, mode=mode, elapsed_s=elapsed_s, console=console)
    return console.export_text()


def test_render_clean_differential() -> None:
    """Vulnerable has findings, guarded is clean → full demo output renders."""
    vulnerable = _result(
        "reference:vulnerable",
        _outcomes(
            {
                "indirect-injection-note-body-direct": "finding",
                "excessive-agency-fetch-attacker-url-direct": "finding",
            }
        ),
    )
    guarded = _result("reference:guarded", _outcomes())

    output = _render(vulnerable, guarded)

    # Safety banner — exact wording, modulo Rich line wrapping.
    assert "Quarry" in output
    assert "DEMO ONLY" in output
    assert "deliberately vulnerable in-process reference agent" in output
    assert "It never binds to a network." in output
    assert "Never point Mylonite at a system you don't own or operate" in output
    assert "(see SECURITY.md)" in output

    # Headline computed from the actual ScanResults.
    assert (
        "the Quarry: 2 exploits on vulnerable, 0 on guarded — this differential "
        "is the oracle that will validate generated tests in Phase 2"
    ) in output
    assert "unexpected finding on the guarded twin" not in output

    # Per-weakness table: names + taxonomy IDs from the seed catalogue.
    assert "tool-description-instruction-smuggling" in output
    assert "indirect-injection-via-note-body" in output
    assert "unrestricted-web-fetch" in output
    assert "unconfirmed-email-send" in output
    assert "LLM01" in output
    assert "ASI02" in output
    assert "AML.T0051" in output
    # Outcome marks reuse the public OUTCOME_MARKS vocabulary.
    assert "✗ FOUND" in output
    assert "✓ clean" in output

    # Teaser, next step, and footer.
    assert (
        "Phase 2 (in progress): each finding becomes a generated regression "
        "test, validated against this same vulnerable/guarded oracle."
    ) in output
    assert "mylonite scan mcp:fetch --authorize fetch" in output
    assert "needs an LLM API key + uv" in output
    assert "docs/quarry.md" in output
    assert "mode: replay (offline)" in output
    assert "0.8s" in output


def test_render_guarded_finding_is_reported_not_hardcoded() -> None:
    """A finding on the guarded twin shows the real count + an explicit note."""
    vulnerable = _result(
        "reference:vulnerable",
        _outcomes({"indirect-injection-note-body-direct": "finding"}),
    )
    guarded = _result(
        "reference:guarded",
        _outcomes({"excessive-agency-send-email-direct-unconfirmed": "finding"}),
    )

    output = _render(vulnerable, guarded)

    assert "1 exploits on vulnerable, 1 on guarded" in output
    assert "0 on guarded" not in output
    assert ("unexpected finding on the guarded twin — LLM-judge noise or a real bug") in output


def test_render_skipped_and_error_outcomes_do_not_crash() -> None:
    """skipped_*/error attempts aggregate into the ⚠ skipped vocabulary."""
    vulnerable = _result(
        "reference:vulnerable",
        _outcomes(
            {
                "tool-description-summary-smuggle": "skipped_planner_failure",
                "indirect-injection-note-body-direct": "finding",
                "indirect-injection-note-body-roleplay": "error",
                "excessive-agency-fetch-attacker-url-direct": "skipped_invalid_metadata",
                "excessive-agency-fetch-via-note-body": "skipped_unknown_seed",
            }
        ),
    )
    guarded = _result(
        "reference:guarded",
        _outcomes({"excessive-agency-send-email-via-note-injection": "skipped_dry_run"}),
    )

    output = _render(vulnerable, guarded)

    assert "⚠ skipped" in output
    # W2 still reports FOUND: any finding in the weakness wins over skips.
    assert "✗ FOUND" in output
    assert "1 exploits on vulnerable, 0 on guarded" in output
