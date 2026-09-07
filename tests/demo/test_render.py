"""Tests for the ``mylonite demo`` differential renderer.

``render_demo`` takes the two ScanResults the demo runner produced
(reference:vulnerable / reference:guarded), aggregates the 8 kitchen-sink
seed attempts into the 4 weakness rows W1-W4, and prints the safety banner,
differential table, computed headline, next-steps teaser, next-step line, and
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
    assert "reference app" in output
    assert "DEMO ONLY" in output
    assert "deliberately vulnerable in-process agent" in output
    assert "It never binds to a network." in output
    assert "Never point Mylonite at a system you don't own or operate" in output
    assert "(see SECURITY.md)" in output

    # Headline computed from the actual ScanResults.
    assert (
        "reference app: 2 exploits on vulnerable, 0 on guarded — this differential "
        "is the oracle that validates every generated regression test"
    ) in output
    assert "unexpected finding on the guarded build" not in output

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
        "Each finding becomes a committed regression test, validated against this "
        "same vulnerable/guarded oracle. Turn one into a gating test: "
        "mylonite gate reference:vulnerable"
    ) in output
    # `--command` takes the executable and `--arg` each argument; a single
    # "python server.py" string would be exec'd as one literal filename.
    assert "mylonite scan --command python --arg server.py --scaffold app.yaml" in output
    assert "mylonite scan --target-file app.yaml --authorize my-app" in output
    assert "needs an LLM API key" in output
    assert "docs/test-your-app.md" in output
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
    assert ("unexpected finding on the guarded build — LLM-judge noise or a real bug") in output


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


# --- verdict-mark styling ---------------------------------------------------
#
# `_render` above exports plain text, which discards styling, so nothing in this
# file could see the marks' colour. These pin it directly: the differential is
# meant to be legible as SHAPE before it is read as words, and an uncoloured
# table renders FOUND and clean as the same weight of text.


def test_styled_wraps_each_known_mark_in_its_own_style() -> None:
    from mylonite.demo.render import _CLEAN_MARK, _FOUND_MARK, _SKIPPED_MARK, _styled

    assert _styled(_FOUND_MARK) == f"[bold red]{_FOUND_MARK}[/bold red]"
    assert _styled(_CLEAN_MARK) == f"[bold green]{_CLEAN_MARK}[/bold green]"
    assert _styled(_SKIPPED_MARK) == f"[bold yellow]{_SKIPPED_MARK}[/bold yellow]"


def test_styled_passes_an_unknown_mark_through_unchanged() -> None:
    """A future OUTCOME_MARKS entry with no style must render, not crash.

    `_aggregate_mark` can return any mark in the table; an unmapped one falls
    through verbatim rather than being wrapped in a broken markup tag.
    """
    from mylonite.demo.render import _styled

    assert _styled("⚠ NOT TESTED") == "⚠ NOT TESTED"
    assert _styled("") == ""


def test_render_demo_emits_colour_for_the_verdict_marks() -> None:
    """End-to-end: the rendered table carries colour, not just glyphs."""
    import re

    vulnerable = _result(
        "reference:vulnerable",
        _outcomes(
            {
                "excessive-agency-fetch-attacker-url-direct": "finding",
                "tool-description-summary-smuggle": "skipped_planner_failure",
            }
        ),
    )
    guarded = _result("reference:guarded", _outcomes())

    console = Console(
        file=io.StringIO(), record=True, width=240, force_terminal=True, color_system="truecolor"
    )
    render_demo(vulnerable, guarded, mode="replay (offline)", elapsed_s=0.1, console=console)
    html = console.export_html(inline_styles=True, clear=False)

    colours = set(re.findall(r"color: (#[0-9a-fA-F]{6})", html))
    # Foreground/background plus the panel border alone would be three; the three
    # verdict styles have to add to that, and they must differ from each other.
    assert len(colours) >= 5, f"expected distinct verdict colours, saw {sorted(colours)}"
