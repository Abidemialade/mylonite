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
from collections.abc import Iterable, Mapping

import pytest
from rich.console import Console

from mylonite.contracts._types import ScanAttempt, ScanAttemptOutcome, ScanReport
from mylonite.demo.render import render_demo
from mylonite.scan.coverage import NO_ADJUDICATOR
from mylonite.scan.engine import ScanResult

# The nine kitchen-sink pattern_ids, grouped by seeded weakness (must match
# SEED_CATALOGUE / reference_targets/mcp_kitchen_sink/seeds/seeds.yaml) --
# `test_the_pattern_ids_match_the_catalogue` below fails if they drift.
_W1 = (
    "tool-description-summary-smuggle",
    "tool-description-send-licence-smuggle",
)
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


def _attempt(
    pattern_id: str,
    outcome: ScanAttemptOutcome,
    *,
    judge_evidence: dict[str, str] | None = None,
) -> ScanAttempt:
    return ScanAttempt(
        seed_id=pattern_id,
        pattern_id=pattern_id,
        outcome=outcome,
        verdict_mechanism="predicate" if outcome in ("finding", "no_finding") else None,
        verdict_reason="synthetic verdict for renderer tests",
        error_detail="RuntimeError" if outcome == "error" else None,
        judge_evidence=judge_evidence or {},
    )


def _result(
    target_id: str,
    outcomes: dict[str, ScanAttemptOutcome],
    *,
    no_verdict: Mapping[str, str] | Iterable[str] = (),
) -> ScanResult:
    """Build a ScanResult; ``no_verdict`` names the attempts nothing adjudicated.

    Pass an iterable of pattern_ids for the demo's own case (predicate
    inconclusive, judge disabled), or a mapping of pattern_id → evidence key to
    exercise the other cause (a judge call that fell back). Both are recorded on
    ``judge_evidence`` exactly as the engine records them, so these tests fail if
    the key convention `scan.coverage` reads ever changes underneath the demo.
    """
    causes: Mapping[str, str] = (
        no_verdict
        if isinstance(no_verdict, Mapping)
        else dict.fromkeys(no_verdict, "no_adjudicator")
    )
    attempts = [
        _attempt(
            pattern_id,
            outcome,
            judge_evidence=(
                {"predicate": "reply_contains_marker", causes[pattern_id]: NO_ADJUDICATOR}
                if pattern_id in causes
                else None
            ),
        )
        for pattern_id, outcome in outcomes.items()
    ]
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

    # Headline computed from the actual ScanResults: the count on a line of its
    # own, so CI's grep for it never meets a wrap.
    lines = [line.strip() for line in output.splitlines()]
    assert "reference app: 2 exploits on vulnerable, 0 on guarded" in lines
    assert (
        "this differential is the oracle that validates every generated regression test"
    ) in lines
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
        "same vulnerable/guarded oracle. Turn one into a gating test:"
    ) in output
    assert "mylonite gate reference:vulnerable" in lines
    # `--command` takes the executable and `--arg` each argument; a single
    # "python server.py" string would be exec'd as one literal filename.
    assert "mylonite scan --command python --arg server.py \\" in lines
    assert "--scaffold app.yaml --scope my-app            # no API key" in lines
    assert "mylonite scan --target-file app.yaml --authorize my-app  # needs an API key" in lines
    assert "Try it on your own app (docs/test-your-app.md):" in lines
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
    from mylonite.demo.render import (
        _CLEAN_MARK,
        _FOUND_MARK,
        _NO_VERDICT_MARK,
        _SKIPPED_MARK,
        _styled,
    )

    assert _styled(_FOUND_MARK) == f"[bold red]{_FOUND_MARK}[/bold red]"
    assert _styled(_CLEAN_MARK) == f"[bold green]{_CLEAN_MARK}[/bold green]"
    assert _styled(_SKIPPED_MARK) == f"[bold yellow]{_SKIPPED_MARK}[/bold yellow]"
    assert _styled(_NO_VERDICT_MARK) == f"[bold yellow]{_NO_VERDICT_MARK}[/bold yellow]"


def test_styled_passes_an_unknown_mark_through_unchanged() -> None:
    """A future OUTCOME_MARKS entry with no style must render, not crash.

    `_aggregate_mark` can return any mark in the table; an unmapped one falls
    through verbatim rather than being wrapped in a broken markup tag.
    """
    from mylonite.demo.render import _styled

    # Deliberately a string no OUTCOME_MARKS value equals. "⚠ NOT TESTED" used
    # to serve here and no longer can: it is now a styled mark in its own right,
    # distinct from the generic "⚠ skipped".
    assert _styled("⚠ some future mark") == "⚠ some future mark"
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


def test_a_never_exercised_seed_renders_as_not_tested_not_skipped() -> None:
    """The distinction the demo table could not previously express.

    `skipped_planner_no_engagement` means the attack was delivered and the agent
    made no tool calls at all — it proves nothing about the target. Rendering it
    with the same generic mark as a harness error let an unexercised cell read
    as a boring skip beside a "0 exploits on guarded" headline.
    """
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result(
        "reference:guarded",
        _outcomes({"excessive-agency-fetch-attacker-url-direct": "skipped_planner_no_engagement"}),
    )

    output = _render(vulnerable, guarded)

    assert "⚠ NOT TESTED" in output
    assert "coverage:" in output
    assert "NOT TESTED" in output


def test_a_harness_failure_still_renders_as_a_plain_skip() -> None:
    """Negative control: the widened mapping must not relabel everything.

    A planner failure is a harness problem, not an unexercised attack, and keeps
    the generic mark.
    """
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result(
        "reference:guarded",
        _outcomes({"excessive-agency-fetch-attacker-url-direct": "skipped_planner_failure"}),
    )

    output = _render(vulnerable, guarded)

    assert "⚠ skipped" in output
    assert "⚠ NOT TESTED" not in output


def test_a_row_mixing_two_non_clean_kinds_falls_back_to_the_generic_mark() -> None:
    """A genuine ambiguity is rendered as one, not resolved by guessing.

    W3 has two seeds; giving them different non-clean outcomes means the row
    cannot honestly claim either label.
    """
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result(
        "reference:guarded",
        _outcomes(
            {
                "excessive-agency-fetch-attacker-url-direct": "skipped_planner_no_engagement",
                "excessive-agency-fetch-via-note-body": "skipped_planner_failure",
            }
        ),
    )

    output = _render(vulnerable, guarded)

    assert "⚠ skipped" in output


def test_no_coverage_note_when_every_seed_was_exercised() -> None:
    """The note must not cry wolf on a fully-exercised run."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes())

    output = _render(vulnerable, guarded)

    assert "coverage:" not in output


# ---------------------------------------------------------------------------
# Unadjudicated rows. The demo runs with the LLM judge disabled, so a predicate
# that cannot rule leaves the attempt with NO mechanism that decided it. The
# engine still records `no_finding` — the only outcome those code paths can
# produce — which the table read as a win for the target.


def _row(output: str, weakness: str) -> str:
    """The one rendered table row for ``weakness``, box-drawing and all.

    Only lines inside the table's box count: below the full table's width the
    taxonomy legend also starts its lines with the weakness ID.
    """
    rows = [
        line
        for line in output.splitlines()
        if line.startswith("│") and line.lstrip("│ ").startswith(f"{weakness} ")
    ]
    assert len(rows) == 1, f"expected exactly one {weakness} row, got {rows}"
    return rows[0]


def test_an_unadjudicated_no_finding_renders_as_no_verdict_not_clean() -> None:
    """The headline bug: `no_finding` with no adjudicator is not a clean result.

    Every W1 seed is left unadjudicated, so neither cell has a verdict to
    report — the shipped fixtures' shape before 0.10.0, where the predicate was
    inconclusive on both builds and the row nonetheless claimed the guard held
    on both. A row with SOME verdict is a different case, covered by
    `test_a_partly_adjudicated_clean_row_shows_its_coverage`.
    """
    vulnerable = _result("reference:vulnerable", _outcomes(), no_verdict=list(_W1))
    guarded = _result("reference:guarded", _outcomes(), no_verdict=list(_W1))

    row = _row(_render(vulnerable, guarded), "W1")

    assert row.count("⚠ NO VERDICT") == 2
    assert "✓ clean" not in row


def test_a_genuine_predicate_negative_still_renders_clean() -> None:
    """Negative control. Only the evidence separates this from the case above."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes())

    output = _render(vulnerable, guarded)

    assert _row(output, "W1").count("✓ clean") == 2
    assert "NO VERDICT" not in output


def test_a_judge_fallback_also_renders_as_no_verdict() -> None:
    """The other cause of a non-verdict, which `scan` can hit with the judge ON.

    A judge call that raised or returned unparseable output records
    ``fallback_cause``; a predicate left unadjudicated by a disabled judge
    records ``no_adjudicator``. Neither decided anything, and the demo must not
    treat the difference as meaningful.
    """
    fallbacks = dict.fromkeys(_W1, "fallback_cause")
    vulnerable = _result("reference:vulnerable", _outcomes(), no_verdict=fallbacks)
    guarded = _result("reference:guarded", _outcomes(), no_verdict=fallbacks)

    assert "⚠ NO VERDICT" in _row(_render(vulnerable, guarded), "W1")


def test_a_row_keeps_its_clean_mark_when_one_of_its_seeds_was_adjudicated() -> None:
    """Documented aggregation rule, pinned so the fix does not overshoot.

    W3 has two seeds. If one produced a real predicate negative, the row reports
    what that verdict supports — the note below the table still counts the other.
    """
    unadjudicated = _W3[0]
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes(), no_verdict=[unadjudicated])

    output = _render(vulnerable, guarded)

    assert "✓ clean" in _row(output, "W3")
    assert "1 reached NO VERDICT" in output


def test_the_coverage_note_counts_both_kinds_of_non_result() -> None:
    """Counting only unexercised attempts undercounted the shipped run 12-to-1."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result(
        "reference:guarded",
        _outcomes({_W3[0]: "skipped_planner_no_engagement"}),
        no_verdict=[_W1[0]],
    )

    output = _render(vulnerable, guarded)

    assert "1 reached NO VERDICT" in output
    assert "1 was NOT TESTED" in output
    assert "of 18 attempts across both builds" in output


def test_the_coverage_note_agrees_in_number_with_what_it_counts() -> None:
    """Two of a kind reads "were", one reads "was"; the singular case is real."""
    vulnerable = _result("reference:vulnerable", _outcomes(), no_verdict=_W2[:2])
    guarded = _result("reference:guarded", _outcomes({_W3[0]: "skipped_planner_no_engagement"}))

    output = _render(vulnerable, guarded)

    assert "2 reached NO VERDICT" in output
    assert "1 was NOT TESTED" in output


# --- a partly-adjudicated clean row reports its coverage --------------------
#
# Guarded W2 in the shipped run is the real case: of three seeds,
# `indirect-injection-note-body-direct` caught the taint gate refusing an
# attacker-addressed `send_email` outright, and the other two never reached a
# sink. Collapsing that to the bare NO-VERDICT mark asserted the row had
# established nothing, which was false; a plain clean would have claimed all
# three resisted, which is the opposite error.
#
# These assert on the GUARDED cell specifically. `_row` returns the whole row,
# whose vulnerable cell is usually clean too, so a bare `not in row` check reads
# the wrong column.


def _guarded_cell(output: str, weakness: str) -> str:
    """The guarded (last) cell of ``weakness``'s rendered row."""
    cells = [c.strip() for c in _row(output, weakness).split("│") if c.strip()]
    return cells[-1]


def test_a_partly_adjudicated_clean_row_shows_its_coverage() -> None:
    """One real predicate negative, two no-verdicts, nothing found."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes(), no_verdict=[_W2[1], _W2[2]])

    cell = _guarded_cell(_render(vulnerable, guarded), "W2")

    assert cell == "✓ clean (1/3)", cell


def test_a_fully_adjudicated_clean_row_carries_no_count() -> None:
    """Non-regression: an unqualified clean stays unqualified, or every green
    cell in the table grows noise."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes())

    assert _guarded_cell(_render(vulnerable, guarded), "W4") == "✓ clean"


def test_a_row_with_no_adjudicated_verdict_still_reports_no_verdict() -> None:
    """The floor this must not erode: zero verdicts means zero, and the cell has
    to say so rather than borrow confidence from a sibling attempt."""
    vulnerable = _result("reference:vulnerable", _outcomes())
    guarded = _result("reference:guarded", _outcomes(), no_verdict=list(_W2))

    cell = _guarded_cell(_render(vulnerable, guarded), "W2")

    assert "NO VERDICT" in cell
    assert "clean" not in cell


def test_both_spellings_of_a_no_verdict_attempt_render_the_same() -> None:
    """The inconsistency this fix removes. A no-verdict attempt has two
    spellings -- the `undecided` literal, and the older `no_finding` carrying a
    no-adjudicator evidence key -- and branching on the raw string rendered the
    same situation two different ways."""
    vulnerable = _result("reference:vulnerable", _outcomes())

    legacy = _result("reference:guarded", _outcomes(), no_verdict=[_W2[1], _W2[2]])
    literal = _result(
        "reference:guarded",
        _outcomes({_W2[1]: "undecided", _W2[2]: "undecided"}),
    )

    assert _guarded_cell(_render(vulnerable, legacy), "W2") == _guarded_cell(
        _render(vulnerable, literal), "W2"
    )


def test_the_counted_clean_mark_is_styled_as_clean() -> None:
    """It is built at render time so it cannot be a key in the style map, and an
    unstyled cell in a styled column reads as a rendering bug."""
    from mylonite.demo.render import _CLEAN_MARK, _styled

    counted = f"{_CLEAN_MARK} (1/3)"

    assert _styled(counted) == f"[bold green]{counted}[/bold green]"


def test_a_finding_still_wins_over_a_partly_clean_row() -> None:
    """Precedence unchanged: one exploit makes the row FOUND regardless of how
    many siblings came back clean or undecided."""
    vulnerable = _result(
        "reference:vulnerable",
        _outcomes({_W2[0]: "finding", _W2[1]: "undecided"}),
    )
    guarded = _result("reference:guarded", _outcomes())

    cells = [c.strip() for c in _row(_render(vulnerable, guarded), "W2").split("│") if c.strip()]

    assert "FOUND" in cells[-2], cells


def test_the_pattern_ids_match_the_catalogue() -> None:
    """This module hard-codes the kitchen-sink pattern_ids so it can build
    synthetic results without running a scan. It listed eight while the
    catalogue had nine — the W1 send-licence seed added in 0.10.0 — so the W1
    row under test carried one attempt where the real demo has two. Nothing
    failed, which is exactly why this guard is here.
    """
    from mylonite.scan.seeds import SEED_CATALOGUE

    catalogue = {
        seed.pattern_id for seed in SEED_CATALOGUE if "kitchen-sink" in seed.applicable_targets
    }

    assert set(_ALL_PATTERNS) == catalogue, (
        f"drifted from SEED_CATALOGUE: missing {sorted(catalogue - set(_ALL_PATTERNS))}, "
        f"stale {sorted(set(_ALL_PATTERNS) - catalogue)}"
    )


# --- an 80-column terminal ---------------------------------------------------
#
# The launch post sends newcomers to `mylonite demo` in whatever terminal they
# have open, and the default is 80 columns. The full table needs 126 on the
# shipped run, and below that Rich used to cut the weakness IDs to nothing and
# the verdict cells to `v…` / `✓ c…`. The renderer now switches layout whenever
# the full table does not fit, a width it computes from the cells.

_RECORDED_MODE = (
    "replay (offline); recorded 2026-09-14 against ollama_chat/qwen3:4b-instruct-2507-q4_K_M"
)


def _shipped_shape() -> tuple[ScanResult, ScanResult]:
    """Every mark the shipped demo prints, including the widest (`✓ clean (1/3)`)."""
    vulnerable = _result(
        "reference:vulnerable",
        _outcomes({_W2[0]: "finding", _W3[0]: "finding", _W4[0]: "finding"}),
        no_verdict=list(_W1),
    )
    guarded = _result("reference:guarded", _outcomes(), no_verdict=[_W2[1], _W2[2]])
    return vulnerable, guarded


def _render_at(width: int, *, mode: str = _RECORDED_MODE) -> str:
    vulnerable, guarded = _shipped_shape()
    console = Console(
        file=io.StringIO(), width=width, record=True, force_terminal=False, color_system=None
    )
    render_demo(vulnerable, guarded, mode=mode, elapsed_s=0.4, console=console)
    return console.export_text()


def test_demo_readable_at_80_columns() -> None:
    import re

    text = _render_at(80)

    assert "…" not in text
    for weakness in ("W1", "W2", "W3", "W4"):
        assert _row(text, weakness)
    for mark in ("FOUND", "clean (1/3)", "NO VERDICT"):
        assert mark in text
    assert any(
        re.fullmatch(r"reference app: \d+ exploits on vulnerable, \d+ on guarded", line.strip())
        for line in text.splitlines()
    )
    # Each command intact on one line, so a reader can copy it.
    assert "mylonite scan --target-file app.yaml --authorize my-app  # needs an API key" in text
    assert "# no API key" in text
    assert "mylonite gate reference:vulnerable" in text
    assert "--scaffold app.yaml --scope my-app" in text
    assert all(len(line) <= 80 for line in text.splitlines()), text


def test_the_taxonomy_moves_to_a_legend_when_the_full_table_does_not_fit() -> None:
    """The IDs are kept, one line per weakness, rather than squeezed into a cell."""
    from mylonite.demo.render import _taxonomy_cell

    text = _render_at(80)

    assert "LLM01" not in _row(text, "W1")
    lines = [line.strip() for line in text.splitlines()]
    for weakness in ("W1", "W2", "W3", "W4"):
        assert f"{weakness}  {_taxonomy_cell(weakness)}" in lines, text  # type: ignore[arg-type]


def test_a_wide_terminal_keeps_the_taxonomy_column() -> None:
    text = _render_at(130)

    assert "LLM01" in _row(text, "W1")
    assert "taxonomy (OWASP LLM / ASI / ATLAS)" in text
    assert "…" not in text


def test_the_mode_line_puts_the_recording_provenance_on_its_own_line() -> None:
    """CI greps `mode: replay`; the long model id no longer pushes it to a wrap."""
    lines = [line.strip() for line in _render_at(80).splitlines()]

    assert "mode: replay (offline) — 0.4s" in lines
    assert "recorded 2026-09-14 against ollama_chat/qwen3:4b-instruct-2507-q4_K_M" in lines


def test_a_live_mode_label_stays_on_one_line() -> None:
    lines = [line.strip() for line in _render_at(80, mode="live (anthropic/m)").splitlines()]

    assert "mode: live (anthropic/m) — 0.4s" in lines


def test_the_real_replay_label_puts_its_provenance_on_its_own_line(tmp_path, monkeypatch) -> None:
    """Ties the runner's label to the renderer's split: both use one separator."""
    import json

    from mylonite.demo import runner as runner_mod

    for variant in ("vulnerable", "guarded"):
        (tmp_path / variant).mkdir()
        (tmp_path / variant / "_meta.json").write_text(
            json.dumps({"recorded_at": "2026-09-14", "model": "ollama_chat/some-long-model-id"}),
            encoding="utf-8",
        )
    monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: tmp_path)

    lines = [
        line.strip() for line in _render_at(80, mode=runner_mod._replay_mode_label()).splitlines()
    ]

    assert "mode: replay (offline) — 0.4s" in lines
    assert "recorded 2026-09-14 against ollama_chat/some-long-model-id" in lines


def _full_table_width() -> int:
    """Width of the one-line table, read off a render with room to spare."""
    top = next(line for line in _render_at(240).splitlines() if line.startswith("┌──────────┬"))
    return len(top)


@pytest.mark.parametrize("offset", [0, -1, None])
def test_no_cell_is_cut_either_side_of_the_layout_switch(offset: int | None) -> None:
    """At the computed threshold, one column below it, and at 60 columns."""
    threshold = _full_table_width()
    width = 60 if offset is None else threshold + offset
    text = _render_at(width)

    assert "…" not in text
    # The full table carries the taxonomy in its rows; the narrow one moves it out.
    assert ("LLM01" in _row(text, "W1")) is (offset == 0)
    expected = {
        "W1": ("⚠ NO VERDICT", "✓ clean"),
        "W2": ("✗ FOUND", "✓ clean (1/3)"),
        "W3": ("✗ FOUND", "✓ clean"),
        "W4": ("✗ FOUND", "✓ clean"),
    }
    for weakness, verdicts in expected.items():
        cells = [c.strip() for c in _row(text, weakness).split("│") if c.strip()]
        assert tuple(cells[-2:]) == verdicts, cells
    headline = [line.strip() for line in text.splitlines()]
    assert "reference app: 3 exploits on vulnerable, 0 on guarded" in headline
