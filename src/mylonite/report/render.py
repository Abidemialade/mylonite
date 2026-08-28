"""Terminal rendering for validation reports and the ablation matrix.

Pure presentation, extracted from ``cli.py`` (issue #91) to keep the CLI a thin
composition root and to put rendering in the report package alongside the SARIF
and JSON-bundle exports. Both functions are ASCII-safe for a legacy cp1252
Windows console. ``cli`` re-exports them for its own use and for tests.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite._twin_fidelity import MARKER_SERVER_LAYER, MARKER_SYNTHETIC


def _render_validation_report(report: Any, console: Console | None = None) -> None:
    """Render a per-leg Rich report (F4): one row per ValidationOutcome.

    This is the core differentiator's SHOWCASE surface, so it is made ASCII-safe independently
    of the root callback's UTF-8 forcing: a legacy cp1252 Windows console must
    never crash on the pass/fail marks or the title dash (Issue #9). Shows the
    per-leg result + metric + detail; the gating formula with live per-leg marks,
    the fires/resists reproducibility counts, the per-seed kill matrix and the
    mutation-score headline; the overall kept verdict; plus a remediation line
    per failed gating leg when the test was rejected.
    """
    # ASCII-aware marks/separators so the showcase surface never crashes on a
    # legacy cp1252 console — independent of the root callback's UTF-8 forcing.
    from mylonite._redaction import redact
    from mylonite.scan.artefacts import _stdout_is_ascii_only

    ascii_safe = _stdout_is_ascii_only()

    def _mark(ok: bool) -> str:
        # NB: avoid '[...]' tokens — Rich would parse them as console markup.
        if ascii_safe:
            return "+" if ok else "x"
        return "✓" if ok else "✗"

    sep = " | " if ascii_safe else " · "
    dash = "-" if ascii_safe else "—"

    if console is None:
        console = Console()
    table = Table(
        title=f"Mylonite validate {dash} {report.test_filename}",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("leg", no_wrap=True)
    table.add_column("result", no_wrap=True)
    table.add_column("metric", no_wrap=True)
    table.add_column("detail")

    for outcome in report.outcomes:
        if outcome.report_only:
            # Informational leg (e.g. effect with no probe declared): not a pass,
            # not a fail — it does not contribute to kept. Show it as such so the
            # table can't read as a confirmation it never made.
            mark = "· report-only"
        else:
            mark = f"{_mark(outcome.passed)} {'pass' if outcome.passed else 'FAIL'}"
        metric = f"{outcome.metric:.2f}" if outcome.metric is not None else "-"
        # outcome.detail is free text from the validation pipeline (e.g. an
        # exception message, or a third-party ValidatorBase plugin's own
        # detail string) — redact it here, before Rich's column-width
        # wrapping has a chance to split a secret-shaped token across a line
        # break, which would defeat a post-render regex redaction. Also
        # escape Rich markup: a detail that quotes target/exception output
        # shaped like a closing tag (e.g. "[/bold]") would otherwise raise
        # rich.errors.MarkupError when the table renders (same class as
        # scan/artefacts.py's render_summary fix, DCR-0004). outcome.stage is
        # a contract Literal (not free text), so it needs neither.
        table.add_row(outcome.stage, mark, metric, rich_escape(redact(outcome.detail)))

    console_print(console, table)

    # --- the differential-oracle EVIDENCE (PR2: make the differential legible) --------
    # The gating formula with live per-leg marks, the fires/resists counts, and
    # the per-seed kill matrix were previously buried in report.notes (rendered
    # nowhere). Surface them so a "KEPT" verdict shows WHY it's trustworthy.
    # Metric legend — what the bare decimals in the table's metric column mean.
    console_print(
        console,
        "metric legend: "
        + sep.join(
            ["differential=agreement", "flakiness=reproducibility", "metamorphic=robustness (0-1)"]
        ),
    )

    # The gate itself, with LIVE per-leg marks — this is what makes a verdict
    # legible: kept = build [ok] AND differential [ok] AND flakiness [x].
    legs_by_stage = {o.stage: o for o in report.outcomes}
    if getattr(report, "gating_legs", None):
        # DCR-0004: a gating_legs entry with no matching outcome must render
        # explicitly as missing, not silently drop out of the AND-chain — an
        # operator reading an incomplete formula with no mark or mention of
        # the missing leg can't tell the VERDICT might depend on it.
        rendered = " AND ".join(
            f"{leg} {_mark(legs_by_stage[leg].passed)}"
            if leg in legs_by_stage
            else f"{leg} (missing)"
            for leg in report.gating_legs
        )
        verdict = "KEPT" if report.kept else "REJECTED"
        console_print(console, f"gate: kept = {rendered}  =>  {verdict}")

    # Reproducibility counts (fires/resists) behind differential + flakiness.
    repro = getattr(report, "reproducibility", None)
    if repro is not None:
        if repro.guard_resisted is not None:
            console_print(
                console,
                f"reproducibility: vulnerable fired {repro.vuln_fired}/{repro.iterations}, "
                f"guarded resisted {repro.guard_resisted}/{repro.iterations}",
            )
        else:
            console_print(
                console,
                f"reproducibility: reproduced {repro.vuln_fired}/{repro.iterations} "
                "against the real target (no in-repo guarded twin)",
            )

    if report.mutation_score is not None:
        console_print(console, f"mutation score: {report.mutation_score:.2f}")

    # Per-seed kill matrix — the oracle's discrimination, seed by seed.
    matrix = getattr(report, "mutation_matrix", None) or []
    if matrix:
        killed = sum(1 for s in matrix if s.killed)
        console_print(
            console,
            f"kill matrix ({killed}/{len(matrix)} seeds killed = "
            "fired-on-vulnerable, resisted-on-guarded):",
        )
        for seed in matrix:
            console_print(console, f"  {_mark(seed.killed)} {seed.weakness}:{seed.pattern_id}")

    # Metamorphic robustness gates kept (M2) — say so explicitly so a failing
    # metamorphic row below IS read as a gate failure, not just a footnote.
    if any(o.stage == "metamorphic" for o in report.outcomes):
        console_print(
            console,
            "note: metamorphic robustness gates kept - a failing row below means "
            "the differential did not survive that perturbation.",
        )

    if report.kept:
        console_print(
            console, f"[green]verdict: KEPT {dash} the test discriminates and is stable.[/green]"
        )
    else:
        console_print(console, f"[red]verdict: REJECTED {dash} the test was not kept.[/red]")
        # The differential remediation must not accuse a real (server-layer) control
        # of being theater when the guarded side was only the SYNTHETIC boundary shim.
        # The validator stamps a [guarded-twin=...] marker into notes; key off it.
        notes = getattr(report, "notes", "") or ""
        if MARKER_SYNTHETIC in notes:
            diff_remediation = (
                "differential fail: the SYNTHETIC boundary twin did not block the attack. "
                "If your real control is server-layer (an approval gate / allowlist enforced "
                "inside the server), declare control_env / vulnerable_launch in the target file "
                "so the differential measures it - the boundary twin cannot see server-side "
                "guards, so this is NOT evidence your control is ineffective."
            )
        elif MARKER_SERVER_LAYER in notes:
            diff_remediation = (
                "differential fail: the server-layer control did not discriminate (raw and "
                "guarded behaved alike) - the control as configured did not stop this attack."
            )
        else:
            diff_remediation = "differential fail: no discriminating power between the twins."
        _remediation = {
            "build": "build fail: emitted test didn't collect; re-run `mylonite generate`.",
            "differential": diff_remediation,
            "flakiness": "flakiness fail: exploit too flaky to gate; try a more deterministic seed.",
            "stability": "stability fail: the attack did not reproduce against the real target.",
            "effect": "effect fail: the target's effect probe did not confirm the damage materialised.",
            "consensus": "consensus fail: judges disagreed the effect was real; add an effect_probe.",
            # DCR-0007: a metamorphic-only failure (every other leg passes) is a
            # documented gating leg that can REJECT a report on its own (see the
            # "metamorphic robustness gates kept" note above) -- without this
            # key the remediation loop below silently skipped it, so the
            # operator saw "verdict: REJECTED" with zero guidance for the
            # actual failing leg.
            "metamorphic": (
                "metamorphic fail: the differential did not survive a robustness "
                "perturbation (see the failing row above) - the exploit may be "
                "over-fit to the exact seed wording; try a paraphrase-robust payload."
            ),
        }
        for outcome in report.outcomes:
            if not outcome.passed and outcome.stage in _remediation:
                console_print(console, f"[red]  remediation: {_remediation[outcome.stage]}[/red]")


def _render_ablation_matrix(results: list[Any], console: Console | None = None) -> None:
    """Render the control-ablation matrix (ASCII-safe for a legacy cp1252 console)."""
    from mylonite.scan.artefacts import _stdout_is_ascii_only

    dash = "-" if _stdout_is_ascii_only() else "—"
    if console is None:
        console = Console()
    table = Table(
        title=f"Mylonite control ablation {dash} marginal contribution",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("control", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("contribution", no_wrap=True)
    table.add_column("raw/guarded fired", no_wrap=True)
    for r in results:
        # An inconclusive row's raw/guarded fired counts and contribution
        # percentage are computed purely from the FIRED/RESISTED legs and
        # exclude the crashed leg(s) entirely — left alone, they can still
        # read as a genuine load-bearing/theater signal (e.g. "2/0 of 2",
        # "+100%") to anyone skimming the table or copying a row out of
        # context, even though `status` correctly says "inconclusive". Never
        # render a bare percentage or count for this row; always surface the
        # inconclusive count instead.
        if r.status == "inconclusive":
            contribution_cell = "n/a"
            fired_cell = (
                f"{r.raw_fired}/{r.guarded_fired} of {r.total} ({r.inconclusive} inconclusive)"
            )
        else:
            contribution_cell = f"{r.contribution:+.0%}"
            fired_cell = f"{r.raw_fired}/{r.guarded_fired} of {r.total}"
        table.add_row(r.weakness, r.status, contribution_cell, fired_cell)
    console_print(console, table)
    load_bearing = [r.weakness for r in results if r.load_bearing]
    redundant = [r.weakness for r in results if r.status == "redundant"]
    theater = [r.weakness for r in results if r.status == "theater"]
    inconclusive = [r.weakness for r in results if r.status == "inconclusive"]
    if load_bearing:
        console_print(console, f"load-bearing: {', '.join(load_bearing)}")
    if redundant:
        console_print(console, f"redundant (another control covers it): {', '.join(redundant)}")
    if theater:
        console_print(console, f"security theater (no marginal contribution): {', '.join(theater)}")
    if inconclusive:
        console_print(
            console,
            f"inconclusive (scan didn't produce a trustworthy result on at least one "
            f"side -- NOT the same as resisted, re-run before trusting this control): "
            f"{', '.join(inconclusive)}",
        )
