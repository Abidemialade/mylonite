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
from mylonite._twin_fidelity import (
    MARKER_SERVER_LAYER,
    MARKER_SYNTHETIC,
    TwinLayer,
    guard_mode_in,
    proof_claim,
)
from mylonite._verdict import (
    KEPT,
    REJECTED,
    STABLE_NOT_PROVEN,
    has_proof,
    is_black_box_keep,
    verdict_label,
    verdict_reason,
)

#: What the guarded side was, per the guard mode the validator stamps. Only
#: the modes that refuse whatever the model does say "by construction".
_STAND_IN_LINES: dict[str, str] = {
    "block": (
        "guarded side: a stand-in. Mylonite's boundary guard ran in block mode: it "
        "refuses every consequential tool call by design, so that side resists by "
        "construction."
    ),
    "approve-deny": (
        "guarded side: a stand-in. Mylonite's boundary guard ran in approve mode with "
        "the default deny-all policy: it refuses every consequential tool call by "
        "design, so that side resists by construction."
    ),
    "allowlist": (
        "guarded side: a stand-in. Mylonite's boundary guard refuses egress to any "
        "host outside its fixed allowlist by design, so that side resists by "
        "construction."
    ),
    "pin": (
        "guarded side: a stand-in. Mylonite's boundary guard refused calls to any tool "
        "whose description changed from its pinned version; your own guard was not "
        "tested."
    ),
    "approve-policy": (
        "guarded side: a stand-in. Mylonite's boundary guard ran in approve mode and "
        "its approval policy decided each call, so that side did not resist by "
        "construction; your own guard was not tested."
    ),
    "observe": (
        "guarded side: a stand-in. Mylonite's boundary guard ran in observe mode: it "
        "records but never refuses, so a resisted run means the model declined, not "
        "that a guard stopped it."
    ),
    "input-frame": (
        "guarded side: a stand-in. Mylonite wrapped the input as data (input "
        "data-framing) and the agent still had to decide, so that side did not "
        "resist by construction; your own guard was not tested."
    ),
}
_STAND_IN_UNKNOWN = (
    "guarded side: a stand-in. Mylonite's boundary guard played the guarded build, "
    "not your own guard."
)


#: The legs whose remediation assumes the attack landed at least once. When the
#: unguarded side fired 0 times, each of them fails for that one reason, and
#: their own lines would send the operator after the guard or the seed wording.
_NEEDS_A_LANDED_ATTACK = frozenset(
    {"differential", "flakiness", "stability", "effect", "consensus", "metamorphic"}
)


def _own_seed_id(report: Any, matrix: list[Any]) -> str | None:
    """The pattern_id of the seed this report's test was written for, if known.

    The generator names the test ``test_security_<slug(pattern_id)>.py``, so the
    seed is the matrix row whose slug matches the report's file name. ``None``
    when no row matches (a hand-built report, say): the matrix then renders as
    it always did, without claiming which seeds ran.
    """
    from mylonite.plugins._reference.reference_pytest_generator import _slugify

    filename = getattr(report, "test_filename", "") or ""
    for seed in matrix:
        if filename == f"test_security_{_slugify(seed.pattern_id)}.py":
            return str(seed.pattern_id)
    return None


def _attack_never_landed(report: Any) -> int | None:
    """The iteration count when the unguarded side fired 0 times, else ``None``."""
    repro = getattr(report, "reproducibility", None)
    if repro is None or not repro.iterations or repro.vuln_fired:
        return None
    return int(repro.iterations)


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
            [
                "differential=discrimination strength",
                "flakiness=reproducibility",
                "metamorphic=robustness (0-1)",
            ]
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
        console_print(console, f"gate: kept = {rendered}  =>  {verdict_label(report)}")

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

    # Per-seed kill matrix — the oracle's discrimination, seed by seed. The
    # differential attacks with the test's own seed only, so every other seed
    # was never run: it is "not run", not a miss, and the mutation score covers
    # the own seed alone. A seed marked killed did run (an older report from a
    # whole-bank run), so it keeps its mark.
    matrix = getattr(report, "mutation_matrix", None) or []
    own = _own_seed_id(report, matrix)
    # A custom-target report has no kill matrix and a placeholder score of 0;
    # a bare "mutation score: 0.00" would read as zero coverage, so skip it.
    if report.mutation_score is not None and matrix:
        if own is not None:
            console_print(
                console,
                f"mutation score: {report.mutation_score:.2f} (seeds killed out of all "
                f"{len(matrix)} in the bank; this test runs only its own seed, so "
                f"1/{len(matrix)} is the most it can score)",
            )
        else:
            console_print(console, f"mutation score: {report.mutation_score:.2f}")
    if matrix:
        killed = sum(1 for s in matrix if s.killed)
        if own is None:
            console_print(
                console,
                f"kill matrix ({killed}/{len(matrix)} seeds killed = "
                "fired-on-vulnerable, resisted-on-guarded):",
            )
            for seed in matrix:
                console_print(console, f"  {_mark(seed.killed)} {seed.weakness}:{seed.pattern_id}")
        else:
            not_run = sum(1 for s in matrix if s.pattern_id != own and not s.killed)
            console_print(
                console,
                f"kill matrix (this test's own seed; {not_run} not run; killed = fired on "
                "the vulnerable side and resisted on the guarded side):",
            )
            for seed in matrix:
                name = f"{seed.weakness}:{seed.pattern_id}"
                if seed.pattern_id == own:
                    state = "killed" if seed.killed else "not killed"
                    console_print(console, f"  {_mark(seed.killed)} {name}  {state}")
                elif seed.killed:
                    console_print(console, f"  {_mark(True)} {name}  killed")
                else:
                    console_print(console, f"  - {name}  not run")

    # Metamorphic robustness gates kept (M2) — say so explicitly so a failing
    # metamorphic row below IS read as a gate failure, not just a footnote.
    if any(o.stage == "metamorphic" for o in report.outcomes):
        console_print(
            console,
            "note: metamorphic robustness gates kept - a failing row below means "
            "the differential did not survive that perturbation.",
        )

    label = verdict_label(report)
    notes = getattr(report, "notes", "") or ""
    if label == KEPT:
        console_print(console, f"[green]verdict: KEPT {dash} {verdict_reason(report)}[/green]")
    elif label == STABLE_NOT_PROVEN:
        # Kept, but nothing proved a safeguard stops the attack, or the build
        # leg was skipped. Never print this as KEPT (see mylonite._verdict).
        console_print(
            console,
            f"[yellow]verdict: STABLE, NOT PROVEN {dash} "
            f"{rich_escape(verdict_reason(report))}[/yellow]",
        )
        if not has_proof(report) and not is_black_box_keep(report):
            console_print(
                console,
                "[yellow]  next: run without --fast so a guarded twin gives a differential "
                "(declare control_env to measure your own control), or declare an "
                "effect_probe in the target file, then re-run `mylonite validate`.[/yellow]",
            )
    else:
        console_print(
            console, f"[red]verdict: REJECTED {dash} {rich_escape(verdict_reason(report))}[/red]"
        )
        # The differential remediation must not accuse a real (server-layer) control
        # of being theater when the guarded side was only the SYNTHETIC boundary shim.
        # The validator stamps a [guarded-twin=...] marker into notes; key off it.
        if MARKER_SYNTHETIC in notes:
            diff_remediation = (
                "differential fail: the SYNTHETIC boundary twin did not block the attack. "
                "If your real control is server-layer (an approval gate / allowlist enforced "
                "inside the server), declare control_env in the target file "
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
        # Deferred: the validator module pulls in the scan engine, which a
        # report render does not otherwise need.
        from mylonite.plugins._reference.reference_validator import (
            BLACK_BOX_EFFECT_CLAUSE,
            EFFECT_UNPROVEN_CLAUSE,
            unguarded_no_verdict,
        )

        consensus_remediation = (
            "consensus fail: judges disagreed the effect was real; add an effect_probe."
        )
        # A rest target refuses an effect_probe: don't advise one there.
        if any(
            o.stage == "effect" and o.detail == BLACK_BOX_EFFECT_CLAUSE for o in report.outcomes
        ):
            consensus_remediation = (
                "consensus fail: judges disagreed the attack landed; a black-box target "
                "gives no state to settle it, so scan the agent's MCP server to confirm."
            )

        effect_remediation = (
            "effect fail: the target's effect probe did not confirm the damage materialised."
        )
        # The effect leg carries EFFECT_UNPROVEN_CLAUSE only when a run fired
        # with nothing in the trace or the probe tying the damage to that
        # attempt (an LLM-judge verdict, say). The generic line would point
        # at the wrong fix (declare a probe, when one already ran). Imported,
        # not copied, so a rewording in the validator cannot break the match.
        for outcome in report.outcomes:
            if (
                outcome.stage == "effect"
                and not outcome.passed
                and EFFECT_UNPROVEN_CLAUSE in outcome.detail
            ):
                effect_remediation = (
                    "effect fail: some runs fired with nothing tying the damage to that "
                    "attempt (an LLM-judge verdict, say), so they do not count. "
                    "Give the effect probe a marker built from {exfil_email} or "
                    "{exfil_host}, so the attempt's own call carries it, and run "
                    "`mylonite scan --target-file <file> --authorize <family>` to "
                    "calibrate the probe."
                )
                break
        _remediation = {
            "build": (
                "build fail: the emitted test did not pass (it failed, errored, ran no "
                "test or only skipped); re-run `mylonite generate`."
            ),
            "differential": diff_remediation,
            "flakiness": "flakiness fail: exploit too flaky to gate; try a more deterministic seed.",
            "stability": "stability fail: the attack did not reproduce against the real target.",
            "effect": effect_remediation,
            "consensus": consensus_remediation,
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
        never_landed = _attack_never_landed(report)
        for outcome in report.outcomes:
            if never_landed is not None and outcome.stage in _NEEDS_A_LANDED_ATTACK:
                continue
            if not outcome.passed and not outcome.report_only and outcome.stage in _remediation:
                console_print(console, f"[red]  remediation: {_remediation[outcome.stage]}[/red]")
        if never_landed is not None:
            # The attack never fired on the unguarded side, so every leg that
            # compares sides failed for that one reason. Say it once. A run cut
            # off by the time limit or the budget is tallied as "did not fire"
            # too, so name that cause when it applies; otherwise point at what
            # decides whether an attack lands: the model and its prompt.
            no_verdict = unguarded_no_verdict(notes)
            if no_verdict:
                rest = never_landed - no_verdict
                tail = f", and the other {rest} did not fire" if rest else ""
                line = (
                    f"{no_verdict}/{never_landed} unguarded runs reached no verdict "
                    f"(cut off by --iteration-timeout or the call budget){tail}, so this "
                    "run says nothing about the attack or the guard. Raise "
                    "--iteration-timeout (or lower --iterations) and re-run."
                )
            else:
                line = (
                    f"the attack never landed on the unguarded side (fired "
                    f"0/{never_landed}), so this run says nothing about the guard. Try a "
                    "different planner model (--planner-model) or system prompt, then "
                    "re-run `mylonite validate`."
                )
            console_print(console, f"[red]  remediation: {line}[/red]")

    if label != REJECTED and MARKER_SYNTHETIC in notes:
        # The guarded side was a Mylonite stand-in, not the user's guard. Say how
        # it decided (the validator stamps the mode), and only call it "by
        # construction" when it refuses whatever the model does. The proof
        # sentence goes under KEPT only: a STABLE, NOT PROVEN verdict has
        # already said nothing proved a safeguard.
        mode = guard_mode_in(notes)
        console_print(console, _STAND_IN_LINES.get(mode or "", _STAND_IN_UNKNOWN))
        if label == KEPT:
            if mode == "observe":
                shows = (
                    "the attack is real and the model declined it on the guarded side; "
                    "no guard refused anything"
                )
            else:
                shows = proof_claim("boundary")
            console_print(
                console,
                f"  what this pass shows: {shows}. Declare control_env in the target "
                "file to test your own guard.",
            )


#: How each guarded side is described on the ablation matrix. Ablation's own
#: vocabulary ("toggling a control"), paired with the shared claim wording from
#: ``_twin_fidelity`` so the matrix states the same claim as every other surface.
_ABLATION_GUARDED_SIDE: dict[str, str] = {
    "server": "server-layer (your control_env toggles)",
    "boundary": "adapter-shim (Mylonite's canonical boundary control)",
}


def _render_ablation_matrix(
    results: list[Any],
    console: Console | None = None,
    *,
    guarded_layer: TwinLayer | None = None,
) -> None:
    """Render the control-ablation matrix (ASCII-safe for a legacy cp1252 console).

    ``guarded_layer`` names what played the guarded side of every row: the
    operator's own server-layer control or Mylonite's boundary shim. It is
    per-run rather than per-row, so it renders once, under the table, together
    with the claim a load-bearing row earns (``_twin_fidelity.proof_claim``).
    ``None`` renders nothing: the matrix does not assert a claim about a run
    whose guarded side it was not told.
    """
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
    if guarded_layer is not None:
        console_print(console, f"guarded side: {_ABLATION_GUARDED_SIDE[guarded_layer]}")
        if load_bearing or redundant:
            console_print(console, f"what a load-bearing row shows: {proof_claim(guarded_layer)}.")


def trifecta_lines(legs: Any) -> list[str]:
    """The ``mylonite check`` summary of a surface's lethal-trifecta legs.

    ``legs`` is a :class:`mylonite.scan.control_shim.TrifectaLegs`. Plain ASCII,
    for any console. When the surface can take in untrusted content and send
    data out but no private data is declared, the last lines say what to
    declare so W2's confidentiality check has something to protect.
    """

    def _names(values: tuple[str, ...]) -> str:
        return ", ".join(values) if values else "none found"

    private = list(legs.private_tools) + [f"marker {m!r}" for m in legs.private_markers]
    lines = [
        "lethal trifecta (untrusted content + private data + external communication):",
        f"  untrusted content:      {_names(legs.untrusted_content)}",
        f"  external communication: {_names(legs.external_communication)}",
        f"  private data:           {', '.join(private) if private else 'not declared'}",
    ]
    if legs.undeclared_private_leg:
        example = legs.untrusted_content[0]
        lines += [
            "declare the tools that return sensitive data, so W2's confidentiality check "
            "refuses sending it out through an external sink:",
            "  control_config:",
            f'    private_tools: [{example}]   # or private_markers: ["<literal>"]',
        ]
    return lines
