"""Differential renderer for ``mylonite demo``.

Takes the two ScanResults the demo runner produced (reference:vulnerable /
reference:guarded), aggregates the 8 kitchen-sink seed attempts into the 4
seeded-weakness rows W1-W4, and prints the safety banner, side-by-side
differential table, computed headline, next-steps teaser, next-step line, and
mode/elapsed footer.

All output flows through a ``rich.Console`` — Rich degrades the ✗/✓/⚠ glyphs
safely on Windows redirected / cp1252 output, which a pre-rendered unicode
string via ``typer.echo`` would not. The weakness → pattern_id mapping and the
per-weakness taxonomy IDs are derived from ``SEED_CATALOGUE`` (the seeds carry
``weakness`` and ``compliance`` fields), so this module cannot drift from the
seed catalogue; only the human-readable weakness names (from
``reference_targets/mcp_kitchen_sink/seeds/seeds.yaml``) are constants here.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterable
from typing import Final, get_args

from rich.cells import cell_len
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite.scan.artefacts import NOT_TESTED_OUTCOMES, OUTCOME_MARKS
from mylonite.scan.coverage import attempt_reached_no_verdict
from mylonite.scan.engine import ScanResult
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern, Weakness

SAFETY_BANNER: Final[str] = (
    "DEMO ONLY — the reference app is a deliberately vulnerable in-process "
    "agent. It never binds to a network. Never point Mylonite at a system you "
    "don't own or operate"
)
"""Bolded part of the safety banner; ``(see SECURITY.md).`` is appended unbolded."""

#: Two lines, not one: the first is the result and fits an 80-column terminal on
#: its own, so CI's grep for "N exploits on vulnerable" never meets a wrap.
_HEADLINE_TEMPLATE: Final[str] = (
    "reference app: {n_vuln} exploits on vulnerable, {n_guard} on guarded\n"
    "this differential is the oracle that validates every generated regression test"
)
_GUARDED_FINDING_NOTE: Final[str] = (
    "⚠ unexpected finding on the guarded build — LLM-judge noise or a real bug"
)
#: Every command sits on its own indented line, under 80 columns, so a reader
#: can copy it whole instead of stitching it back together across a wrap.
_TEASER: Final[str] = (
    "Each finding becomes a committed regression test, validated against this same "
    "vulnerable/guarded oracle. Turn one into a gating test:\n"
    "  mylonite gate reference:vulnerable"
)
#: Each command is one line with no shell continuation: a trailing backslash
#: works in bash but not in PowerShell or cmd. A Windows console renders one
#: column narrower than COLUMNS, so every line stays within 79 columns: the
#: scaffold command is 78 on its own, so these two commands carry no indent,
#: and the API-key notes sit on the lead-in lines rather than after them.
_NEXT_STEP: Final[str] = (
    "Try it on your own app (docs/test-your-app.md).\n"
    "Make a target file (no API key):\n"
    "mylonite scan --command python --arg app.py --scaffold app.yaml --scope my-app\n"
    "Scan it (needs an API key):\n"
    "mylonite scan --target-file app.yaml --authorize my-app"
)

#: Joins the replay mode label to its fixture provenance ("replay (offline); recorded
#: <date> against <model>"). The runner builds the label with it and
#: :func:`render_demo` splits on it to print the provenance on its own line, so the
#: two cannot drift apart.
MODE_PROVENANCE_SEP: Final[str] = "; "

_FOUND_MARK: Final[str] = OUTCOME_MARKS["finding"]
_CLEAN_MARK: Final[str] = OUTCOME_MARKS["no_finding"]
_SKIPPED_MARK: Final[str] = OUTCOME_MARKS["skipped_planner_failure"]
#: Distinct from the above: the attack was delivered but the agent never
#: engaged, so nothing was exercised. `scan/artefacts.py` already renders this
#: as its own mark and warns loudly about it; the demo table did not.
_NOT_TESTED_MARK: Final[str] = OUTCOME_MARKS["skipped_planner_no_engagement"]
#: A third kind of non-result, distinct from both of the above. The attack was
#: delivered AND the agent engaged — but the deterministic predicate declined to
#: rule and the demo runs with no LLM judge to adjudicate, so nothing decided.
#: Not in OUTCOME_MARKS because it is not an outcome: the engine records these
#: as `no_finding`, and only `judge_evidence` distinguishes them.
_NO_VERDICT_MARK: Final[str] = "⚠ NO VERDICT"

#: Rich styles for the outcome marks. The demo's entire claim is a contrast
#: between two columns, and an unstyled table renders FOUND and clean as the
#: same weight of plain text -- the differential is invisible until you read
#: every cell individually. Colour makes the shape of the result legible
#: before the words are, which is the one thing this table exists to do.
#:
#: NOT TESTED shares the caution colour with a plain skip on purpose: both mean
#: "this cell is not a result", and the difference between them is *why*, which
#: is carried by the words. A third colour would imply a third severity.
_MARK_STYLES: Final[dict[str, str]] = {
    _FOUND_MARK: "bold red",
    _CLEAN_MARK: "bold green",
    _SKIPPED_MARK: "bold yellow",
    _NOT_TESTED_MARK: "bold yellow",
    _NO_VERDICT_MARK: "bold yellow",
}


def _styled(mark: str) -> str:
    """``mark`` wrapped in its Rich style, or returned unchanged if it has none.

    Styling is applied here rather than inside :func:`_aggregate_mark` so that
    function keeps returning a bare comparable string.
    """
    style = _MARK_STYLES.get(mark)
    if style is None and mark.startswith(_CLEAN_MARK):
        # The counted clean mark ("✓ clean (1/3)") is built at render time, so it
        # cannot be a dict key. It is still a clean verdict and must read as one.
        style = _MARK_STYLES[_CLEAN_MARK]
    return f"[{style}]{mark}[/{style}]" if style else mark


# Human-readable weakness names, verbatim from the kitchen-sink seed
# catalogue (reference_targets/mcp_kitchen_sink/seeds/seeds.yaml); the seed
# objects carry taxonomy tags but not these names.
_WEAKNESS_NAMES: Final[dict[Weakness, str]] = {
    "W1": "tool-description-instruction-smuggling",
    "W2": "indirect-injection-via-note-body",
    "W3": "unrestricted-web-fetch",
    "W4": "unconfirmed-email-send",
}

_WEAKNESS_ORDER: Final[tuple[Weakness, ...]] = get_args(Weakness)

_KITCHEN_SINK_SEEDS: Final[tuple[SeedPattern, ...]] = tuple(
    seed for seed in SEED_CATALOGUE if "kitchen-sink" in seed.applicable_targets
)

_WEAKNESS_PATTERNS: Final[dict[Weakness, frozenset[str]]] = {
    weakness: frozenset(
        seed.pattern_id for seed in _KITCHEN_SINK_SEEDS if seed.weakness == weakness
    )
    for weakness in _WEAKNESS_ORDER
}


def _taxonomy_cell(weakness: Weakness) -> str:
    """``OWASP LLM / ASI / ATLAS`` IDs for one weakness, unioned across its seeds."""
    seeds = [seed for seed in _KITCHEN_SINK_SEEDS if seed.weakness == weakness]

    def union(ids_per_seed: Iterable[list[str]]) -> str:
        merged = sorted({tag for ids in ids_per_seed for tag in ids})
        return ", ".join(merged) if merged else "—"

    llm = union(seed.compliance.owasp_llm for seed in seeds)
    asi = union(seed.compliance.owasp_asi for seed in seeds)
    atlas = union(seed.compliance.mitre_atlas for seed in seeds)
    return f"{llm} / {asi} / {atlas}"


def _aggregate_mark(result: ScanResult, pattern_ids: frozenset[str]) -> str:
    """Collapse one weakness's seed attempts into a single outcome mark.

    Binding rule: FOUND if ANY seed in the weakness found, else clean only if
    EVERY seed came back ``no_finding``, else the outcome's own mark.

    That last clause is the point. This used to collapse everything non-clean
    into one generic "⚠ skipped", which made a seed the agent never engaged with
    indistinguishable from a harness error — and `OUTCOME_MARKS` already draws
    that distinction: ``skipped_planner_no_engagement`` is "⚠ NOT TESTED",
    because an attempt in which the agent did nothing proves nothing about the
    target, while ``skipped_planner_failure`` is a genuine "⚠ skipped". Both
    render on the guarded column of the shipped demo today, and reading the
    first as the second overstates what the differential established.

    A row mixing two DIFFERENT non-clean kinds falls back to the generic mark:
    that is a real ambiguity, and inventing a winner between them would be the
    same overstatement in miniature.

    ``no_finding`` alone is not enough for clean. The demo runs with the LLM
    judge disabled (``wiring.build_scan(judge_fallback=...)``) so its differential
    stays purely predicate-driven and reproducible — which means an inconclusive
    predicate has no adjudicator at all and is recorded as ``no_finding`` with a
    ``no_adjudicator`` cause. Nothing decided those; rendering them ✓ clean
    claimed a result the demo never established.
    """
    # Join on pattern_id (== seed_id in v0.2); _WEAKNESS_PATTERNS is keyed the
    # same way, so a future pattern_id/seed_id divergence would surface as rows
    # quietly dropping into the skip bucket rather than a crash.
    attempts = [a for a in result.report.attempts if a.pattern_id in pattern_ids]
    outcomes = [attempt.outcome for attempt in attempts]
    if any(outcome == "finding" for outcome in outcomes):
        return _FOUND_MARK
    if not outcomes:
        return _SKIPPED_MARK
    undecided = [a for a in attempts if attempt_reached_no_verdict(a)]
    if len(undecided) == len(attempts):
        return _NO_VERDICT_MARK

    # A row of adjudicated clean verdicts, possibly alongside attempts nothing
    # adjudicated, and no finding anywhere.
    #
    # Keyed on `attempt_reached_no_verdict`, NOT on the raw outcome string,
    # because a no-verdict attempt has two spellings: the `undecided` literal
    # added in 0.10.0, and the older `no_finding` carrying a no-adjudicator
    # evidence key (still produced by reports read off disk). Branching on the
    # string rendered the SAME situation two different ways -- plain clean for
    # one spelling, the bare NO-VERDICT mark for the other -- which is how
    # guarded W2 came to claim it had established nothing when one of its three
    # seeds had caught the taint gate refusing an attacker-addressed
    # `send_email` outright.
    #
    # Fully adjudicated stays an unqualified clean. Partly adjudicated carries
    # the count, so the cell neither erases the verdicts it does have nor
    # implies verdicts it does not: a plain green here would claim all three
    # seeds resisted when two never reached a sink.
    decided_clean = [
        a for a in attempts if a.outcome == "no_finding" and not attempt_reached_no_verdict(a)
    ]
    if decided_clean and len(decided_clean) + len(undecided) == len(attempts):
        if not undecided:
            return _CLEAN_MARK
        return f"{_CLEAN_MARK} ({len(decided_clean)}/{len(attempts)})"
    # `.get` rather than `[]`: an unknown outcome string must degrade to the
    # generic mark, never crash the one command a newcomer runs first.
    non_clean = {
        OUTCOME_MARKS.get(outcome, _SKIPPED_MARK) for outcome in outcomes if outcome != "no_finding"
    }
    return non_clean.pop() if len(non_clean) == 1 else _SKIPPED_MARK


def _print_coverage_note(console: Console, vulnerable: ScanResult, guarded: ScanResult) -> None:
    """Say plainly when a row is not a result.

    ``scan``'s own summary has carried a loud NOT-TESTED callout for some time
    (``artefacts.render_summary``); the demo table had no equivalent, so a
    guarded column containing an unexercised seed read as a clean sweep next to
    a headline of "0 exploits on guarded". The headline is honest — it counts
    findings — but on its own it invites the wrong conclusion about the cells
    that produced no evidence either way.

    Deliberately not styled bold red like ``scan``'s: this is the bundled
    reference app, where a seed the planner declined to engage is an expected
    property of the recorded run rather than a misconfiguration the reader can
    act on. It still has to be said.

    Counts BOTH kinds of non-result, and names them separately because their
    causes are different and only one is about the target: an unexercised
    attempt means the agent never engaged, while a no-verdict attempt means the
    agent engaged and nothing adjudicated the outcome. Reporting only the first
    would undercount the cells that establish nothing -- on the shipped fixtures,
    by an order of magnitude.
    """
    attempts = [a for r in (vulnerable, guarded) for a in r.report.attempts]
    untested = sum(1 for a in attempts if a.outcome in NOT_TESTED_OUTCOMES)
    no_verdict = sum(1 for a in attempts if attempt_reached_no_verdict(a))
    if not (untested or no_verdict):
        return

    parts = []
    if no_verdict:
        parts.append(
            f"{no_verdict} reached NO VERDICT (the agent engaged, but the "
            "deterministic predicate declined to rule and this demo runs with no "
            "LLM judge, so nothing decided them)"
        )
    if untested:
        was = "was" if untested == 1 else "were"
        parts.append(
            f"{untested} {was} NOT TESTED (the attack was delivered but the agent never engaged)"
        )
    console_print(
        console,
        f"[yellow]coverage: of {len(attempts)} attempts across both builds, "
        f"{' and '.join(parts)}. A ⚠ cell is not a clean one — it establishes "
        "nothing in either direction.[/yellow]",
        highlight=False,
    )


def render_demo(
    vulnerable: ScanResult,
    guarded: ScanResult,
    *,
    mode: str,
    elapsed_s: float,
    console: Console | None = None,
) -> None:
    """Render the vulnerable-vs-guarded differential for ``mylonite demo``."""
    if console is None:
        console = Console()

    console_print(
        console, Panel(f"[bold]{SAFETY_BANNER}[/bold] (see SECURITY.md).", border_style="yellow")
    )

    rows = [
        (
            weakness,
            _WEAKNESS_NAMES[weakness],
            _taxonomy_cell(weakness),
            _aggregate_mark(vulnerable, _WEAKNESS_PATTERNS[weakness]),
            _aggregate_mark(guarded, _WEAKNESS_PATTERNS[weakness]),
        )
        for weakness in _WEAKNESS_ORDER
    ]
    widths = [
        max(cell_len(cell) for cell in column) for column in zip(_COLUMNS, *rows, strict=True)
    ]
    # Rich spends one border per column plus one, and one space of padding on
    # each side of every cell.
    wide = console.width >= sum(widths) + 3 * len(widths) + 1
    if wide:
        _print_wide_table(console, rows)
    else:
        _print_narrow_table(console, rows, widths)

    n_vuln = vulnerable.report.findings_count
    n_guard = guarded.report.findings_count
    console_print(
        console, _HEADLINE_TEMPLATE.format(n_vuln=n_vuln, n_guard=n_guard), highlight=False
    )
    if n_guard > 0:
        console_print(console, f"[yellow]{_GUARDED_FINDING_NOTE}[/yellow]", highlight=False)
    _print_coverage_note(console, vulnerable, guarded)
    console_print(console, _TEASER, highlight=False)
    console_print(console, _NEXT_STEP, highlight=False)
    # The replay label carries "; recorded <date> against <model>", and the
    # model id is long enough to push the whole line past 80 columns. The
    # provenance goes on its own line so `mode: replay` always reads as one.
    label, _, provenance = mode.partition(MODE_PROVENANCE_SEP)
    console_print(console, f"mode: {label} — {elapsed_s:.1f}s", highlight=False)
    if provenance:
        console_print(console, provenance, highlight=False)


_TABLE_TITLE: Final[str] = "the reference app — vulnerable vs guarded build"
_COLUMNS: Final[tuple[str, ...]] = (
    "weakness",
    "name",
    "taxonomy (OWASP LLM / ASI / ATLAS)",
    "vulnerable",
    "guarded",
)

_Row = tuple[Weakness, str, str, str, str]


def _print_wide_table(console: Console, rows: list[_Row]) -> None:
    """Every column on one line: the layout for a terminal the table fits in."""
    table = Table(title=_TABLE_TITLE, title_justify="left", show_lines=False)
    for header in _COLUMNS:
        table.add_column(header, no_wrap=True)
    for weakness, name, taxonomy, vuln_mark, guard_mark in rows:
        table.add_row(weakness, name, taxonomy, _styled(vuln_mark), _styled(guard_mark))
    console_print(console, table)


def _print_narrow_table(console: Console, rows: list[_Row], widths: list[int]) -> None:
    """The layout for a terminal narrower than the full table, 80 columns included.

    Rich shrinks a table that does not fit by cutting every cell to an ellipsis,
    which turned the weakness IDs into nothing and the verdicts into ``v…``. So
    the taxonomy leaves the table for a legend underneath, the verdict and ID
    columns are held at their full width, and only the name gives way -- broken
    after a hyphen, since the names are single hyphenated words that Rich would
    otherwise split mid-word.
    """
    weakness_w, name_w, _, vuln_w, guard_w = widths
    # Four columns: five borders and two spaces of padding per column.
    name_room = console.width - (weakness_w + vuln_w + guard_w) - 3 * 4 - 1
    table = Table(title=_TABLE_TITLE, title_justify="left", show_lines=False)
    table.add_column(_COLUMNS[0], no_wrap=True, min_width=weakness_w)
    table.add_column(_COLUMNS[1], no_wrap=False, ratio=1, overflow="fold")
    table.add_column(_COLUMNS[3], no_wrap=True, min_width=vuln_w)
    table.add_column(_COLUMNS[4], no_wrap=True, min_width=guard_w)
    for weakness, name, _taxonomy, vuln_mark, guard_mark in rows:
        if name_room < name_w:
            name = "\n".join(textwrap.wrap(name, width=max(name_room, 1), break_on_hyphens=True))
        table.add_row(weakness, name, _styled(vuln_mark), _styled(guard_mark))
    console_print(console, table)

    legend = Table.grid(padding=(0, 2))
    legend.add_column(no_wrap=True)
    legend.add_column()
    for weakness, _name, taxonomy, _vuln, _guard in rows:
        legend.add_row(weakness, taxonomy)
    console_print(console, "taxonomy (OWASP LLM / ASI / ATLAS):", highlight=False)
    console_print(console, legend, highlight=False)
