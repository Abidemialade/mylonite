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

from collections.abc import Iterable
from typing import Final, get_args

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite.scan.artefacts import NOT_TESTED_OUTCOMES, OUTCOME_MARKS
from mylonite.scan.engine import ScanResult
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern, Weakness

SAFETY_BANNER: Final[str] = (
    "DEMO ONLY — the reference app is a deliberately vulnerable in-process "
    "agent. It never binds to a network. Never point Mylonite at a system you "
    "don't own or operate"
)
"""Bolded part of the safety banner; ``(see SECURITY.md).`` is appended unbolded."""

_HEADLINE_TEMPLATE: Final[str] = (
    "reference app: {n_vuln} exploits on vulnerable, {n_guard} on guarded — this "
    "differential is the oracle that validates every generated regression test"
)
_GUARDED_FINDING_NOTE: Final[str] = (
    "⚠ unexpected finding on the guarded build — LLM-judge noise or a real bug"
)
_TEASER: Final[str] = (
    "Each finding becomes a committed regression test, validated against this same "
    "vulnerable/guarded oracle. Turn one into a gating test: mylonite gate reference:vulnerable"
)
_NEXT_STEP: Final[str] = (
    "Try it on YOUR app next: mylonite scan --command python --arg server.py --scaffold "
    "app.yaml --scope my-app (free, no API key), then mylonite scan --target-file app.yaml "
    "--authorize my-app (needs an LLM API key) — details: docs/test-your-app.md"
)

_FOUND_MARK: Final[str] = OUTCOME_MARKS["finding"]
_CLEAN_MARK: Final[str] = OUTCOME_MARKS["no_finding"]
_SKIPPED_MARK: Final[str] = OUTCOME_MARKS["skipped_planner_failure"]
#: Distinct from the above: the attack was delivered but the agent never
#: engaged, so nothing was exercised. `scan/artefacts.py` already renders this
#: as its own mark and warns loudly about it; the demo table did not.
_NOT_TESTED_MARK: Final[str] = OUTCOME_MARKS["skipped_planner_no_engagement"]

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
}


def _styled(mark: str) -> str:
    """``mark`` wrapped in its Rich style, or returned unchanged if it has none.

    Styling is applied here rather than inside :func:`_aggregate_mark` so that
    function keeps returning a bare comparable string.
    """
    style = _MARK_STYLES.get(mark)
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
    """
    # Join on pattern_id (== seed_id in v0.2); _WEAKNESS_PATTERNS is keyed the
    # same way, so a future pattern_id/seed_id divergence would surface as rows
    # quietly dropping into the skip bucket rather than a crash.
    outcomes = [
        attempt.outcome for attempt in result.report.attempts if attempt.pattern_id in pattern_ids
    ]
    if any(outcome == "finding" for outcome in outcomes):
        return _FOUND_MARK
    if not outcomes:
        return _SKIPPED_MARK
    if all(outcome == "no_finding" for outcome in outcomes):
        return _CLEAN_MARK
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
    """
    untested = sum(
        1
        for result in (vulnerable, guarded)
        for attempt in result.report.attempts
        if attempt.outcome in NOT_TESTED_OUTCOMES
    )
    if not untested:
        return
    console_print(
        console,
        f"[yellow]coverage: {untested} attempt(s) were NOT TESTED — the attack was "
        "delivered but the agent never engaged, so those seeds established nothing "
        "in either direction. A ⚠ cell is not a clean one.[/yellow]",
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

    table = Table(
        title="the reference app — vulnerable vs guarded build",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("weakness", no_wrap=True)
    table.add_column("name", no_wrap=True)
    table.add_column("taxonomy (OWASP LLM / ASI / ATLAS)", no_wrap=True)
    table.add_column("vulnerable", no_wrap=True)
    table.add_column("guarded", no_wrap=True)

    for weakness in _WEAKNESS_ORDER:
        pattern_ids = _WEAKNESS_PATTERNS[weakness]
        table.add_row(
            weakness,
            _WEAKNESS_NAMES[weakness],
            _taxonomy_cell(weakness),
            _styled(_aggregate_mark(vulnerable, pattern_ids)),
            _styled(_aggregate_mark(guarded, pattern_ids)),
        )
    console_print(console, table)

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
    console_print(console, f"mode: {mode} — {elapsed_s:.1f}s", highlight=False)
