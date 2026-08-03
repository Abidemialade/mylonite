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
from mylonite.scan.artefacts import OUTCOME_MARKS
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
    "Try it on YOUR app next: mylonite scan --command 'python server.py' --scaffold "
    "app.yaml, then mylonite scan --target-file app.yaml --authorize my-app "
    "(needs an LLM API key) — details: docs/test-your-app.md"
)

_FOUND_MARK: Final[str] = OUTCOME_MARKS["finding"]
_CLEAN_MARK: Final[str] = OUTCOME_MARKS["no_finding"]
_SKIPPED_MARK: Final[str] = OUTCOME_MARKS["skipped_planner_failure"]

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

    Binding rule: FOUND if ANY seed in the weakness found, else SKIPPED if any
    seed skipped / errored (or no attempt reached the weakness at all), else
    clean. A harness ``error`` outcome is intentionally absorbed into the
    SKIPPED bucket at this weakness-aggregation level (the demo only needs the
    found / not-found differential). Unknown outcome strings also fall into the
    skipped bucket — never crash.
    """
    # Join on pattern_id (== seed_id in v0.2); _WEAKNESS_PATTERNS is keyed the
    # same way, so a future pattern_id/seed_id divergence would surface as rows
    # quietly dropping into the skip bucket rather than a crash.
    outcomes = [
        attempt.outcome for attempt in result.report.attempts if attempt.pattern_id in pattern_ids
    ]
    if any(outcome == "finding" for outcome in outcomes):
        return _FOUND_MARK
    if not outcomes or any(outcome != "no_finding" for outcome in outcomes):
        return _SKIPPED_MARK
    return _CLEAN_MARK


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
            _aggregate_mark(vulnerable, pattern_ids),
            _aggregate_mark(guarded, pattern_ids),
        )
    console_print(console, table)

    n_vuln = vulnerable.report.findings_count
    n_guard = guarded.report.findings_count
    console_print(
        console, _HEADLINE_TEMPLATE.format(n_vuln=n_vuln, n_guard=n_guard), highlight=False
    )
    if n_guard > 0:
        console_print(console, f"[yellow]{_GUARDED_FINDING_NOTE}[/yellow]", highlight=False)
    console_print(console, _TEASER, highlight=False)
    console_print(console, _NEXT_STEP, highlight=False)
    console_print(console, f"mode: {mode} — {elapsed_s:.1f}s", highlight=False)
