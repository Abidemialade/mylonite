"""Artefact writing and stdout summary rendering for ScanResult.

* ``write_artefacts(result, output_dir)`` — creates an ISO-timestamped
  subdirectory and writes ``scan_report.json`` plus one
  ``exploit_<pattern_id>.json`` per finding. JSON serialised via the Pydantic
  models so the on-disk shape matches the committed schemas at
  ``src/mylonite/schemas/``.
* ``render_summary(result)`` — returns a string with a Rich-rendered summary
  table the CLI prints unmodified.
"""

from __future__ import annotations

import io
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rich import box
from rich.console import Console
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite._redaction import redact
from mylonite.scan.engine import ScanResult

# Outcomes that mean "an attack was NOT exercised" — distinct from a benign
# skip (the seed didn't apply) and CRUCIALLY distinct from a proven `no_finding`.
# A scan with these but zero findings is NOT a clean result: those seeds tested
# nothing. They get a loud mark and a summary warning so the gap is never silent.
NOT_TESTED_OUTCOMES: Final[frozenset[str]] = frozenset(
    {"skipped_no_seed_arm", "skipped_payload_not_delivered"}
)

OUTCOME_MARKS: Final[dict[str, str]] = {
    "finding": "✗ FOUND",
    "no_finding": "✓ clean",
    "skipped_invalid_metadata": "⚠ skipped",
    "skipped_unknown_seed": "⚠ skipped",
    "skipped_planner_failure": "⚠ skipped",
    "skipped_no_seed_arm": "⚠ NOT TESTED",
    "skipped_payload_not_delivered": "⚠ NOT TESTED",
    "skipped_dry_run": "· dry-run",
    "error": "✗ error",
}

# ASCII fallback marks for non-UTF-8 consoles (Windows cp1252) — a completed
# scan must never crash on output just because a glyph can't be encoded.
OUTCOME_MARKS_ASCII: Final[dict[str, str]] = {
    "finding": "FOUND",
    "no_finding": "clean",
    "skipped_invalid_metadata": "skip",
    "skipped_unknown_seed": "skip",
    "skipped_planner_failure": "skip",
    "skipped_no_seed_arm": "NOT-TESTED",
    "skipped_payload_not_delivered": "NOT-TESTED",
    "skipped_dry_run": "dry-run",
    "error": "error",
}

# Pre-v0.3.0 private name — kept as an alias so existing call sites stay valid.
_OUTCOME_MARK: Final = OUTCOME_MARKS


def _stdout_is_ascii_only() -> bool:
    """True when stdout can't encode UTF-8 (e.g. a legacy Windows cp1252 console)."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    return enc not in {"utf8", "utf16", "utf16le", "utf16be", "utf32"}


def _sanitise_filename(pattern_id: str) -> str:
    """Make ``pattern_id`` safe for filesystem use."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", pattern_id).strip("-_.") or "unknown"


def _timestamped_subdir(root: Path) -> Path:
    """Return a never-collide subdir under ``root``."""
    base = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
    candidate = root / base
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = root / f"{base}-{suffix}"
    return candidate


def write_artefacts(result: ScanResult, output_root: Path) -> Path:
    """Write ``scan_report.json`` + exploit files; return the scan subdirectory."""
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    scan_dir = _timestamped_subdir(output_root)
    scan_dir.mkdir(parents=True)

    report_path = scan_dir / "scan_report.json"
    report_path.write_text(
        json.dumps(result.report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    for exploit in result.exploits:
        filename = f"exploit_{_sanitise_filename(exploit.pattern_id)}.json"
        path = scan_dir / filename
        path.write_text(
            json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return scan_dir


def render_summary(result: ScanResult, *, ascii_safe: bool | None = None) -> str:
    """Build a Rich-rendered summary table and return it as REDACTED plain text.

    ``ascii_safe`` forces ASCII-only output (marks, box, separators) so the
    string is safe to print to a non-UTF-8 console; ``None`` auto-detects from
    ``sys.stdout``. A completed scan must never crash on output (Issue #9) — the
    CLI already forces UTF-8, but driver/embedded callers may not.

    The returned string is passed through :func:`mylonite._redaction.redact`
    before it comes back, so every current AND future caller is safe by
    construction — one review found a caller (``mylonite report``) that
    rendered this exact string to a real console with no redaction, even
    though ``mylonite scan`` redacted it. Free-text cell values
    (``attempt.verdict_reason``) are ALSO redacted before they reach the
    table, not just here: Rich wraps a cell's text to fit the column width,
    which can split a secret-shaped token across a line break and defeat a
    regex over the final flattened string.
    """
    if ascii_safe is None:
        ascii_safe = _stdout_is_ascii_only()
    marks = OUTCOME_MARKS_ASCII if ascii_safe else OUTCOME_MARKS
    sep = " | " if ascii_safe else " · "
    report = result.report
    buffer = io.StringIO()
    console = Console(file=buffer, width=110, force_terminal=False)

    table = Table(
        title=f"Mylonite scan - {report.target_id}",
        title_justify="left",
        show_lines=False,
        box=box.ASCII if ascii_safe else box.HEAVY_HEAD,
    )
    table.add_column("status", no_wrap=True)
    table.add_column("seed_id", no_wrap=True)
    table.add_column("mechanism", no_wrap=True)
    table.add_column("reason")

    for attempt in report.attempts:
        mark = marks.get(attempt.outcome, attempt.outcome)
        table.add_row(
            mark,
            attempt.seed_id,
            attempt.verdict_mechanism or "-",
            # Free text (an LLM judge's rationale can quote target/response
            # content) — redact before Rich's column-width wrapping, not after.
            redact(attempt.verdict_reason or ""),
        )

    console_print(console, table)
    counts = (
        f"{len(report.attempts)} attempts{sep}{report.findings_count} findings{sep}"
        f"provider={report.provider}{sep}model={report.model}{sep}"
        f"{report.elapsed_seconds:.1f}s"
    )
    console_print(console, counts)
    if report.inconclusive_attempts:
        judged = sum(1 for a in report.attempts if a.verdict_mechanism == "llm")
        denom = judged or report.inconclusive_attempts
        line = (
            f"judge: {report.inconclusive_attempts}/{denom} attempts inconclusive "
            f"(unparseable/failed LLM output) - {report.fallback_breakdown}"
        )
        # A scan where every judged attempt fell back found nothing because it
        # could not judge; it must not read as clean.
        style = "bold red" if report.inconclusive_attempts >= denom else "yellow"
        console_print(console, f"[{style}]{line}[/{style}]")
    # R7: a customiser fallback means a seed body was NOT refined for this target
    # (raw seed used) — surface it so a low-quality plant isn't invisible.
    customiser_fallbacks = report.fallback_breakdown.get("customiser_fallback", 0)
    if customiser_fallbacks:
        console_print(
            console,
            f"[yellow]customiser: {customiser_fallbacks} payload(s) used the raw seed "
            "body (LLM customisation fell back) - the plant may be less target-tuned"
            "[/yellow]",
        )
    nrun_disagreements = report.fallback_breakdown.get("nrun_disagreement", 0)
    if nrun_disagreements:
        console_print(
            console,
            f"[yellow]flakiness: {nrun_disagreements} payload(s) disagreed across runs "
            "(N-run majority decided) - the finding is not perfectly reproducible[/yellow]",
        )
    # Correctness safeguard (PR3): an attempt that was NOT TESTED (poison never
    # delivered / no seed_arm to plant) proved nothing — it must not let a
    # findings_count==0 scan read as "clean". Surface the gap loudly so a misfire
    # can never be mistaken for safety.
    not_tested = sum(1 for a in report.attempts if a.outcome in NOT_TESTED_OUTCOMES)
    if not_tested:
        console_print(
            console,
            f"[bold red]coverage: {not_tested} attempt(s) were NOT TESTED "
            "(planted payload undelivered, no seed_arm, or no plant/sink/recall "
            "surface) - those seeds proved NOTHING. This is not a clean result for "
            "them; declare a seed_arm (and for the tool-chaining / memory modes, "
            "ensure the target exposes a plant + sink/recall surface), then "
            "re-scan.[/bold red]",
        )
    if report.aborted:
        console_print(console, f"[red]aborted: {report.aborted}[/red]")
    return redact(buffer.getvalue())
