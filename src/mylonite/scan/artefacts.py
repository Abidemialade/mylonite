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
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rich.console import Console
from rich.table import Table

from mylonite.scan.engine import ScanResult

OUTCOME_MARKS: Final[dict[str, str]] = {
    "finding": "✗ FOUND",
    "no_finding": "✓ clean",
    "skipped_invalid_metadata": "⚠ skipped",
    "skipped_unknown_seed": "⚠ skipped",
    "skipped_planner_failure": "⚠ skipped",
    "skipped_dry_run": "· dry-run",
    "error": "✗ error",
}

# Pre-v0.3.0 private name — kept as an alias so existing call sites stay valid.
_OUTCOME_MARK: Final = OUTCOME_MARKS


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


def render_summary(result: ScanResult) -> str:
    """Build a Rich-rendered summary table and return it as plain text."""
    report = result.report
    buffer = io.StringIO()
    console = Console(file=buffer, width=110, force_terminal=False)

    table = Table(
        title=f"Mylonite scan — {report.target_id}",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("status", no_wrap=True)
    table.add_column("seed_id", no_wrap=True)
    table.add_column("mechanism", no_wrap=True)
    table.add_column("reason")

    for attempt in report.attempts:
        mark = OUTCOME_MARKS.get(attempt.outcome, attempt.outcome)
        table.add_row(
            mark,
            attempt.seed_id,
            attempt.verdict_mechanism or "-",
            attempt.verdict_reason or "",
        )

    console.print(table)
    counts = (
        f"{len(report.attempts)} attempts · {report.findings_count} findings · "
        f"provider={report.provider} · model={report.model} · "
        f"{report.elapsed_seconds:.1f}s"
    )
    console.print(counts)
    if report.aborted:
        console.print(f"[red]aborted: {report.aborted}[/red]")
    return buffer.getvalue()
