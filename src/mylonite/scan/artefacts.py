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
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite._paths import safe_slug
from mylonite._redaction import redact, redact_value
from mylonite.contracts._types import ExploitRecord, ToolSpec
from mylonite.scan.coverage import ATTEMPT_CLASS, AttemptClass
from mylonite.scan.engine import ScanResult

# Outcomes that mean "an attack was NOT exercised" — distinct from a benign
# skip (the seed didn't apply) and CRUCIALLY distinct from a proven `no_finding`.
# A scan with these but zero findings is NOT a clean result: those seeds tested
# nothing. They get a loud mark and a summary warning so the gap is never silent.
#
# Derived from coverage.ATTEMPT_CLASS (the total, exhaustiveness-guarded
# classification of every ScanAttemptOutcome) instead of being maintained as a
# second, independent allowlist. Before this, a hand-maintained subset here
# (originally just {"skipped_no_seed_arm", "skipped_payload_not_delivered"})
# omitted "error" and the other structural skips — so a scan where every
# attempt raised an exception rendered "N attempts * 0 findings" with no
# warning, the exact false-clean this module exists to prevent. Deliberately
# excludes AttemptClass.INTENTIONALLY_SKIPPED (currently just
# "skipped_dry_run"): that's an operator choice, not a coverage gap.
NOT_TESTED_OUTCOMES: Final[frozenset[str]] = frozenset(
    outcome for outcome, cls in ATTEMPT_CLASS.items() if cls is AttemptClass.NOT_TESTED
)

OUTCOME_MARKS: Final[dict[str, str]] = {
    "finding": "✗ FOUND",
    "no_finding": "✓ clean",
    # Rendered distinctly from "✓ clean" ON PURPOSE. A cold-start user reported
    # shipping a scan as "this server passed the W2 check" when in fact both
    # attempts made zero tool calls, because the attacked capability did not
    # exist on that server — a distinction only visible by opening the raw JSON.
    # It is now visible in the table.
    "not_applicable": "⚠ N/A (no such capability)",
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
    "not_applicable": "N/A-no-capability",
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
    return safe_slug(pattern_id)


def _timestamped_subdir(root: Path) -> Path:
    """Atomically create and return a never-collide subdir under ``root``.

    DCR-0005: the previous ``candidate.exists()`` check then a separate
    ``mkdir()`` by the caller was a classic check-then-create race — two
    concurrent scans landing in the same ``output_dir`` within the same
    second could both pass the ``exists()`` check for the same candidate
    before either created it, and the second ``mkdir()`` would then raise (or,
    worse, silently write into the first scan's directory if the caller ever
    relaxed this to ``exist_ok=True``). ``mkdir(exist_ok=False)`` in a retry
    loop makes directory creation itself the atomicity boundary — there is no
    window between "check" and "create" for a second process to land in.
    """
    base = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
    suffix = 0
    while True:
        candidate = root / base if suffix == 0 else root / f"{base}-{suffix}"
        try:
            candidate.mkdir(parents=True)
            return candidate
        except FileExistsError:
            suffix += 1


def _disambiguated_exploit_filenames(exploits: list[ExploitRecord]) -> list[str]:
    """One ``exploit_<slug>[-N].json`` filename per exploit, never colliding.

    DCR-0006: two exploits can legitimately share a ``pattern_id`` — e.g. a
    ``runs>1`` flakiness-filter re-attempt, or a seed emitted by more than one
    attack module — and the OLD naming (``exploit_<pattern_id>.json``) let a
    later one silently overwrite an earlier one's evidence file on disk,
    losing that finding's evidence entirely. Each repeat of the same base
    filename gets a ``-N`` suffix instead.
    """
    seen: dict[str, int] = {}
    filenames: list[str] = []
    for exploit in exploits:
        base = f"exploit_{_sanitise_filename(exploit.pattern_id)}"
        count = seen.get(base, 0)
        seen[base] = count + 1
        filenames.append(f"{base}.json" if count == 0 else f"{base}-{count + 1}.json")
    return filenames


def write_artefacts(result: ScanResult, output_root: Path) -> Path:
    """Write ``scan_report.json`` + exploit files; return the scan subdirectory."""
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    scan_dir = _timestamped_subdir(output_root)

    # Redact before writing (DCR-0002): these artefacts are loadable/replayable
    # data, but a successful exfiltration attack can capture a live secret in
    # e.g. an exploit's response.raw_response, and the CLI's own UX tells the
    # operator to commit this exact directory. redact_value() masks only
    # secret-shaped string leaves (by key name or shape); it never changes the
    # JSON's structure or non-string values, so schema validation and replay
    # both keep working on the redacted copy.
    report_path = scan_dir / "scan_report.json"
    report_path.write_text(
        json.dumps(redact_value(result.report.model_dump(mode="json")), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    filenames = _disambiguated_exploit_filenames(result.exploits)
    for exploit, filename in zip(result.exploits, filenames, strict=True):
        path = scan_dir / filename
        path.write_text(
            json.dumps(redact_value(exploit.model_dump(mode="json")), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )

    # PR7: the tool inventory sidecar. NOT a ScanReport field -- ScanReport is
    # one of the five Pydantic contracts (contracts/_types.py, `extra="forbid"`),
    # so a new field there would make an artefact written by this version
    # unreadable by an older one loading it back. A sidecar costs no schema
    # event: `mylonite report` degrades gracefully (an enhancement-tier input,
    # per gate/recommend.py's TargetContext.tools docstring) when it's absent,
    # e.g. reading an artefact directory from a version that predates this file.
    if result.descriptor is not None:
        tool_surface_path = scan_dir / "tool_surface.json"
        tool_surface_path.write_text(
            json.dumps(
                redact_value(
                    {
                        "schema_version": "1.0",
                        "target_id": result.descriptor.target_id,
                        "tools": [t.model_dump(mode="json") for t in result.descriptor.tools],
                    }
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    return scan_dir


def read_tool_surface(scan_dir: Path) -> tuple[ToolSpec, ...] | None:
    """Read the ``tool_surface.json`` sidecar back, if present.

    ``None`` (never an exception) when the sidecar is absent — an artefact
    directory from a version predating PR7, or a scan whose ``describe()``
    failed before any tool inventory existed — or malformed. This is
    strictly an ENHANCEMENT-tier input to the structural recommendation
    engine (``gate/recommend.py``'s ``TargetContext.tools`` docstring): a
    scan/validation/report flow must fully function with an empty tuple
    here, never require this file to exist.
    """
    path = Path(scan_dir) / "tool_surface.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return tuple(ToolSpec.model_validate(t) for t in data["tools"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


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

    Every string cell built from attacker/target-influenced free text
    (``seed_id``, ``verdict_mechanism``, ``verdict_reason``) is also passed
    through :func:`rich.markup.escape` before ``add_row``. Redaction only
    masks secret-SHAPED tokens; it does not defend against Rich markup — a
    ``verdict_reason`` that quotes target output containing a stray
    ``[/bold]``-shaped substring (a closing tag with no matching open tag)
    raises ``rich.errors.MarkupError`` when the table is rendered, crashing
    the CLI after a successful scan (DCR-0004).
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
            # seed_id/verdict_mechanism/verdict_reason are attacker/target-
            # influenced free text — escape Rich markup so a target response
            # quoting something shaped like a closing tag (e.g. "[/bold]")
            # can't raise MarkupError when the table renders (DCR-0004).
            rich_escape(attempt.seed_id),
            rich_escape(attempt.verdict_mechanism or "-"),
            # Free text (an LLM judge's rationale can quote target/response
            # content) — redact before Rich's column-width wrapping, not after.
            rich_escape(redact(attempt.verdict_reason or "")),
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
            "(planted payload undelivered, no seed_arm, no plant/sink/recall "
            "surface, malformed seed metadata, an unresolvable seed, a planner "
            "failure, or an unexpected error during invocation/judging) - those "
            "seeds proved NOTHING. This is not a clean result for them; declare a "
            "seed_arm (and for the tool-chaining / memory modes, ensure the target "
            "exposes a plant + sink/recall surface), check each attempt's "
            "verdict_reason/error_detail for the specific cause, then "
            "re-scan.[/bold red]",
        )
    if report.aborted:
        console_print(console, f"[red]aborted: {report.aborted}[/red]")
    return redact(buffer.getvalue())
