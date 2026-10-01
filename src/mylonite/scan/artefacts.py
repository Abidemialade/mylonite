"""Artefact writing and stdout summary rendering for ScanResult.

* ``write_artefacts(result, output_dir)`` — creates an ISO-timestamped
  subdirectory and writes ``scan_report.json`` plus one
  ``exploit_<pattern_id>.json`` per finding. JSON serialised via the Pydantic
  models so the on-disk shape matches the committed schemas at
  ``src/mylonite/schemas/``. A scan whose attempts were decided by the trace
  rule (or whose target carries a calibration summary) also gets a
  ``verdicts.json`` sidecar: the per-class summary, its reason codes and
  proof levels, and the calibration certificate.
* ``render_summary(result)`` — returns a string with a Rich-rendered summary
  table the CLI prints unmodified.
"""

from __future__ import annotations

import io
import json
import re
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print
from mylonite._paths import safe_slug
from mylonite._redaction import redact, redact_value
from mylonite.contracts import ExploitRecord, ScanReport, ToolSpec
from mylonite.reason_codes import NT_MODULE_LOAD_FAILED, format_code_counts
from mylonite.scan._llm import LLMSpend
from mylonite.scan.assembly import unmatched_opt_in_note
from mylonite.scan.class_verdict import (
    CalibrationSummary,
    ClassVerdict,
    class_verdicts,
    has_trace_outcome,
)
from mylonite.scan.coverage import (
    ATTEMPT_CLASS,
    MODULE_LOAD_FAILURE_KEY,
    NO_ATTACK_EMITTED_KEY,
    AttemptClass,
    adjudication_counts,
    attempt_reached_no_verdict,
    reason_code_for_attempt,
)
from mylonite.scan.engine import ScanResult
from mylonite.scan.evidence_tier import attempt_evidence_tier, tier_counts

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
    # Distinct from BOTH "✓ clean" and "⚠ NOT TESTED". The attack was delivered
    # AND the agent engaged — but nothing adjudicated the result, so the cell
    # establishes nothing in either direction.
    "undecided": "⚠ NO VERDICT",
    "skipped_invalid_metadata": "⚠ skipped",
    "skipped_unknown_seed": "⚠ skipped",
    "skipped_planner_failure": "⚠ skipped",
    # Named separately from a planner skip because the remedy differs: the
    # target's command never started.
    "launch_failure": "⚠ LAUNCH FAILED",
    "skipped_no_seed_arm": "⚠ NOT TESTED",
    "skipped_payload_not_delivered": "⚠ NOT TESTED",
    "skipped_planner_no_engagement": "⚠ NOT TESTED",
    "skipped_dry_run": "· dry-run",
    "error": "✗ error",
}

# ASCII fallback marks for non-UTF-8 consoles (Windows cp1252) — a completed
# scan must never crash on output just because a glyph can't be encoded.
OUTCOME_MARKS_ASCII: Final[dict[str, str]] = {
    "finding": "FOUND",
    "no_finding": "clean",
    "not_applicable": "N/A-no-capability",
    "undecided": "NO-VERDICT",
    "skipped_invalid_metadata": "skip",
    "skipped_unknown_seed": "skip",
    "skipped_planner_failure": "skip",
    "launch_failure": "LAUNCH-FAILED",
    "skipped_no_seed_arm": "NOT-TESTED",
    "skipped_payload_not_delivered": "NOT-TESTED",
    "skipped_planner_no_engagement": "NOT-TESTED",
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


#: The one format for a scan directory's name. `_timestamped_subdir` writes it
#: and `parse_scan_dir_timestamp` reads it back, so the two cannot drift.
_SCAN_DIR_TIME_FORMAT: Final = "%Y-%m-%dT%H-%M-%SZ"

#: How old a `--latest` scan may be before `generate` mentions it. A judgement
#: call, not a measured threshold: long enough not to nag during an ordinary
#: scan-then-generate session, short enough to catch "I ran that last week".
STALE_SCAN_AGE: Final = timedelta(hours=24)


def find_latest_scan_dir(scans_root: Path) -> Path | None:
    """Return the newest ``<ts>/`` subdir under ``scans_root``.

    Scan dirs are ISO-timestamped by :func:`_timestamped_subdir`, so the
    lexically-greatest name is the most recent. ``None`` if the root is absent
    or empty.

    Note what this does NOT consider: how old that directory is. A caller
    offering a ``--latest`` affordance should say which one it picked — see
    :func:`warn_if_scan_is_stale`.
    """
    if not scans_root.is_dir():
        return None
    candidates = sorted((p for p in scans_root.iterdir() if p.is_dir()), reverse=True)
    return candidates[0] if candidates else None


def parse_scan_dir_timestamp(scan_dir: Path) -> datetime | None:
    """UTC time from a scan directory's name, or ``None``.

    The inverse of :func:`_timestamped_subdir`, including its ``-N`` collision
    suffix. Returns ``None`` -- never raises -- for a hand-created or
    older-format directory, because staleness is advisory and must not be able
    to break the command that consults it.
    """
    base = re.sub(r"-\d+$", "", scan_dir.name)
    try:
        return datetime.strptime(base, _SCAN_DIR_TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def warn_if_scan_is_stale(scan_dir: Path, *, emit: Callable[[str], None]) -> None:
    """Advisory note when a resolved scan is older than :data:`STALE_SCAN_AGE`.

    Deliberately non-fatal, and deliberately not raising. Scanning once then
    generating or gating repeatedly while iterating on the emitted test is a
    normal workflow, and an old-but-valid scan is a legitimate input -- the
    problem being addressed is only that the choice was previously invisible.

    ``emit`` is injected rather than imported so this stays free of CLI
    concerns, per this package's no-``typer`` rule.
    """
    recorded = parse_scan_dir_timestamp(scan_dir)
    if recorded is None:
        return
    age = datetime.now(UTC) - recorded
    if age <= STALE_SCAN_AGE:
        return
    emit(
        f"warning: that scan is {age.days}d old. It may predate changes to the "
        "target, the seeds, or the model. Re-run `mylonite scan` if the emitted "
        "test should reflect the target as it is now."
    )


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
    base = datetime.now(UTC).strftime(_SCAN_DIR_TIME_FORMAT)
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

    if _has_class_summary(result):
        (scan_dir / VERDICTS_FILENAME).write_text(
            json.dumps(redact_value(_verdicts_document(result)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return scan_dir


#: The per-class summary sidecar. Like ``tool_surface.json``, NOT a ScanReport
#: field, so it costs no schema event and an older version simply ignores it.
VERDICTS_FILENAME: Final = "verdicts.json"
#: 1.1: added "evidence_tiers", top level and per class: findings by evidence
#: tier (state, trace, judge-only).
_VERDICTS_SCHEMA_VERSION: Final = "1.1"


def _has_class_summary(result: ScanResult) -> bool:
    """Whether this result gets the per-class summary (sidecar and block).

    Only when an attempt was decided by the trace rule, the target carries a
    calibration summary, an attack module failed to load, or a scheduled class
    had no attack emitted for it (#221). In the last two cases whole classes
    are NOT TESTED, and the class block is where that shows per class.
    Reference, REST and replayed scans otherwise have none of these, so their
    artefacts and output are unchanged.
    """
    return (
        has_trace_outcome(result.report)
        or result.calibration is not None
        or bool(_load_failures(result.report))
        or any(a.judge_evidence.get(NO_ATTACK_EMITTED_KEY) for a in result.report.attempts)
    )


def _load_failures(report: ScanReport) -> dict[str, tuple[str, str, list[str], str]]:
    """Attack modules that failed to load, read off the report's attempts.

    ``{entry point: (stage, error type, [lost classes], unmatched opt-in ids)}``;
    an empty class list means the module's classes are unknown.
    """
    out: dict[str, tuple[str, str, list[str], str]] = {}
    for attempt in report.attempts:
        evidence = attempt.judge_evidence
        module = evidence.get(MODULE_LOAD_FAILURE_KEY)
        if not module:
            continue
        _stage, _error, classes, _ids = out.setdefault(
            module,
            (
                evidence.get("load_stage", "load"),
                attempt.error_detail or "error",
                [],
                evidence.get("unmatched_opt_in", ""),
            ),
        )
        if evidence.get("weakness"):
            classes.append(evidence["weakness"])
    return out


def _load_failure_line(report: ScanReport) -> str | None:
    """The scan-level line naming each attack module that failed to load (#222)."""
    failures = _load_failures(report)
    if not failures:
        return None
    parts = []
    for module, (stage, error, classes, unmatched) in sorted(failures.items()):
        lost = f"{', '.join(classes)} NOT TESTED" if classes else "classes unknown, NOT TESTED"
        if unmatched:
            lost += f"; {unmatched_opt_in_note(unmatched.split(','))}"
        parts.append(f"{module} ({stage} failed: {error}; {lost})")
    text = (
        f"attack modules: {len(failures)} failed to load [{NT_MODULE_LOAD_FAILED}]: "
        f"{'; '.join(parts)}. Their attacks never ran, so this is not a clean result "
        "for what they cover."
    )
    return f"[bold red]{rich_escape(text)}[/bold red]"


def _verdicts_document(result: ScanResult) -> dict[str, object]:
    verdicts = class_verdicts(result.report, calibration=result.calibration)
    codes: dict[str, int] = {}
    proof_levels: dict[str, int] = {}
    for attempt in result.report.attempts:
        evidence = attempt.judge_evidence
        if attempt.outcome == "finding" and evidence.get("proof_level"):
            level = evidence["proof_level"]
            proof_levels[level] = proof_levels.get(level, 0) + 1
    for verdict in verdicts:
        for code in verdict.codes:
            codes[code] = codes.get(code, 0) + 1
    return {
        "schema_version": _VERDICTS_SCHEMA_VERSION,
        "target_id": result.report.target_id,
        "classes": [v.to_dict() for v in verdicts],
        # How many classes each code explains.
        "codes": codes,
        # How many findings were shown at each proof level.
        "proof_levels": proof_levels,
        # How many findings rest on the target's state, the trace, or the judge alone.
        "evidence_tiers": tier_counts(a for a in result.report.attempts if a.outcome == "finding"),
        "counts": {
            "finding": sum(v.findings for v in verdicts),
            "resisted": sum(v.resisted for v in verdicts),
            "server_reported": sum(v.server_reported for v in verdicts),
            "not_tested": sum(v.not_tested for v in verdicts),
        },
        "calibration": result.calibration.to_dict() if result.calibration else None,
    }


def read_verdicts_calibration(scan_dir: Path) -> CalibrationSummary | None:
    """The calibration summary a saved scan directory recorded, if any.

    ``None`` (never an exception) when ``verdicts.json`` is absent, malformed,
    or records no calibration, so ``mylonite report`` renders the same per-class
    block the scan printed whenever it can, and degrades to the attempts alone
    when it cannot.
    """
    path = Path(scan_dir) / VERDICTS_FILENAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return CalibrationSummary.from_dict(data.get("calibration"))


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
    # Derived, not read from a stamp, so an older scan_report.json gets one too.
    table.add_column("evidence", no_wrap=True)
    table.add_column("reason")

    # #206: an aborted run (e.g. budget exhausted) that still found something
    # must not bury those findings under whatever ran first — reorder the
    # table so they lead, without changing anything about a non-aborted run.
    rows = report.attempts
    if report.aborted and report.findings_count:
        from mylonite.scan.coverage import findings_first

        rows = findings_first(rows)  # type: ignore[assignment]

    for attempt in rows:
        mark = marks.get(attempt.outcome, attempt.outcome)
        table.add_row(
            mark,
            # seed_id/verdict_mechanism/verdict_reason are attacker/target-
            # influenced free text — escape Rich markup so a target response
            # quoting something shaped like a closing tag (e.g. "[/bold]")
            # can't raise MarkupError when the table renders (DCR-0004).
            rich_escape(attempt.seed_id),
            rich_escape(attempt.verdict_mechanism or "-"),
            attempt_evidence_tier(attempt) or "-",
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
    console_print(console, _verdicts_line(report, sep=sep))
    evidence_line = _evidence_line(report)
    if evidence_line:
        console_print(console, evidence_line)
    if result.llm_spend is not None:
        console_print(console, format_spend(result.llm_spend, sep=sep))
    if report.inconclusive_attempts:
        judged = sum(1 for a in report.attempts if a.verdict_mechanism == "llm")
        denom = judged or report.inconclusive_attempts
        # #212: not every inconclusive cause is a failed LLM CALL — an errored
        # effect_probe reaches this same tally (its judge_fallback_cause is
        # "effect_probe_errored", stamped as fallback_breakdown's
        # "judge_effect_probe_errored" key), and that is a probe read
        # failure, never an "unparseable/failed LLM output".
        only_effect_probe_errors = set(report.fallback_breakdown) <= {"judge_effect_probe_errored"}
        cause_label = (
            "effect_probe errored, the effect could not be confirmed"
            if only_effect_probe_errors
            else "unparseable/failed LLM output, or an effect_probe errored"
        )
        line = (
            f"judge: {report.inconclusive_attempts}/{denom} attempts inconclusive"
            f"{_codes_suffix(report.attempts, no_verdict_only=True)} "
            f"({cause_label}) - {report.fallback_breakdown}"
        )
        # A scan where every judged attempt fell back found nothing because it
        # could not judge; it must not read as clean.
        style = "bold red" if report.inconclusive_attempts >= denom else "yellow"
        console_print(console, f"[{style}]{line}[/{style}]")
    # A customiser fallback means a seed body was NOT refined for this target
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
    load_failure_line = _load_failure_line(report)
    if load_failure_line:
        console_print(console, load_failure_line)
    # Correctness safeguard (PR3): an attempt that was NOT TESTED (poison never
    # delivered / no seed_arm to plant) proved nothing — it must not let a
    # findings_count==0 scan read as "clean". Surface the gap loudly so a misfire
    # can never be mistaken for safety.
    not_tested = sum(1 for a in report.attempts if a.outcome in NOT_TESTED_OUTCOMES)
    if not_tested:
        console_print(
            console,
            f"[bold red]coverage: {not_tested} attempt(s) were NOT TESTED"
            f"{_codes_suffix(report.attempts)} "
            "(planted payload undelivered, no seed_arm, no plant/sink/recall "
            "surface, malformed seed metadata, an unresolvable seed, a planner "
            "failure, an attack module that failed to load, a class no attack "
            "module in this run emitted an attack for, or an unexpected error "
            "during invocation/judging) - those seeds proved NOTHING. This is not a "
            "clean result for them; reinstall any attack module named on the "
            "`attack modules:` line, declare a seed_arm (and for the tool-chaining / "
            "memory modes, ensure the target exposes a plant + sink/recall surface), "
            "check each attempt's "
            "verdict_reason/error_detail for the specific cause, then "
            "re-scan.[/bold red]",
        )
    if _has_class_summary(result):
        for line in _class_block(result, sep=sep):
            console_print(console, line)
    if report.aborted:
        console_print(console, f"[red]aborted: {report.aborted}[/red]")
    scope = _clean_result_scope(report, not_tested=not_tested)
    if scope:
        console_print(console, scope)
    return redact(buffer.getvalue())


def _class_line(verdict: ClassVerdict, *, sep: str) -> str:
    counts = [
        f"{n} {label}"
        for n, label in (
            (verdict.findings, "finding"),
            (verdict.resisted, "resisted"),
            (verdict.not_tested, "not tested"),
        )
        if n
    ]
    line = f"  {verdict.weakness}  {verdict.status}"
    if verdict.proof_levels:
        line += f"{sep}proof: {', '.join(verdict.proof_levels)}"
    if verdict.codes:
        line += f" [{', '.join(verdict.codes)}]"
    if counts:
        line += f" ({', '.join(counts)})"
    return rich_escape(line)


def _calibration_line(calibration: CalibrationSummary) -> str:
    line = f"calibration: {calibration.status}"
    if calibration.certified_tools:
        line += f" ({', '.join(calibration.certified_tools)})"
    codes = [c for c in (calibration.reason_code, calibration.seed_reason_code) if c]
    if codes:
        line += f" [{', '.join(dict.fromkeys(codes))}]"
    line += f"; seed control: {calibration.seed_status}"
    return rich_escape(line)


def _class_block(result: ScanResult, *, sep: str) -> list[str]:
    """One line per weakness class (``classes:``), then the calibration status.

    Look each code up in docs/reason-codes.md. Exit codes do not read this block.
    """
    verdicts = class_verdicts(result.report, calibration=result.calibration)
    lines: list[str] = []
    if verdicts:
        lines.append("classes:")
        lines.extend(_class_line(v, sep=sep) for v in verdicts)
    if result.calibration is not None:
        lines.append(_calibration_line(result.calibration))
    return lines


def _codes_suffix(attempts: Sequence[object], *, no_verdict_only: bool = False) -> str:
    """`` [MYL-NT-005 x2, ...]``: the reason codes behind a summary line, each
    looked up in docs/reason-codes.md. Empty when no attempt carries a code.

    Rich markup-escaped: a bare ``[MYL-...]`` would otherwise parse as a style tag.
    """
    codes = [
        code
        for a in attempts
        if not no_verdict_only or attempt_reached_no_verdict(a)
        if (code := reason_code_for_attempt(a)) is not None
    ]
    if not codes:
        return ""
    return " " + rich_escape(f"[{format_code_counts(codes)}]")


def format_spend(spend: LLMSpend, *, sep: str) -> str:
    """One line stating what a run spent on LLM calls.

    Calls by caller (planner / customiser / judge / ...), the cap when one was
    in force, and the tokens the provider reported. Token totals are marked
    partial when some calls reported no usage, so a provider that reports none
    never reads as a zero-token run.
    """
    callers = ", ".join(f"{name} {n}" for name, n in sorted(spend.by_caller.items()) if n)
    line = f"llm: {spend.calls} calls"
    if callers:
        line += f" ({callers})"
    if spend.cap:
        line += f" of {spend.cap} cap"
    if spend.calls_with_usage:
        tokens = f"{spend.prompt_tokens:,} in / {spend.completion_tokens:,} out tokens"
        if spend.calls_with_usage < spend.calls:
            tokens += f" (reported by {spend.calls_with_usage} of {spend.calls} calls)"
        line += f"{sep}{tokens}"
    return line


def spend_summary(spend: LLMSpend, elapsed_s: float) -> str:
    """The ``llm:`` line plus wall-clock, for a command that runs several scans."""
    sep = " | " if _stdout_is_ascii_only() else " · "
    return f"{format_spend(spend, sep=sep)}{sep}{elapsed_s:.1f}s"


def _verdicts_line(report: ScanReport, *, sep: str) -> str:
    """One line stating how the scan's verdicts were reached.

    Always printed, so a reader can see how much of a result was settled by a
    deterministic check and how much by the LLM judge, without having to read
    the per-attempt mechanism column.
    """
    counts = adjudication_counts(report)
    context = f"{counts.total_attempts} attempts"
    if counts.decided == 0:
        line = f"verdicts: none decided ({context})"
    else:
        line = (
            f"verdicts: {counts.predicate} by deterministic check{sep}"
            f"{counts.llm} by LLM judge (of {counts.decided} decided; {context})"
        )
    if counts.no_verdict:
        line += f"{sep}{counts.no_verdict} reached no verdict"
    return line


def _evidence_line(report: ScanReport) -> str | None:
    """What the findings rest on, by evidence tier; ``None`` with no findings.

    A finding only the LLM judge made reads ``judge-only``: nothing in the
    target's state or the recorded trace confirmed it, and ``validate`` will
    not keep a test on that alone.
    """
    findings = [a for a in report.attempts if a.outcome == "finding"]
    if not findings:
        return None
    counts = tier_counts(findings)
    line = "findings by evidence: " + ", ".join(f"{n} {tier}" for tier, n in counts.items())
    if counts["judge-only"]:
        return f"[yellow]{line} (judge-only: no state or trace confirmation)[/yellow]"
    return line


def _clean_result_scope(report: ScanReport, *, not_tested: int) -> str | None:
    """The scope of a clean result, stated where the clean result is read.

    Printed only for a scan that completed, exercised every attempt and found
    nothing: the case no other summary line addresses. It says what the result
    covers — the attack patterns in this run, against this model — so a clean
    scan reads as the scoped statement it is.
    """
    if report.findings_count or report.aborted or not_tested:
        return None
    decided = adjudication_counts(report).decided
    if decided == 0:
        return None
    return (
        f"result: every exercised attack was resisted ({decided} decided). This "
        f"covers the attack patterns run in this scan against {report.model}; "
        "re-scan when the system prompt, tools or model change."
    )
