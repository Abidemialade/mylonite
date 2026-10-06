"""Gate orchestration: sequence scan -> generate -> validate -> assemble -> PR.

Owns the SEQUENCE and the exit-code decision only. Collaborators are injected so
the Typer command supplies live ones and tests supply offline fakes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite import reason_codes
from mylonite._cli_io import echo
from mylonite._redaction import redact, redact_value
from mylonite._replay import FixtureError
from mylonite._verdict import (
    STABLE_NOT_PROVEN,
    is_black_box_keep,
    verdict_label,
    verdict_reason,
)
from mylonite.contracts import ExploitRecord, GeneratedTest, ValidationReport
from mylonite.exit_codes import (
    EXIT_CONFIG,
    EXIT_GATE_CANDIDATES,
    EXIT_GATE_KEPT,
    EXIT_GENERATE_FAILED,
    EXIT_NOT_KEPT,
    EXIT_SUCCESS,
    EXIT_VALIDATE_FAILED,
)
from mylonite.gate.mitigation import (
    build_gate_pr_body,
    commits_as_pending,
    severity_sort_kept,
    weakness_class_for,
)
from mylonite.scan.coverage import AbortReason, Coverage, ScanOutcome
from mylonite.scan.llm_types import CompletionFn
from mylonite.scan.weakness import WEAKNESS_CLASSES


@dataclass
class GateResult:
    exit_code: int
    opened_pr: bool = False
    branch: str | None = None
    kept: bool | None = None
    #: How many of the run's findings were kept / rejected (0/0 when the run
    #: never reached a per-finding verdict at all, e.g. an aborted scan).
    kept_count: int = 0
    rejected_count: int = 0
    #: How many findings reproduced but were not proven (STABLE, NOT PROVEN).
    #: They are reported as candidates and never written as gate tests.
    candidate_count: int = 0


@dataclass(frozen=True)
class _FindingOutcome:
    """One exploit's path through generate -> write -> validate.

    ``stage`` distinguishes WHY a finding did not end up kept, which is what
    lets the all-fail exit-code rule (``EXIT_GENERATE_FAILED`` /
    ``EXIT_VALIDATE_FAILED`` only when EVERY finding failed at that stage;
    ``EXIT_NOT_KEPT`` the moment a real differential verdict — kept or not —
    was reached for any finding) survive going from one exploit to N without
    re-deriving it from string matching.

    ``"candidate"`` is a finding the validator kept but did not prove
    (STABLE, NOT PROVEN): it is reported, never committed, never counted as
    kept.
    """

    exploit: ExploitRecord
    stage: str  # "kept" | "candidate" | "rejected" | "generate_failed" | "validate_failed"
    report: ValidationReport | None = None
    #: For "rejected": the first failed validation stage + its (redacted,
    #: capped) detail — what actually goes in the PR body's rejected-findings
    #: list. For "generate_failed"/"validate_failed": a plain description;
    #: there is no ValidationReport to draw a stage from.
    reason: str = ""


def _write_validation_report(out_dir: Path, report: ValidationReport) -> None:
    """Persist the oracle verdict to ``out_dir``, redacted for commit.

    Mirrors what ``validate`` writes so the two commands leave the same artefact
    on disk. ``outcome.detail`` and ``notes`` are free text that can carry a live
    exception message (DCR-0003) and this file gets committed to a branch, so the
    same sanitisation applies here.
    """
    from mylonite._redaction import redact

    sanitized = report.model_copy(
        update={
            "outcomes": [
                outcome.model_copy(update={"detail": redact(outcome.detail)})
                for outcome in report.outcomes
            ],
            "notes": redact(report.notes) if report.notes else report.notes,
        }
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "validation_report.json").write_text(
        sanitized.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )


def _write_redacted_exploit(path: Path, exploit: ExploitRecord) -> None:
    """Write ``exploit`` to ``path`` with secret-shaped values redacted.

    The exploit record carries the payload, the customised prompt and the
    target's reply, any of which can hold a live credential, and this file is
    committed (#223). Redacted the way ``scan`` and ``generate`` redact their
    copy of the same record: secret-shaped string leaves only, never structure.
    """
    path.write_text(
        json.dumps(redact_value(exploit.model_dump(mode="json")), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _rejection_reason(report: ValidationReport) -> str:
    """The first validation stage that actually FAILED the verdict, its
    detail redacted and capped — more actionable in the PR body's
    rejected-findings list than a bare "not kept". A ``report_only`` outcome
    (e.g. the custom-target effect leg with no ``effect_probe`` declared)
    never decided ``kept`` by definition, so a failed report-only leg must
    never be named as "the reason" — the real deciding stage may be a later,
    genuinely-gating one.
    """
    from mylonite._redaction import redact

    failed = next((o for o in report.outcomes if not o.passed and not o.report_only), None)
    if failed is None:
        return "the generated test was REJECTED (not kept)"
    detail = redact(failed.detail or "").strip()
    if len(detail) > 200:
        detail = detail[:200].rstrip() + "…"
    return f"failed the {failed.stage} stage" + (f": {detail}" if detail else "")


@dataclass(frozen=True)
class ScanOutcomeBundle:
    """What ``scan_fn`` hands ``run_gate``: the typed verdict AND the exploits.

    Replaces a bare ``list[ExploitRecord]`` seam (the A-series false-clean bug:
    a scan that never actually ran — e.g. ``provider_unreachable`` — and a
    scan that ran cleanly both produced an empty list, and ``run_gate``
    couldn't tell them apart). Carrying ``outcome`` alongside the exploits
    makes that distinction structurally reachable at the call site.
    """

    outcome: ScanOutcome
    exploits: list[ExploitRecord]


#: Hex digits of ``sha256(pattern_id)`` in a finding's short id.
FINDING_HASH_LENGTH = 6
#: The longest short id a gate assigns before a collision suffix: a
#: two-character weakness tag, a dash and the hash, e.g. ``w4-1a2b3c``.
FINDING_ID_LENGTH = 2 + 1 + FINDING_HASH_LENGTH


def _finding_id(exploit: ExploitRecord) -> str:
    """A short, stable folder and file id for one finding, e.g. ``w4-1a2b3c``.

    The weakness class (``W1``..``W4``, lower-cased, resolved the way the PR
    body resolves it so it does not flip between runs; ``f`` when none is
    known) keeps it readable; six hex digits of the pattern id's
    SHA-256 keep it stable run to run. The full pattern id stays in the
    test's docstring, the exploit JSON, the console summary and the PR body.
    It is this short so a gate dir fits under Windows' 260-character path
    limit from a checkout about 200 characters deep.
    """
    import hashlib

    raw = weakness_class_for(exploit)
    tag = raw.lower() if raw in WEAKNESS_CLASSES else "f"
    digest = hashlib.sha256(exploit.pattern_id.encode("utf-8")).hexdigest()
    return f"{tag}-{digest[:FINDING_HASH_LENGTH]}"


def _finding_ids(exploits: list[ExploitRecord]) -> list[str]:
    """One short id per exploit, same order, with a deterministic ``-N``
    suffix when two DIFFERENT pattern ids share a weakness and hash prefix.
    Without it the second finding would overwrite the first's folder. Order
    is the caller's (already sorted by pattern_id), so the suffix is itself
    stable run to run. Computed for every run, not just a multi-finding one,
    since it also names the test file and where a rejected finding's
    evidence goes (see :func:`_finish_unkept`).
    """
    seen: dict[str, int] = {}
    ids: list[str] = []
    for exploit in exploits:
        base = _finding_id(exploit)
        count = seen.get(base, 0)
        seen[base] = count + 1
        ids.append(base if count == 0 else f"{base}-{count + 1}")
    return ids


def gate_test_filename(finding_id: str) -> str:
    """The test file a gate writes for the finding with this short id."""
    return f"test_{finding_id}.py"


def exploit_filename_for(test_filename: str) -> str:
    """The exploit JSON a gate writes next to ``test_filename``.

    Derived from the test file name the gate assigned (see
    :func:`gate_test_filename`), so the validator's copy, the committed path
    list and the file on disk always agree.
    """
    stem = Path(test_filename).stem
    return f"exploit_{stem.removeprefix('test_')}.json"


#: Matches the shape of a short id this gate assigns (see :func:`_finding_id`
#: / :func:`_finding_ids`): a weakness tag, a dash, six hex digits, and an
#: optional ``-N`` collision suffix. Matching this shape is never enough on
#: its own to treat something as the gate's own output -- see
#: :func:`_our_pattern_id_if_marker`, which is always checked alongside it.
_FINDING_ID_SHAPE = re.compile(r"^[a-z][a-z0-9]*-[0-9a-f]{6}(?:-\d+)?$")


def _our_pattern_id_if_marker(path: Path) -> str | None:
    """The ``pattern_id`` recorded in ``path``, iff it is a file this gate
    could actually have written: valid JSON holding the shape of an
    :class:`ExploitRecord` dump (see :func:`_write_redacted_exploit`). ``None``
    for anything else -- a missing file, unreadable JSON, or JSON that is not
    shaped like this gate's own record -- so a user's own ``exploit_*.json``
    sitting in the gate directory for some other reason is never mistaken for
    this gate's own marker and named in :func:`_leftover_earlier_findings`.
    An empty string is a valid (if unusual) answer: the record is genuinely
    ours, it just has no pattern id recorded.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not (isinstance(data, dict) and "pattern_id" in data and "payload" in data):
        return None
    pattern_id = data.get("pattern_id")
    return pattern_id if isinstance(pattern_id, str) else ""


def _leftover_earlier_findings(out_dir: Path, current_ids: set[str]) -> list[tuple[str, str]]:
    """Every finding id under ``out_dir`` this gate itself kept on an earlier
    run against this ``--out``, that the current run does not touch at all
    (#225) -- reported, never removed. ``gate`` never deletes anything from
    ``--out``: pruning what an earlier run wrote needs a manifest of what
    Mylonite itself wrote, which is a separate, larger change (tracked
    outside this one). "Not touched by the current run" is also not evidence
    that the earlier finding is gone -- a flaky miss, a NOT TESTED or aborted
    attempt, or a target file that now declares a narrower
    ``weakness_classes`` can all make a real, still-live finding vanish from
    one run's own ``current_ids`` without it having been fixed at all.

    An id the current run DOES reprocess is never reported here, kept or not:
    :func:`_snapshot_earlier` / :func:`_put_back_earlier` already restore
    that finding's earlier KEPT test byte for byte if this run's own attempt
    does not keep it, so there is nothing stale to report for it.

    Returns ``(finding_id, pattern_id)`` pairs, sorted by id. Matched only by
    BOTH the gate's own naming shape (:data:`_FINDING_ID_SHAPE`) AND one of
    its own marker files -- a genuine ``exploit_*.json`` record
    (:func:`_our_pattern_id_if_marker`), never a directory or file recognised
    by name alone, so a user's own similarly-named file or folder is never
    listed as if this gate had written it. A symlink or junction — to a
    finding folder, or to a loose ``test_<id>.py`` — is always skipped: this
    function only ever reads, never writes or removes, but a link into
    somewhere unexpected is never worth following just to decide what to
    print.
    """
    if not out_dir.is_dir():
        return []
    leftovers: dict[str, str] = {}
    for child in sorted(out_dir.iterdir()):
        if (
            child.name in current_ids
            or child.is_symlink()
            or not _FINDING_ID_SHAPE.match(child.name)
        ):
            continue
        try:
            if not child.is_dir():
                continue
        except OSError:
            continue
        for exploit_path in sorted(child.glob("exploit_*.json")):
            pattern_id = _our_pattern_id_if_marker(exploit_path)
            if pattern_id is not None:
                leftovers[child.name] = pattern_id
                break
    for test_path in sorted(out_dir.glob("test_*.py")):
        if test_path.is_symlink():
            continue
        finding_id = test_path.stem.removeprefix("test_")
        if finding_id in current_ids or finding_id in leftovers:
            continue
        if not _FINDING_ID_SHAPE.match(finding_id):
            continue
        exploit_path = out_dir / exploit_filename_for(test_path.name)
        pattern_id = _our_pattern_id_if_marker(exploit_path)
        if pattern_id is not None:
            leftovers[finding_id] = pattern_id
    return sorted(leftovers.items())


def _partial_scan_reason(outcome: ScanOutcome) -> str | None:
    """Why this run's own scan may not have reached every earlier finding, or
    ``None`` when it ran to completion with full coverage -- appended to
    :func:`_report_leftover_earlier_findings`'s note so "not re-proven" is
    never read as "fixed" when the scan itself didn't get the chance to
    re-check.
    """
    if outcome.abort is not None:
        return f"this run's scan aborted ({outcome.abort.value}) before finishing"
    if outcome.coverage is not Coverage.EXERCISED:
        return f"this run's scan coverage was partial ({outcome.not_tested} attempt(s) not tested)"
    return None


def _report_leftover_earlier_findings(
    out_dir: Path, current_ids: set[str], outcome: ScanOutcome
) -> None:
    """Print, never remove, every earlier kept finding this run did not
    touch (#225). ``gate`` never deletes anything from ``--out`` -- see
    :func:`_leftover_earlier_findings` for why "not found again" is not
    evidence of staleness.
    """
    leftovers = _leftover_earlier_findings(out_dir, current_ids)
    if not leftovers:
        return
    lines = [
        f"Mylonite gate: {len(leftovers)} earlier kept finding(s) under {out_dir} were "
        "left in place, not re-proven this run:"
    ]
    for finding_id, pattern_id in leftovers:
        label = f" ({pattern_id})" if pattern_id else ""
        lines.append(f"  {finding_id}{label}")
    reason = _partial_scan_reason(outcome)
    if reason is not None:
        lines.append(f"  ({reason} -- this run may simply not have reached it yet)")
    lines.append(
        "Delete a leftover's own folder (or its root test_<id>.py/exploit_<id>.json) "
        "yourself once you've confirmed the weakness is fixed."
    )
    echo("\n".join(lines))


#: Windows' MAX_PATH is 260 characters including the terminating NUL, so a
#: file path can hold 259. It applies unless long paths are enabled in the
#: registry (``LongPathsEnabled``); Python itself is long-path aware.
WINDOWS_MAX_PATH = 259


def _windows_long_paths_enabled() -> bool:
    """``True`` when Windows' ``LongPathsEnabled`` registry flag is set."""
    try:
        import winreg

        with winreg.OpenKey(  # type: ignore[attr-defined,unused-ignore]
            winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined,unused-ignore]
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
        ) as key:
            value, _kind = winreg.QueryValueEx(  # type: ignore[attr-defined,unused-ignore]
                key, "LongPathsEnabled"
            )
    except (ImportError, OSError):
        return False
    return bool(value == 1)


def _path_limit() -> int | None:
    """The longest file path this machine can write, or ``None`` for no limit
    a gate can reach (Linux and macOS allow 4096)."""
    if sys.platform != "win32" or _windows_long_paths_enabled():
        return None
    return WINDOWS_MAX_PATH


def _absolute(path: Path) -> Path:
    """``path`` made absolute and normalised the way Windows counts it, without
    resolving links (``resolve()`` could swap in a different, longer path)."""
    return Path(os.path.normpath(Path(path).absolute()))


def gate_paths(
    out_dir: Path, finding_ids: list[str] | None = None, *, multi: bool = True
) -> list[Path]:
    """Every file a gate run writes for these findings, kept or rejected.

    The names come from the short ids the gate assigns, never from pattern
    ids or a generator, so the prediction cannot drift from what is written.
    ``finding_ids`` defaults to one placeholder of the longest id the gate
    can assign, collision suffix included: the bound the command checks
    before the scan. :func:`run_gate` checks again with the real ids.
    ``multi`` gives each finding its own folder, as a multi-finding run does;
    the preflight assumes it, so a gate dir that fits today still fits when a
    later run finds a second weakness. The longest name in a fixture folder
    is a recorded response (:data:`mylonite._replay.FIXTURE_NAME_LENGTH`
    hex digits).
    """
    from mylonite._replay import FIXTURE_NAME_LENGTH

    out_dir = _absolute(out_dir)
    if finding_ids is None:
        # Shaped like a real id (`w0-000000-0`) so a refusal names a path a
        # reader recognises.
        finding_ids = ["w0-" + "0" * FINDING_HASH_LENGTH + "-0"]
    fixture = "0" * FIXTURE_NAME_LENGTH + ".json"
    paths: list[Path] = []
    for finding_id in finding_ids:
        test_name = gate_test_filename(finding_id)
        names = [test_name, exploit_filename_for(test_name), "validation_report.json"]
        kept_dir = out_dir / finding_id if multi else out_dir
        for folder in (kept_dir, _rejected_evidence_dir(out_dir, finding_id)):
            paths.extend(folder / name for name in names)
            paths.extend(folder / "fixtures" / name for name in (fixture, "_meta.json"))
    return paths


def gate_path_problem(
    out_dir: Path,
    finding_ids: list[str] | None = None,
    *,
    multi: bool = True,
    limit: int | None = None,
) -> str | None:
    """One line naming the longest path a gate under ``out_dir`` would write,
    when it is longer than this machine allows; ``None`` when it fits.

    ``limit`` defaults to the machine's own (:func:`_path_limit`). The line
    is a single line with no glyphs, so it prints on any console; only the
    path the user chose can carry non-ASCII characters.
    """
    limit = limit if limit is not None else _path_limit()
    if limit is None:
        return None
    longest = max(gate_paths(out_dir, finding_ids, multi=multi), key=lambda p: len(str(p)))
    length = len(str(longest))
    if length <= limit:
        return None
    root = str(_absolute(out_dir))
    return (
        f"error: gate output path too long for Windows: {length} characters, over "
        f"the {limit}-character limit ({longest}). Shorten the --out directory "
        f"({len(root)} characters now) by at least {length - limit} characters, "
        "or enable Windows long paths."
    )


def _rejected_evidence_dir(out_dir: Path, finding_id: str) -> Path:
    """Where a REJECTED or validate-failed finding's artefacts are relocated
    to: ``<out>-rej/<id>/``, a directory that is a SIBLING of ``out_dir``,
    never a descendant of it. Two independent things rely on that: (1) the
    committed `git add` path list only ever names files under ``out_dir``
    (see ``gate/wiring.py``'s ``open_pr_fn``), so nothing here can be swept
    in by it; (2) a later `gate` run reusing the same ``--out`` writes fresh
    content back under ``out_dir`` without ever having to know this
    directory exists, so stale evidence from an earlier run's rejected
    finding can never leak into a later run's own commit. The suffix is
    short because this is the deepest folder a gate writes.
    """
    return out_dir.parent / f"{out_dir.name}-rej" / finding_id


@dataclass(frozen=True)
class _EarlierFiles:
    """What a finding's folder held, under the names this run writes, before
    the run wrote into it: usually an earlier run's KEPT test, exploit and
    replay fixtures for the same finding id (ids are stable run to run)."""

    #: The test and exploit files that existed, with their bytes.
    files: dict[Path, bytes]
    #: ``fixtures/`` relative path -> bytes, or ``None`` when there was none.
    fixtures: dict[str, bytes] | None


def _snapshot_earlier(this_out: Path, paths: list[Path]) -> _EarlierFiles:
    """Read what ``paths`` and ``this_out/fixtures`` hold before this run
    overwrites them, so a run that does not keep can put them back."""
    files = {path: path.read_bytes() for path in paths if path.is_file()}
    fixtures_dir = this_out / "fixtures"
    fixtures = (
        {
            item.relative_to(fixtures_dir).as_posix(): item.read_bytes()
            for item in fixtures_dir.rglob("*")
            if item.is_file()
        }
        if fixtures_dir.is_dir()
        else None
    )
    return _EarlierFiles(files=files, fixtures=fixtures)


def _is_link(path: Path) -> bool:
    """True for a symlink, or a Windows junction (which ``is_symlink`` misses
    before Python 3.12)."""
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return bool(isjunction(path))
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _put_back_earlier(this_out: Path, rejected_dir: Path, earlier: _EarlierFiles) -> None:
    """Restore what this finding's folder held before the run.

    Whatever the run left in ``this_out/fixtures`` (a single-finding run
    records into the gate root's shared folder) moves to the evidence folder
    first, so this run's recordings never mix into a kept test's fixtures.
    Then the earlier files are written back byte for byte.
    """
    _put_back_fixtures(this_out, rejected_dir, earlier)
    for path, data in earlier.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _put_back_fixtures(this_out: Path, rejected_dir: Path, earlier: _EarlierFiles) -> None:
    """Move this run's ``fixtures/`` to the evidence folder, then write the
    earlier run's fixtures back byte for byte."""
    fixtures_dir = this_out / "fixtures"
    if fixtures_dir.is_dir():
        rejected_dir.mkdir(parents=True, exist_ok=True)
        dest = rejected_dir / "fixtures"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(fixtures_dir), str(dest))
    for rel, data in (earlier.fixtures or {}).items():
        target = fixtures_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _finish_unkept(
    this_out: Path,
    out_dir: Path,
    finding_id: str,
    message: str,
    written: list[Path],
    earlier: _EarlierFiles,
) -> None:
    """Echo the per-finding verdict, then relocate the files this REJECTED,
    candidate or validate-failed finding wrote into
    :func:`_rejected_evidence_dir`, and put back what the finding's folder
    held before the run (see :func:`_put_back_earlier`).
    Evidence stays on disk there for local debugging; it is simply outside
    anywhere a commit — automatic or printed for the operator to run by
    hand — ever looks.

    Only ``written`` moves, never a directory. A single finding writes
    straight into ``out_dir``, which can already hold an earlier run's kept
    tests, ``target.yaml`` and workflows; moving the directory took all of
    that with it, and the next rejected run then deleted it. Each file
    replaces only the same-named file of this finding's own earlier
    evidence, so other findings' evidence is never touched. A per-finding
    subdirectory left empty by the move is removed.

    The one directory that moves is ``fixtures/``: a per-finding
    subdirectory's own, or, in a single-finding run, the gate root's. An
    earlier run's KEPT test, exploit and fixtures under the same id are put
    back byte for byte, so a run that does not keep never removes or alters a
    proven test.
    """
    echo(message)
    present = [p for p in written if p.exists()]
    fixtures = this_out / "fixtures"
    if not present and not fixtures.is_dir() and not earlier.files:
        return
    rejected_dir = _rejected_evidence_dir(out_dir, finding_id)
    rejected_dir.mkdir(parents=True, exist_ok=True)
    for path in present:
        dest = rejected_dir / path.name
        if dest.exists():
            dest.unlink()
        shutil.move(str(path), str(dest))
    _put_back_earlier(this_out, rejected_dir, earlier)
    if this_out != out_dir and this_out.exists() and not any(this_out.iterdir()):
        this_out.rmdir()
    echo(
        f"Mylonite gate: {finding_id}: evidence kept at {rejected_dir} for local debugging "
        "(not committed)."
    )


def _how_to_prove(report: ValidationReport) -> str:
    """One sentence on what would turn this candidate into a kept finding."""
    if is_black_box_keep(report):
        return "Gate cannot prove a finding on a black-box target."
    # `gate` always runs the build leg, so a missing proof leg is the only
    # other way a keep reads STABLE, NOT PROVEN here.
    return (
        "To prove it, let a guarded side run (declare `control_env` so Mylonite "
        "can switch your real safeguard off and on, and drop `--fast`) or "
        "declare an `effect_probe` in the target file, then re-run `mylonite gate`."
    )


def candidate_reason(report: ValidationReport) -> str:
    """Why a finding is only a candidate, and how to get it proven."""
    return f"{verdict_reason(report)} {_how_to_prove(report)}"


def candidate_line(exploit: ExploitRecord, report: ValidationReport) -> str:
    """The console line for one candidate. One line, plain ASCII apart from
    the pattern id, so it prints on any console."""
    return (
        f"Mylonite gate: {exploit.pattern_id}: {STABLE_NOT_PROVEN} - a candidate "
        f"only, not written as a gate test: {candidate_reason(report)}"
    )


def _candidates_section(candidates: list[tuple[ExploitRecord, str]]) -> str:
    """The PR-body section that lists findings `gate` would not commit."""
    rows = [
        "",
        "",
        "## Candidates (not proven, not committed)",
        "",
        "_Each of these reproduced, but nothing proved a safeguard stops it, so "
        "`gate` did not write or commit a test for it._",
        "",
    ]
    rows.extend(f"- `{exploit.pattern_id}`: {reason}" for exploit, reason in candidates)
    return "\n".join(rows) + "\n"


def _for_generation(exploit: ExploitRecord, finding_id: str) -> ExploitRecord:
    """The copy of ``exploit`` handed to ``generate_fn``.

    It carries the finding's short id, so the bundled generator names the
    exploit file the emitted test loads after it (a generator that ignores
    the id still gets its test file renamed, see :func:`_process_one_finding`).
    A finding that still works on the user's app is also tagged so its test
    is emitted as a pending fix (see :func:`commits_as_pending`). Only this
    copy carries the tags: the exploit JSON written next to the test is
    always the untagged record, so a later ``mylonite generate`` run from it
    (after the fix) emits a plain regression test.
    """
    from mylonite.plugins._reference.reference_pytest_generator import (
        GATE_ID_METADATA_KEY,
        PENDING_FIX_METADATA_KEY,
    )

    meta = {**exploit.payload.metadata, GATE_ID_METADATA_KEY: finding_id}
    if commits_as_pending(exploit):
        meta[PENDING_FIX_METADATA_KEY] = "true"
    return exploit.model_copy(
        update={"payload": exploit.payload.model_copy(update={"metadata": meta})}
    )


def _process_one_finding(
    exploit: ExploitRecord,
    out_dir: Path,
    finding_id: str,
    *,
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest, Path], ValidationReport | None],
    multi: bool,
) -> _FindingOutcome:
    """Generate, write, and validate ONE finding. Never raises for a per-finding
    failure (generate/validate returning ``None``) — that is recorded as a
    ``_FindingOutcome`` so one bad finding cannot hide the rest."""
    this_out = out_dir / finding_id if multi else out_dir
    prefix = f"Mylonite gate: {exploit.pattern_id}: " if multi else "Mylonite gate: "

    generated = generate_fn(_for_generation(exploit, finding_id))
    if generated is None:
        reason = "the test generator returned nothing"
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="generate_failed", reason=reason)

    # The gate names the files, not the generator: `test_<id>.py` and
    # `exploit_<id>.json`. The short id keeps the gate dir under Windows' path
    # limit, gives every finding's test a unique module name for pytest, and
    # is what the path check before the scan predicted.
    generated = generated.model_copy(update={"filename": gate_test_filename(finding_id)})
    expected_exploit = exploit_filename_for(generated.filename)
    if "exploit_" in generated.source and expected_exploit not in generated.source:
        # The test loads an exploit file by some other name: committed, it
        # could never find its data. Fail here, before anything is written.
        reason = f"the generated test does not load {expected_exploit}"
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="generate_failed", reason=reason)

    this_out.mkdir(parents=True, exist_ok=True)
    test_path = this_out / generated.filename
    exploit_path = this_out / expected_exploit
    written = [test_path, exploit_path]
    fixtures_dir = this_out / "fixtures"
    if _is_link(fixtures_dir):
        # Gate replaces this folder before it records; a link would point
        # that at somewhere else. Never follow it, never delete through it.
        reason = (
            f"its fixtures folder {fixtures_dir} is a symlink or junction, which gate "
            "will not follow or replace; make it a plain folder, then re-run"
        )
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="validate_failed", reason=reason)
    # An earlier run may have kept a test under this same id. Read it first,
    # so a run that does not keep can put it back untouched.
    earlier = _snapshot_earlier(this_out, written)
    # This finding's own `fixtures/` folder is re-recorded from scratch: an
    # earlier run's recordings (possibly in an older replay-key format) would
    # otherwise mix with this run's. The snapshot above holds their bytes, so
    # a run that does not keep, or raises, puts them back.
    if earlier.fixtures is not None:
        shutil.rmtree(this_out / "fixtures")
    test_path.write_text(generated.source, encoding="utf-8")
    _write_redacted_exploit(exploit_path, exploit)

    # The pending tag only shapes the emitted test. Hand the validator the
    # untagged record so it never reaches the payloads it builds.
    generated = generated.model_copy(update={"exploit": exploit})
    try:
        try:
            # The validator gets this finding's own directory: a route that
            # records replay fixtures writes them to `this_out/fixtures`, where
            # this finding's test reads them, never to a directory shared by
            # findings.
            report = validate_fn(generated, this_out)
        finally:
            # The validator may write its own copy of the exploit next to the
            # test (the reference route records fixtures there). Write the
            # redacted record again, even if validation raised, so whatever
            # ends up committed or kept for debugging is redacted.
            _write_redacted_exploit(exploit_path, exploit)
    except FixtureError as exc:
        # A recording problem is this finding's failure, not the run's: say
        # so, put the earlier files back, and go on to the next finding.
        reason = f"its replay fixtures could not be recorded ({redact(str(exc))})"
        message = f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate."
        _finish_unkept(this_out, out_dir, finding_id, message, written, earlier)
        return _FindingOutcome(exploit=exploit, stage="validate_failed", reason=reason)
    except BaseException:
        # Any other stop (budget, interrupt, a target that went down) leaves
        # the run's partial recording as evidence and restores what an earlier
        # run kept under this id (test, exploit and fixtures), before the error
        # propagates.
        if earlier.files or earlier.fixtures is not None:
            _put_back_earlier(this_out, _rejected_evidence_dir(out_dir, finding_id), earlier)
        raise
    if report is None:
        reason = "the validator returned nothing"
        message = f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate."
        _finish_unkept(this_out, out_dir, finding_id, message, written, earlier)
        return _FindingOutcome(exploit=exploit, stage="validate_failed", reason=reason)

    if not report.kept:
        # The console line stays the historical wording; the PR-body reason
        # (below) is the one that carries the actual failed-stage detail —
        # keeping the two separate means neither has to compromise.
        console_reason = "the generated test was REJECTED (not kept)"
        message = (
            f"{prefix}{console_reason}." if multi else f"{prefix}{console_reason} — no PR opened."
        )
        _finish_unkept(this_out, out_dir, finding_id, message, written, earlier)
        return _FindingOutcome(
            exploit=exploit, stage="rejected", report=report, reason=_rejection_reason(report)
        )

    if verdict_label(report) == STABLE_NOT_PROVEN:
        # Never keep unproven: the test reproduced but nothing proved a
        # safeguard stops the attack. Move its files out of the gate dir, the
        # way a rejected finding's are, so no commit can pick them up, and
        # keep the validation report with that evidence (never in the gate
        # dir, where it could overwrite an earlier kept run's report).
        _finish_unkept(
            this_out, out_dir, finding_id, candidate_line(exploit, report), written, earlier
        )
        _write_validation_report(_rejected_evidence_dir(out_dir, finding_id), report)
        return _FindingOutcome(
            exploit=exploit, stage="candidate", report=report, reason=candidate_reason(report)
        )

    # Persist the oracle verdict BEFORE any git contact. The generated test and
    # the exploit JSON were already on disk above, but the validation report --
    # the most expensive artefact of the run -- was only ever written by
    # `validate`, so a failure in the git/gh step threw it away.
    _write_validation_report(this_out, report)
    return _FindingOutcome(exploit=exploit, stage="kept", report=report)


def _coverage_note(outcome: ScanOutcome) -> str:
    """One PR-body line when the scan behind this PR did not exercise every
    attempt, so a reviewer never reads the gated findings as a complete
    result. Empty when coverage was complete.

    An abort can leave ``not_tested == 0``: a seed the scan never reached
    was never added to ``attempts`` at all, so nothing was classified
    NOT_TESTED, even though coverage is still PARTIAL because
    ``abort is not None``. Naming the abort there instead of a zero count
    avoids a note that reads as a contradiction next to a gated finding.
    """
    if outcome.coverage is Coverage.EXERCISED:
        return ""
    if outcome.abort is not None and outcome.not_tested == 0:
        return (
            "\n\n> **Coverage was incomplete.** The scan did not finish "
            f"({outcome.abort.value}), so this PR gates what it proved before "
            "stopping; it does not show the rest of the target is clean.\n"
        )
    return (
        f"\n\n> **Coverage was incomplete.** {outcome.not_tested} attempt(s) were NOT "
        "TESTED, so this PR gates what the scan proved; it does not show the rest of "
        "the target is clean.\n"
    )


def _layout_table(
    out_dir: Path,
    kept: list[tuple[ExploitRecord, ValidationReport]],
    kept_dirs: list[Path],
) -> str:
    """A PR-body table mapping each kept finding to the files that gate it.

    Finding folders and test files are named by short id (``w4-1a2b3c``), so
    the reviewer needs this to see which pattern each folder holds. Paths are
    relative to the gate directory and built from the same names the commit
    stages (``report.test_filename`` in each finding's own folder).
    """
    rows = [
        "",
        "",
        "| Finding | Test |",
        "|---|---|",
    ]
    for (exploit, report), kept_dir in zip(kept, kept_dirs, strict=True):
        rel = (kept_dir / report.test_filename).relative_to(out_dir).as_posix()
        rows.append(f"| `{exploit.pattern_id}` | `{rel}` |")
    return "\n".join(rows) + "\n"


def _request_ceiling_tripped() -> bool:
    from mylonite.scan._llm import request_ceiling_hit

    return request_ceiling_hit() is not None


def _echo_nonempty(message: str) -> None:
    if message:
        echo(message)


def _abort_message(outcome: ScanOutcome, budget_hint_text: str | None) -> str:
    """The operator-facing message for an aborted scan. ``scan``'s own budget
    message ends by suggesting ``--weakness-class``, which is `scan`-only —
    `gate` has no such flag, and for a custom target the real lever is the
    target file's own ``weakness_classes:`` key. Rather than tamper with the
    shared ``ScanOutcome`` message text (also used verbatim by ``scan``
    itself, where it IS correct), `gate` prints its own self-contained
    message for a budget abort specifically, using the hint
    ``gate/wiring.budget_hint()`` computed — the same function ``cli.py``'s
    own direct ``BudgetExceededError`` handler calls, so both paths agree.
    Every other abort reason's message doesn't mention a nonexistent flag,
    so it is printed unchanged.
    """
    if outcome.abort is AbortReason.BUDGET_EXCEEDED and _request_ceiling_tripped():
        return ""  # the CLI prints the one line that names the hard ceiling
    if outcome.abort is AbortReason.BUDGET_EXCEEDED and budget_hint_text:
        return reason_codes.tag(
            reason_codes.ABT_BUDGET_EXCEEDED,
            "error: gate's scan phase exhausted its LLM call budget and stopped "
            f"early; coverage is incomplete. {budget_hint_text}",
        )
    return outcome.operator_message or (
        "Mylonite gate: the scan did not complete a trustworthy run "
        f"(coverage={outcome.coverage.name}, abort={outcome.abort}) — cannot gate."
    )


def run_gate(
    *,
    out_dir: Path,
    scan_fn: Callable[[], ScanOutcomeBundle],
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest, Path], ValidationReport | None],
    open_pr_fn: Callable[..., Any],
    open_pr: bool,
    llm_enrich: bool = False,
    mitigation_model: str | None = None,
    mitigation_completion_fn: CompletionFn | None = None,
    system_prompt: str | None = None,
    target_context: Any | None = None,
    budget_hint_text: str | None = None,
    validation_cost_hint: str | None = None,
    workflows: bool = False,
) -> GateResult:
    def _note_no_workflows_written() -> None:
        # `--workflows` only ever renders .github/workflows/* from inside
        # open_pr_fn (gate/wiring.py), which this function calls only once
        # something was KEPT (see the bottom of this function) -- every
        # return point above that call skips write_workflows entirely. #225:
        # that used to be silent; every such return now says so plainly,
        # and only when the operator actually asked for a workflow this run.
        if workflows:
            echo(
                "Mylonite gate: --workflows was given, but nothing was kept this run, so "
                "no CI workflow file was written -- a workflow only wires in a kept "
                "finding's test, and this run kept none."
            )

    bundle = scan_fn()
    exploits = bundle.exploits
    if not exploits:
        # An empty exploits list is ambiguous on its own: it means either "the
        # scan genuinely ran and found nothing" or "the scan never meaningfully
        # ran" (aborted, e.g. provider_unreachable, or every attempt errored
        # out without an explicit abort). ``trustworthy_clean`` is what
        # disambiguates the two — a real finding (exploits non-empty) is
        # trusted regardless of overall coverage, matching pre-existing
        # behaviour where a partial/aborted scan that still found something
        # before stopping is gated on that finding.
        if not bundle.outcome.trustworthy_clean:
            _echo_nonempty(_abort_message(bundle.outcome, budget_hint_text))
            _note_no_workflows_written()
            return GateResult(exit_code=bundle.outcome.exit_code, opened_pr=False, kept=None)
        echo("Mylonite gate: no exploit found — nothing to gate.")
        _note_no_workflows_written()
        return GateResult(exit_code=EXIT_SUCCESS, opened_pr=False, kept=None)

    # Deterministic order: every finding is gated, in the same order every
    # run, regardless of what order the scan happened to discover them.
    sorted_exploits = sorted(exploits, key=lambda e: e.pattern_id)
    multi = len(sorted_exploits) > 1
    finding_ids = _finding_ids(sorted_exploits)
    # The command checked the path before the scan against the longest id the
    # gate can assign. Check the real ids too before paying for any
    # validation, so the two can never disagree silently.
    path_problem = gate_path_problem(out_dir, finding_ids, multi=multi)
    if path_problem is not None:
        echo(f"{path_problem} The scan ran; nothing was generated or validated.")
        _note_no_workflows_written()
        return GateResult(exit_code=EXIT_CONFIG, opened_pr=False, kept=None)
    if multi:
        n = len(sorted_exploits)
        cost = f" — {validation_cost_hint}" if validation_cost_hint else ""
        echo(f"{n} findings: validating each (about {n}x the single-finding validation cost{cost})")

    # A reused --out can still hold this gate's own KEPT output from an
    # earlier run, for a finding id this run no longer finds at all. #225:
    # report it, never remove it -- "not found again" is not evidence the
    # finding is fixed (a flaky miss, a NOT TESTED/aborted attempt, or a
    # narrower target scope can all do the same). An id this run DOES
    # process is never reported here; the per-finding snapshot/restore below
    # already owns that one.
    _report_leftover_earlier_findings(out_dir, set(finding_ids), bundle.outcome)

    # With multiple findings, give each its own subdir so tests don't clobber
    # each other; a single finding keeps the exact dir the operator chose —
    # mirrors `generate`'s identical convention (generate/wiring.py's
    # _resolve_exploit_paths + cli.py's `generate`).
    outcomes = [
        _process_one_finding(
            exploit,
            out_dir,
            finding_id,
            generate_fn=generate_fn,
            validate_fn=validate_fn,
            multi=multi,
        )
        for exploit, finding_id in zip(sorted_exploits, finding_ids, strict=True)
    ]

    kept = [(o.exploit, o.report) for o in outcomes if o.stage == "kept" and o.report is not None]
    # Parallel to `kept`: the exact directory `open_pr_fn` must treat as
    # committed for that finding — never re-derived independently downstream
    # (a re-derived id in wiring.py could disagree with a de-duplicated one
    # from _finding_ids above).
    kept_dirs = [
        (out_dir / finding_id if multi else out_dir)
        for outcome, finding_id in zip(outcomes, finding_ids, strict=True)
        if outcome.stage == "kept"
    ]
    # Most-severe-first (ties broken by pattern_id): a reviewer with several
    # kept findings in one gate PR sees the one that matters most first. The
    # same permutation is applied to both lists, so the PR body, the
    # per-finding layout table below and the git-add list all agree on order.
    kept, kept_dirs = severity_sort_kept(kept, kept_dirs)
    candidates = [(o.exploit, o.reason) for o in outcomes if o.stage == "candidate"]
    rejected = [(o.exploit, o.reason) for o in outcomes if o.stage not in ("kept", "candidate")]

    if multi and candidates:
        echo(
            f"{len(kept)} kept, {len(candidates)} not proven (candidates, not committed), "
            f"{len(rejected)} rejected"
        )
    elif multi:
        echo(f"{len(kept)} kept, {len(rejected)} rejected")
    # Files are named by short id; say which pattern each one gates.
    for (exploit, report), kept_dir in zip(kept, kept_dirs, strict=True):
        echo(f"Mylonite gate: {exploit.pattern_id} -> {kept_dir / report.test_filename}")

    def _finish(result: GateResult) -> GateResult:
        # An aborted scan (budget exhausted or any other abort) always
        # carries the scan's own exit code and operator message, even when
        # proven findings were gated and a PR was opened/printed for them —
        # mirroring ScanOutcome.from_report's own "abort always wins" rule so
        # `gate` cannot silently exit 0 on a budget-exhausted run just because
        # it found something before the budget ran out.
        # Without an abort, the scan's own caveat (findings alongside NOT
        # TESTED attempts) still prints: `scan` shows it, and a gate run over
        # the same scan must not hide it. The exit code is unchanged.
        if bundle.outcome.abort is not None:
            _echo_nonempty(_abort_message(bundle.outcome, budget_hint_text))
            result.exit_code = bundle.outcome.exit_code
        elif bundle.outcome.operator_message:
            echo(bundle.outcome.operator_message)
        if result.kept is not True:
            _note_no_workflows_written()
        return result

    if not kept and candidates:
        echo(
            f"Mylonite gate: no proven finding to gate - {len(candidates)} candidate(s), "
            "nothing written as a gate test, no PR opened."
        )
        return _finish(
            GateResult(
                exit_code=EXIT_GATE_CANDIDATES,
                opened_pr=False,
                kept=False,
                rejected_count=len(rejected),
                candidate_count=len(candidates),
            )
        )
    if not kept:
        stages = {o.stage for o in outcomes}
        if stages <= {"generate_failed"}:
            return _finish(
                GateResult(
                    exit_code=EXIT_GENERATE_FAILED,
                    opened_pr=False,
                    kept=None,
                    rejected_count=len(rejected),
                )
            )
        if stages <= {"generate_failed", "validate_failed"}:
            return _finish(
                GateResult(
                    exit_code=EXIT_VALIDATE_FAILED,
                    opened_pr=False,
                    kept=None,
                    rejected_count=len(rejected),
                )
            )
        # `_process_one_finding` already echoed the per-finding rejected
        # message above; for a single exploit that IS the whole story, so
        # printing another summary line here would just repeat it verbatim.
        # A genuinely multi-finding run still gets an aggregate line, since
        # its per-finding lines differ from it.
        if multi:
            echo("Mylonite gate: no generated test was kept — no PR opened.")
        return _finish(
            GateResult(
                exit_code=EXIT_NOT_KEPT, opened_pr=False, kept=False, rejected_count=len(rejected)
            )
        )

    # build_pr_body stays per-finding (mitigation.py); build_gate_pr_body is
    # the thin wrapper that joins the kept findings' sections and lists the
    # rejected ones with their reason.
    body = build_gate_pr_body(
        kept,
        rejected,
        llm_enrich=llm_enrich,
        model=mitigation_model,
        completion_fn=mitigation_completion_fn,
        system_prompt=system_prompt,
        target=target_context,
        gate_dir=out_dir,
    )
    body += _coverage_note(bundle.outcome)
    if candidates:
        body += _candidates_section(candidates)
    if multi:
        body += _layout_table(out_dir, kept, kept_dirs)
    pr = open_pr_fn(out_dir=out_dir, findings=kept, kept_dirs=kept_dirs, body=body, open_pr=open_pr)
    opened = bool(getattr(pr, "opened", False))
    branch = getattr(pr, "branch", None)
    return _finish(
        GateResult(
            exit_code=EXIT_GATE_KEPT,
            opened_pr=opened,
            branch=branch,
            kept=True,
            kept_count=len(kept),
            rejected_count=len(rejected),
            candidate_count=len(candidates),
        )
    )
