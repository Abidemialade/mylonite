#!/usr/bin/env python3
"""Score a third-party-campaign run against verification/PREREG_THIRD_PARTY_2026_10.md.

Why this exists
----------------
``.github/workflows/third-party-campaign.yml`` runs Mylonite's own CLI
against six systems it has never run against before (see
``verification/SOURCE.md`` and ``verification/PREREG_THIRD_PARTY_2026_10.md``).
Each cell runs the real journey -- ``scan`` then ``generate`` then
``validate`` -- so a ``validation_report.json`` is written next to the
generated test REGARDLESS of whether the finding was kept (the standalone
``validate`` command always persists one; only ``gate``'s orchestrator skips
it for a rejected finding, which is why this harness drives the three
commands directly rather than ``gate``). This script turns one such
directory into a single classification the prereg's pass rule defines, and
then combines N classifications (the N=3, >=2/3 bar for targets 1-3) into
one cell verdict.

Classification, in order of precedence
---------------------------------------
1. ``PRODUCT_DEFECT`` -- the run cannot be trusted as a clean result.
   **A Python traceback with at least one actual ``mylonite`` STACK FRAME
   anywhere in the captured log wins this classification outright**, before
   anything else is even considered: Mylonite's own code is designed to
   catch and cleanly report provider and config errors (``aborted``,
   ``classify_provider_error``), so a raw traceback FROM MYLONITE'S OWN CODE
   leaking to stdout means something it did not anticipate, regardless of
   what the traceback's text happens to contain. "An actual stack frame"
   means a quoted ``File "...mylonite/....py"`` reference with "mylonite" as
   a PATH SEGMENT -- never a bare substring match anywhere in the block,
   which would also fire on a target's own planted/echoed content that
   happens to contain the word "mylonite" (e.g. ``redis.yaml``'s seed key
   literal ``mylonite-tpv-seed``, which a target server could echo back
   verbatim in its own error message). A traceback with NO such frame at all
   -- the target server's own crash -- is target noise, not a Mylonite
   defect: the stdio adapter spawns each target server without separating
   its stderr from Mylonite's own (``_session_adapter.py``'s
   ``stdio_client`` call carries no ``errlog``), so a third-party server's
   own traceback (e.g. on shutdown, or a tool error) lands in the same
   captured log. Properly separating the two streams needs a
   ``src/mylonite`` change (passing ``errlog=`` through to ``stdio_client``)
   that this harness does not make; filtering by stack frame here is the
   workaround that needs none. A target-only traceback is recorded
   (``target_noise_traceback: true`` in the output) but never blocks the
   cell. The PRODUCT_DEFECT classification also covers: a
   missing/partial report with no positively-evidenced infrastructure
   signature in the log; a scan whose attempts include one that is neither
   ``finding`` nor ``no_finding`` and carries NO reason code anywhere
   (report or log), alongside zero findings; and an aborted or
   never-exercised scan with no reason code anywhere. Per the prereg,
   PRODUCT_DEFECT is NEVER counted toward the N=3 bar and is NEVER
   auto-re-run -- it is logged as a product issue instead.
2. ``INVALID`` -- the run directory is missing or unreadable AND the
   captured log carries a positively-evidenced infrastructure signature (an
   anchored provider/network exception class name, or a specific,
   unambiguous line such as a DNS-resolution failure or a GitHub Actions
   runner shutdown notice -- never a bare word like "timeout" or a bare
   number like "503", both of which can appear in ordinary, non-error log
   text, e.g. a token count). This is the ONLY classification a re-run is
   allowed for.
3. ``KEPT`` -- a ``validation_report.json`` exists and
   ``mylonite._verdict.verdict_label(report) == "KEPT"``. Reading the label,
   not the bare ``ValidationReport.kept`` boolean, matters: ``kept=True``
   also covers a ``STABLE, NOT PROVEN`` report (e.g. a judge-only keep, or
   one missing the build/differential-or-effect legs), which under
   never-keep-unproven counts as **not kept** for this campaign.
4. ``NOT_KEPT`` -- a ``validation_report.json`` exists and the label is
   ``REJECTED`` or ``STABLE, NOT PROVEN``, or the scan was cleanly exercised
   (a judged ``no_finding``, with every other attempt explained) and found
   nothing.
5. ``FOUND_UNVALIDATED`` -- ``scan_report.json`` recorded a finding but no
   ``validation_report.json`` sits beside it (and no traceback was found --
   see #1). Under never-keep-unproven this is a candidate, never a verdict
   -- deliberately NOT folded into KEPT.
6. ``NOT_TESTED`` -- no attempt reached a verdict at all (every attempt
   skipped, not-applicable, or undecided) or the scan aborted, AND a reason
   code for it was found somewhere -- in an attempt's own text fields, or
   printed to the captured log (the abort-reason codes, e.g.
   ``MYL-ABT-001``, are stamped into the console line, not into
   ``scan_report.json`` itself). NOT_TESTED REQUIRES a reason code; the
   identical situation with none found is PRODUCT_DEFECT (#1), never a
   silent, code-free NOT_TESTED.

Which stage's log a reason code comes from
------------------------------------------
``scan`` and ``validate`` are two processes with their own captured logs
(``scan.log`` and ``validate.log``; ``run.log`` holds both, and is kept for
the traceback check and the cost step). A reason code only counts for the
stage that printed it. Without this, a run whose ``validate`` stopped would
carry every code its ``scan`` printed, and two re-drives whose scans
skipped different seeds would disagree on the N=3 bar for a reason that
has nothing to do with the result being scored.

When ``validate`` ran (``validate.log`` exists) but wrote no
``validation_report.json`` -- it raises on an abort, such as its hard LLM
request ceiling, and exits 3 -- the result is decided by ``validate.log``
alone, never by the trimmed ``{model, provider}`` ``scan_report.json`` that
``generate`` leaves in the same directory. An abort code (``MYL-ABT-*``;
``MYL-ABT-001`` for the ceiling) makes it NOT_TESTED keyed on exactly those
abort codes. Otherwise it is INVALID with an infrastructure signature, or
PRODUCT_DEFECT.

Usage
-----

::

    # one run (the directory `validate` wrote validation_report.json into)
    python scripts/score_third_party.py score out/generated/<slug>/ \\
        --target tpv-server-memory --run-log run.log \\
        --scan-log scan.log --validate-log validate.log --out score-run1.json

    # combine N re-drives of the same cell (targets 1-3: N=3, bar 2/3)
    python scripts/score_third_party.py rollup \\
        score-run1.json score-run2.json score-run3.json \\
        --bar-numerator 2 --bar-denominator 3 --out rollup.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from verification._scan_dir import ScanDirIntegrityError, load_scan_dir  # noqa: E402

PRODUCT_DEFECT = "PRODUCT_DEFECT"
INVALID = "INVALID"
KEPT = "KEPT"
NOT_KEPT = "NOT_KEPT"
FOUND_UNVALIDATED = "FOUND_UNVALIDATED"
NOT_TESTED = "NOT_TESTED"

_REASON_CODE_RE = re.compile(r"MYL-[A-Z]+-\d+")
_ABORT_CODE_RE = re.compile(r"MYL-ABT-\d+")

#: Outcomes a "real" judged attempt can have. Everything else (skip/error/
#: undecided/not_applicable variants) needs a reason code to count as
#: explained.
_JUDGED_OUTCOMES = frozenset({"finding", "no_finding"})

#: A raw Python traceback with a mylonite stack frame anywhere in the log
#: overrides every other classification -- see the module docstring's
#: point #1. A traceback block runs from this header through every
#: subsequent INDENTED line (the ``File "..."``/code-context pairs) up to
#: and including the one final un-indented exception-type line.
_TRACEBACK_MARKER = "Traceback (most recent call last):"
_TRACEBACK_BLOCK_RE = re.compile(re.escape(_TRACEBACK_MARKER) + r"\n(?:[ \t].*\n)*\S.*")

#: Matched against each traceback BLOCK's own text (not the whole log) to
#: tell "Mylonite's own code did not anticipate this" apart from "the
#: target server crashed, and the stdio adapter does not separate its
#: stderr from ours" -- see the module docstring's point #1. Anchored to an
#: actual `File "...mylonite/....py"` STACK FRAME line -- "mylonite" as a
#: path segment (between path separators), in a quoted `File "..."`
#: reference, ending in `.py` -- never a bare substring match. A bare
#: substring match on the whole block would also fire on a target's own
#: planted/echoed content that happens to contain the word "mylonite" (e.g.
#: `redis.yaml`'s seed key literal `mylonite-tpv-seed`, which a target
#: server's own error message could echo back verbatim); this pattern
#: cannot match that, since it requires both the quoted `File "..."` frame
#: shape and a `.py` suffix. Mylonite's own installed location always
#: contains this path segment, whether run from a wheel's site-packages or
#: an editable checkout, on both POSIX (`/`) and Windows (`\`).
_MYLONITE_FRAME_RE = re.compile(r'File "[^"]*[/\\]mylonite[/\\][^"]*\.py"')


def _mylonite_traceback_present(log_text: str) -> bool:
    """True when at least one traceback block carries a ``mylonite`` stack
    frame -- as opposed to one raised entirely inside a spawned third-party
    server, whose own stderr the stdio adapter does not currently separate
    from Mylonite's own captured output."""
    return any(
        _MYLONITE_FRAME_RE.search(match.group(0))
        for match in _TRACEBACK_BLOCK_RE.finditer(log_text)
    )


#: Anchored provider/network exception CLASS NAMES (LiteLLM's own typed
#: hierarchy, or the httpx/socket exceptions it wraps) -- matched as whole
#: words, never a bare status-code or generic-word substring. "503" matches
#: a token count like "1,503"; "timeout" matches ordinary config text
#: (`--iteration-timeout`); these class names do not.
_INFRA_CLASS_RE = re.compile(
    r"\b("
    r"RateLimitError|APIConnectionError|ServiceUnavailableError|InternalServerError|"
    r"APITimeoutError|ConnectTimeout|ReadTimeout|ConnectError|RemoteProtocolError|"
    r"ConnectionResetError|ConnectionRefusedError|gaierror"
    r")\b"
)

#: Specific, unambiguous LINES (not bare words) that only ever appear for a
#: genuine infrastructure failure.
_INFRA_LINE_SIGNATURES: tuple[str, ...] = (
    "temporary failure in name resolution",
    "name or service not known",
    "the runner has received a shutdown signal",
)


def _infra_signature_in(log_text: str) -> str | None:
    match = _INFRA_CLASS_RE.search(log_text)
    if match:
        return match.group(1)
    lowered = log_text.lower()
    for line in _INFRA_LINE_SIGNATURES:
        if line in lowered:
            return line
    return None


def _reason_codes_in_attempts(raw_report: dict) -> list[str]:
    """Every ``MYL-...`` reason code mentioned in the attempts list's own
    text fields."""
    codes: list[str] = []
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict):
            continue
        for field in ("verdict_reason", "not_applicable_reason", "error_detail"):
            text = attempt.get(field)
            if isinstance(text, str):
                codes.extend(_REASON_CODE_RE.findall(text))
    return codes


def _dedupe(codes: list[str]) -> list[str]:
    """Sorted, de-duplicated -- two runs that each saw the SAME code twice
    must still agree with a run that saw it once."""
    return sorted(set(codes))


#: Lazily built, then cached -- {pattern_id: weakness} for every bundled
#: catalogue seed (``mylonite.scan.seeds.SEED_CATALOGUE``), the exact table
#: ``mylonite.gate.mitigation._PATTERN_TO_WEAKNESS`` already builds for a kept
#: exploit. Built here too (rather than imported) because that one is private
#: and keyed for ``ExploitRecord`` objects, not the bare ``pattern_id`` strings
#: a raw ``scan_report.json`` attempt carries.
_PATTERN_TO_WEAKNESS: dict[str, str] | None = None

#: A descriptor-synthesised seed's pattern_id always starts ``synth-w<N>-``
#: (see ``seed_synth.py``'s ``_w1_seed``/``_w1_rugpull_seed`` and friends) --
#: the catalogue lookup above only covers the bundled kitchen-sink seeds, so a
#: synthesised one is read from its own id instead of a table.
_SYNTH_PATTERN_RE = re.compile(r"^synth-(w[1-4])-", re.IGNORECASE)


def _pattern_to_weakness() -> dict[str, str]:
    global _PATTERN_TO_WEAKNESS
    if _PATTERN_TO_WEAKNESS is None:
        from mylonite.scan.seeds import SEED_CATALOGUE

        _PATTERN_TO_WEAKNESS = {s.pattern_id: s.weakness for s in SEED_CATALOGUE}
    return _PATTERN_TO_WEAKNESS


def _weakness_for_pattern(pattern_id: str) -> str | None:
    """The W1-W4 class a scan attempt's own ``pattern_id`` belongs to, or
    ``None`` when neither the bundled catalogue nor the synthesised-id shape
    recognises it (an adaptively-named custom-target pattern_id)."""
    mapping = _pattern_to_weakness()
    if pattern_id in mapping:
        return mapping[pattern_id]
    match = _SYNTH_PATTERN_RE.match(pattern_id)
    if match:
        return match.group(1).upper()
    return None


def _calibration_info(raw_report: dict) -> dict[str, object]:
    """``{"calibration_status": ..., "calibration_reason_code": ...}``, read
    from ``scan_report.json``'s own ``calibration`` block
    (``mylonite.plugins._mcp.calibration.CalibrationResult.to_dict()``,
    written only for a custom target that declares an ``effect_probe``).
    Both are ``None`` when the target has no probe to calibrate (a bundled
    reference target, or a precision cell with no ``seed_arm``/
    ``effect_probe`` at all) or the report predates this field."""
    calibration = raw_report.get("calibration") if isinstance(raw_report, dict) else None
    if not isinstance(calibration, dict):
        return {"calibration_status": None, "calibration_reason_code": None}
    return {
        "calibration_status": calibration.get("status"),
        "calibration_reason_code": calibration.get("reason_code"),
    }


def _finding_proof_level(raw_report: dict) -> str | None:
    """The ``proof_level`` (``judge_evidence["proof_level"]``) of the FIRST
    ``outcome=finding`` attempt -- the only one ``generate``/``validate`` ever
    act on, per the prereg's multi-finding note. ``None`` when nothing fired,
    or the attempt carries no such key (an older report)."""
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if isinstance(attempt, dict) and attempt.get("outcome") == "finding":
            evidence = attempt.get("judge_evidence")
            if isinstance(evidence, dict) and evidence.get("proof_level"):
                return str(evidence["proof_level"])
            return None
    return None


def _weakness_counts(raw_report: dict, weakness: str) -> dict[str, int]:
    """Fired (``outcome=finding``) and resisted (``outcome=no_finding``)
    attempt counts for one weakness class, read from the attempts list.
    ``kept`` always starts at 0 -- the caller fills it in once the run's
    verdict label is known, since only the first finding is ever validated
    (the multi-finding note), so "kept" is a cell-level fact, not something
    countable from the attempts list alone."""
    fired = 0
    resisted = 0
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict):
            continue
        if _weakness_for_pattern(str(attempt.get("pattern_id", ""))) != weakness:
            continue
        if attempt.get("outcome") == "finding":
            fired += 1
        elif attempt.get("outcome") == "no_finding":
            resisted += 1
    return {"fired": fired, "resisted": resisted, "kept": 0}


def _unexplained_attempts(raw_report: dict) -> list[dict]:
    """Attempts that are neither a judged ``finding``/``no_finding`` NOR
    carry a reason code anywhere in their own text fields -- an outcome with
    no story, which must never be silently folded into a clean result."""
    unexplained = []
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict):
            continue
        if attempt.get("outcome") in _JUDGED_OUTCOMES:
            continue
        texts = [
            attempt.get(field)
            for field in ("verdict_reason", "not_applicable_reason", "error_detail")
        ]
        if not any(isinstance(t, str) and _REASON_CODE_RE.search(t) for t in texts):
            unexplained.append(attempt)
    return unexplained


def _classify_missing_report(run_dir: Path, log_text: str) -> dict[str, object]:
    """Decide PRODUCT_DEFECT vs INVALID when no report exists at all.

    Called only after the caller has already ruled out a traceback in
    ``log_text`` (see :func:`score_run`). Defaults to PRODUCT_DEFECT -- an
    infra failure must be POSITIVELY evidenced, never assumed, since
    PRODUCT_DEFECT is the only classification that keeps a real crash from
    being quietly re-run away.
    """
    signature = _infra_signature_in(log_text)
    if signature is not None:
        return {
            "classification": INVALID,
            "reason": f"{run_dir}: no report found; infra signature in run.log: {signature!r}",
        }
    return {
        "classification": PRODUCT_DEFECT,
        "reason": (
            f"{run_dir}: no scan_report.json or validation_report.json found, and no "
            "recognised infrastructure signature in run.log"
        ),
    }


def _read_log(path: Path | None) -> str | None:
    """The log's text, or None when no path was given or the file does not
    exist (the stage never ran)."""
    if path is None or not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _classify_validate_without_report(run_dir: Path, validate_text: str) -> dict[str, object]:
    """``validate`` ran but wrote no ``validation_report.json``.

    Decided by ``validate.log`` alone -- see the module docstring's "Which
    stage's log a reason code comes from". An abort code keys NOT_TESTED on
    exactly the abort codes ``validate`` printed, so N re-drives that all
    tripped the same ceiling agree whatever their scans printed.
    """
    abort_codes = _dedupe(_ABORT_CODE_RE.findall(validate_text))
    if abort_codes:
        return {
            "classification": NOT_TESTED,
            "stage": "validate",
            "reason": (
                "validate stopped early (MYL-ABT-001 is its LLM request ceiling) and "
                "wrote no validation_report.json"
            ),
            "reason_codes": abort_codes,
        }
    signature = _infra_signature_in(validate_text)
    if signature is not None:
        return {
            "classification": INVALID,
            "stage": "validate",
            "reason": (
                f"{run_dir}: validate wrote no validation_report.json; infra signature in "
                f"validate.log: {signature!r}"
            ),
        }
    return {
        "classification": PRODUCT_DEFECT,
        "stage": "validate",
        "reason": (
            f"{run_dir}: validate ran but wrote no validation_report.json, with no abort "
            "code and no recognised infrastructure signature in validate.log"
        ),
    }


def _read_raw_report_safe(run_dir: Path) -> dict:
    """``scan_report.json``'s own dict, or ``{}`` when it is missing or
    unreadable -- never raises. Used only to fill in ``calibration_status``/
    ``calibration_reason_code``/``proof_level`` as an explicit ``None`` on a
    path that never reads the report for its own classification (a missing
    report, an aborted scan with no reason code, a traceback). Those paths'
    own dict already carries a ``reason``/``reason_codes`` field explaining
    WHY there is nothing to calibrate or confirm; this never duplicates that
    text, it only guarantees the three keys are always present."""
    report_path = run_dir / "scan_report.json"
    if not report_path.is_file():
        return {}
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def score_run(
    run_dir: Path,
    *,
    run_log: Path | None = None,
    scan_log: Path | None = None,
    validate_log: Path | None = None,
    pattern: str | None = None,
) -> dict[str, object]:
    """Classify one run directory per the prereg's pass rule.

    ``run_log`` is the whole captured output, used for the traceback check
    and, when no ``scan_log`` is given, for scan-stage reason codes.
    ``scan_log`` and ``validate_log`` are each stage's own output; a
    ``validate_log`` path whose file does not exist means validate never ran.
    ``pattern`` is the cell's own ``--weakness-class``/``pattern`` dispatch
    value (``W1``-``W4``, or ``None``/blank for the first campaign's
    unfiltered cells, which default to ``W1`` -- see
    :func:`_weakness_counts`'s caller below).
    """
    scan_text = _read_log(scan_log)
    validate_text = _read_log(validate_log)
    log_text = _read_log(run_log)
    if log_text is None:
        log_text = "\n".join(t for t in (scan_text, validate_text) if t is not None)

    # Rule #1, checked before anything else: a traceback with a mylonite
    # stack frame anywhere is a product defect, full stop -- see the module
    # docstring. A traceback with NO mylonite frame (the target server's own
    # crash, inseparable from our log without a src/ change) is recorded,
    # not blocked -- it falls through to ordinary classification below.
    has_traceback = _TRACEBACK_MARKER in log_text
    target_noise_traceback = False
    if has_traceback and _mylonite_traceback_present(log_text):
        result: dict[str, object] = {
            "classification": PRODUCT_DEFECT,
            "reason": (
                "a Python traceback with a mylonite stack frame is present in "
                "run.log -- investigate as a product crash, never auto-re-run"
            ),
        }
    else:
        if has_traceback:
            target_noise_traceback = True
        if validate_text is not None and not (run_dir / "validation_report.json").is_file():
            result = _classify_validate_without_report(run_dir, validate_text)
        else:
            # Reason codes come from the stage whose result is being scored:
            # validate's log when it wrote the report, otherwise scan's.
            if validate_text is not None:
                codes_text = validate_text
            elif scan_text is not None:
                codes_text = scan_text
            else:
                codes_text = log_text
            result = _score_run_normally(run_dir, log_text, codes_text, pattern=pattern)
    if target_noise_traceback:
        result["target_noise_traceback"] = True
    result["exercised"] = _run_exercised(run_dir, result)

    # Integrity rule 7 (the prereg): calibration status and proof level
    # travel with EVERY scored run, not only KEPT/NOT_KEPT/FOUND_UNVALIDATED
    # -- a NOT_TESTED/PRODUCT_DEFECT/INVALID run gets both as an explicit
    # ``None`` (present, not omitted) rather than leaving a downstream
    # reader to ``dict.get()`` defensively. ``setdefault`` is a no-op for
    # every branch above that already computed a real value.
    raw_report_for_defaults = _read_raw_report_safe(run_dir)
    defaults = _calibration_info(raw_report_for_defaults)
    result.setdefault("calibration_status", defaults["calibration_status"])
    result.setdefault("calibration_reason_code", defaults["calibration_reason_code"])
    result.setdefault("proof_level", _finding_proof_level(raw_report_for_defaults))
    return result


def _run_exercised(run_dir: Path, result: dict[str, object]) -> bool:
    """Whether at least one attempt in this run reached a real verdict
    (``finding``/``no_finding``) -- the integrity rule's "a cell counts only
    if attacks were actually exercised" (used by :func:`precision_rollup`).

    Prefers re-reading ``scan_report.json`` directly (the same
    ``ScanDirResult.exercised`` every other classification already trusts).
    When no ``scan_report.json`` sits in this directory but ``validate`` ran
    anyway -- the "scan stopped at its ceiling but still recorded a finding"
    path, scored from ``validate``'s own log -- the prereg says that always
    follows a real recorded finding, so it counts as exercised even though
    the finding itself lives in a directory this function was not pointed
    at. Anything else defaults to whether the classification itself required
    a judged outcome.
    """
    report_path = run_dir / "scan_report.json"
    if report_path.is_file():
        try:
            return load_scan_dir(run_dir).exercised
        except ScanDirIntegrityError:
            return False
    if result.get("stage") == "validate":
        return True
    return result.get("classification") in (KEPT, NOT_KEPT, FOUND_UNVALIDATED)


def _score_run_normally(
    run_dir: Path, log_text: str, codes_text: str, *, pattern: str | None = None
) -> dict[str, object]:
    """Every classification branch except rule #1 (the traceback check,
    handled by the caller, :func:`score_run`, before this is reached).
    ``log_text`` is the whole log, searched for infra signatures;
    ``codes_text`` is the scored stage's own log, the only place reason
    codes are read from. ``pattern`` is the cell's own weakness-class
    filter (``W1``-``W4``); blank/``None`` defaults to ``W1`` (the first
    campaign's cells, all unfiltered, only ever cared about W1's counts)."""
    report_path = run_dir / "scan_report.json"
    validation_path = run_dir / "validation_report.json"
    weakness_key = (pattern or "W1").upper()

    if not report_path.is_file() and not validation_path.is_file():
        return _classify_missing_report(run_dir, log_text)

    scan_result = None
    if report_path.is_file():
        try:
            scan_result = load_scan_dir(run_dir)
        except ScanDirIntegrityError as exc:
            # A partial copy (a finding with no exploit file) is untrustworthy
            # in the same way a missing report is -- no traceback was found
            # above, so this is a product/harness defect, not an infra one.
            return {"classification": PRODUCT_DEFECT, "reason": str(exc)}

    raw_report: dict = {}
    if report_path.is_file():
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    log_reason_codes = _REASON_CODE_RE.findall(codes_text)
    reason_codes = _dedupe(_reason_codes_in_attempts(raw_report) + log_reason_codes)
    weakness_classes = sorted(scan_result.weakness_classes) if scan_result is not None else []
    calibration_info = _calibration_info(raw_report)
    proof_level = _finding_proof_level(raw_report)
    pattern_counts = _weakness_counts(raw_report, weakness_key)
    pattern_key = weakness_key.lower()

    if validation_path.is_file():
        from mylonite._verdict import verdict_label
        from mylonite.contracts import ValidationReport

        report = ValidationReport.model_validate_json(validation_path.read_text(encoding="utf-8"))
        label = verdict_label(report)
        if label == "KEPT":
            if weakness_key in weakness_classes:
                pattern_counts["kept"] = 1
            return {
                "classification": KEPT,
                "label": label,
                "weakness_classes": weakness_classes,
                "reason_codes": reason_codes,
                "proof_level": proof_level,
                pattern_key: pattern_counts,
                "adjudication": {"status": "unadjudicated", "reason": None},
                **calibration_info,
            }
        failing = next(
            (o for o in report.outcomes if not o.passed and not o.report_only),
            None,
        )
        detail = (failing.detail if failing else None) or report.notes or f"verdict: {label}"
        return {
            "classification": NOT_KEPT,
            "label": label,
            "detail": detail,
            "weakness_classes": weakness_classes,
            "reason_codes": reason_codes,
            "proof_level": proof_level,
            pattern_key: pattern_counts,
            **calibration_info,
        }

    aborted = raw_report.get("aborted")
    if aborted:
        # The abort's own MYL-ABT-* reason code is stamped into the printed
        # console line (reason_codes.tag), NOT into scan_report.json itself
        # -- so it can only be found in log_reason_codes, not the attempts
        # list. NOT_TESTED requires one; its absence is a product defect.
        if reason_codes:
            return {
                "classification": NOT_TESTED,
                "reason": f"scan aborted: {aborted}",
                "reason_codes": reason_codes,
            }
        return {
            "classification": PRODUCT_DEFECT,
            "reason": (
                f"scan aborted ({aborted}) but no reason code found in scan_report.json or run.log"
            ),
        }

    findings_count = raw_report.get("findings_count", 0) or 0
    unexplained = _unexplained_attempts(raw_report)

    if findings_count == 0 and unexplained:
        return {
            "classification": PRODUCT_DEFECT,
            "reason": (
                f"{len(unexplained)} attempt(s) are neither judged (finding/no_finding) "
                "nor carry a reason code, alongside zero findings -- an unexplained gap "
                "the prereg treats as a product issue, not a clean result"
            ),
            "reason_codes": reason_codes,
        }

    if findings_count > 0:
        return {
            "classification": FOUND_UNVALIDATED,
            "weakness_classes": weakness_classes,
            "reason_codes": reason_codes,
            "proof_level": proof_level,
            pattern_key: pattern_counts,
            **calibration_info,
        }

    if scan_result is not None and not scan_result.exercised:
        if reason_codes:
            return {
                "classification": NOT_TESTED,
                "reason": "no attempt reached a verdict (all skipped/not_applicable/undecided)",
                "reason_codes": reason_codes,
            }
        return {
            "classification": PRODUCT_DEFECT,
            "reason": (
                "no attempt reached a verdict, and no reason code found in scan_report.json "
                "or run.log"
            ),
        }

    return {
        "classification": NOT_KEPT,
        "detail": "exercised, 0 findings, no unexplained attempts (a clean resist)",
        "weakness_classes": weakness_classes,
        "reason_codes": reason_codes,
        "proof_level": proof_level,
        pattern_key: pattern_counts,
        **calibration_info,
    }


def _rollup_key(score: dict[str, object]) -> tuple[object, ...]:
    """The value two runs must share to "agree", per the prereg: the bare
    classification for everything except NOT_TESTED, which also needs the
    SAME reason code(s), de-duplicated -- two NOT_TESTED runs for different
    reasons do not agree with each other, and a repeated code in one run's
    list must not make it disagree with another run that saw it once."""
    classification = score.get("classification")
    if classification == NOT_TESTED:
        return (classification, tuple(_dedupe(score.get("reason_codes", []) or [])))
    return (classification,)


def rollup(
    scores: list[dict[str, object]], *, bar_numerator: int, bar_denominator: int
) -> dict[str, object]:
    """Apply the fixed-N, >=bar-numerator/bar-denominator rule across re-drives."""
    keys = [_rollup_key(s) for s in scores]
    counts = Counter(keys)
    winner_key, n = counts.most_common(1)[0] if counts else (None, 0)
    met_bar = len(scores) == bar_denominator and n >= bar_numerator and winner_key is not None
    winner_classification = winner_key[0] if winner_key is not None else None
    return {
        "n": len(scores),
        "counts": {str(k): v for k, v in counts.items()},
        "result": winner_classification if met_bar else "NO_CONSENSUS",
        "reason_codes": list(winner_key[1]) if met_bar and len(winner_key) > 1 else [],
        "bar": f"{bar_numerator}/{bar_denominator}",
        "met_bar": met_bar,
    }


def precision_rollup(scores: list[dict[str, object]]) -> dict[str, object]:
    """Combine N re-drives of a precision cell: a cell passes only on
    0 KEPT across every run, and only when every run was itself exercised.

    Per the integrity rules, "0 kept" is a vacuous, un-countable pass unless
    attacks were actually dispatched: a run where every attempt read
    NOT_TESTED proves nothing about the target's precision, so a single
    unexercised run makes the WHOLE cell ``INCONCLUSIVE``, not a clean
    ``PASS`` -- a cell is only as trustworthy as its least-exercised run.
    ``FAIL`` means at least one run was classified ``KEPT`` (a false
    positive to triage) and every run was exercised.
    """
    n = len(scores)
    if n == 0:
        # An empty input is never a clean pass -- a glob that matched nothing,
        # or a bug upstream, must not silently read as "0 kept, all exercised".
        # Every real call site today either requires >=1 score file (the CLI's
        # `nargs="+"`) or raises before reaching here on a missing/empty file,
        # but the bare function gets its own explicit guard rather than
        # relying on that.
        return {"n": 0, "kept_count": 0, "unexercised_runs": 0, "result": "INCONCLUSIVE"}
    kept_runs = [s for s in scores if s.get("classification") == KEPT]
    unexercised_runs = sum(1 for s in scores if not s.get("exercised"))
    if unexercised_runs > 0:
        result = "INCONCLUSIVE"
    elif kept_runs:
        result = "FAIL"
    else:
        result = "PASS"
    return {
        "n": n,
        "kept_count": len(kept_runs),
        "unexercised_runs": unexercised_runs,
        "result": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    score_p = sub.add_parser("score", help="Classify one run directory.")
    score_p.add_argument("run_dir", type=Path)
    score_p.add_argument(
        "--target", required=True, help="Target family name, recorded in the output."
    )
    score_p.add_argument(
        "--run-log",
        type=Path,
        default=None,
        help="Captured stdout log for this run -- required to distinguish a traceback-"
        "driven product defect or an infra failure from a clean result.",
    )
    score_p.add_argument(
        "--scan-log",
        type=Path,
        default=None,
        help="scan's own captured output; scan-stage reason codes are read from it.",
    )
    score_p.add_argument(
        "--validate-log",
        type=Path,
        default=None,
        help="validate's own captured output; a missing file means validate never ran.",
    )
    score_p.add_argument(
        "--pattern",
        default=None,
        help="The cell's own --weakness-class/pattern value (W1-W4). Controls which "
        "class's fired/resisted/kept counts are reported, and under which key "
        "('w2' for W2, etc.) -- blank/omitted defaults to W1.",
    )
    score_p.add_argument("--out", type=Path, required=True)

    rollup_p = sub.add_parser(
        "rollup", help="Combine N per-run score.json files into one cell verdict."
    )
    rollup_p.add_argument("score_files", nargs="+", type=Path)
    rollup_p.add_argument("--bar-numerator", type=int, default=2)
    rollup_p.add_argument("--bar-denominator", type=int, default=3)
    rollup_p.add_argument("--out", type=Path, required=True)

    precision_p = sub.add_parser(
        "precision-rollup",
        help="Combine N re-drives of a precision cell (0 KEPT, every run exercised).",
    )
    precision_p.add_argument("score_files", nargs="+", type=Path)
    precision_p.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)

    if args.command == "score":
        result = score_run(
            args.run_dir,
            run_log=args.run_log,
            scan_log=args.scan_log,
            validate_log=args.validate_log,
            pattern=args.pattern,
        )
        result["target"] = args.target
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "rollup":
        scores = [json.loads(f.read_text(encoding="utf-8")) for f in args.score_files]
        result = rollup(
            scores,
            bar_numerator=args.bar_numerator,
            bar_denominator=args.bar_denominator,
        )
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "precision-rollup":
        scores = [json.loads(f.read_text(encoding="utf-8")) for f in args.score_files]
        result = precision_rollup(scores)
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
