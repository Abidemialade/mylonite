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
2. ``INFRA`` -- Mylonite's own commands never ran at all: ``--run-log`` names
   a file that does not exist, and neither ``--scan-log`` nor
   ``--validate-log`` has any content either. In the campaign workflow,
   ``run.log``/``scan.log``/``validate.log`` are written only by the "Run
   the real journey" step's own ``tee``; their total absence means an
   EARLIER step -- the scaffold sanity check, a target install, a server
   launch -- failed first and stopped the job before ``scan``, ``generate``
   or ``validate`` was ever invoked. That is a target/harness pre-flight
   failure, not a Mylonite defect, and reads ``INFRA`` instead of falling
   through to the ``PRODUCT_DEFECT`` default in #1. Like ``PRODUCT_DEFECT``
   and ``INVALID``, ``INFRA`` never counts toward a pass and is never
   exercised (:func:`_run_exercised`), so it cannot contribute to a
   precision cell's vacuous-pass guard either.
3. ``INVALID`` -- the run directory is missing or unreadable AND the
   captured log carries a positively-evidenced infrastructure signature (an
   anchored provider/network exception class name, or a specific,
   unambiguous line such as a DNS-resolution failure or a GitHub Actions
   runner shutdown notice -- never a bare word like "timeout" or a bare
   number like "503", both of which can appear in ordinary, non-error log
   text, e.g. a token count). This is the ONLY classification a re-run is
   allowed for.
4. ``KEPT`` -- a ``validation_report.json`` exists and
   ``mylonite._verdict.verdict_label(report) == "KEPT"``. Reading the label,
   not the bare ``ValidationReport.kept`` boolean, matters: ``kept=True``
   also covers a ``STABLE, NOT PROVEN`` report (e.g. a judge-only keep, or
   one missing the build/differential-or-effect legs), which under
   never-keep-unproven counts as **not kept** for this campaign.
5. ``NOT_KEPT`` -- a ``validation_report.json`` exists and the label is
   ``REJECTED`` or ``STABLE, NOT PROVEN``, or the scan was cleanly exercised
   (a judged ``no_finding``, with every other attempt explained) and found
   nothing.
6. ``FOUND_UNVALIDATED`` -- ``scan_report.json`` recorded a finding but no
   ``validation_report.json`` sits beside it (and no traceback was found --
   see #1). Under never-keep-unproven this is a candidate, never a verdict
   -- deliberately NOT folded into KEPT.
7. ``NOT_TESTED`` -- no attempt reached a verdict at all (every attempt
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

``scan_findings`` and ``max_scan_proof_level``
-----------------------------------------------
"Run the real journey" passes ``generate``/``validate`` exactly ONE exploit
file -- the alphabetically-first ``outcome=="finding"`` ``pattern_id``, a
documented scope limit, never "the one with the strongest proof". A real
scan can therefore record several findings while only one of them is ever
validated, and a finding that reached a HIGHER proof level (or a confirmed
removal) can go unreported if nothing says otherwise -- confirmed live
against a real campaign run (2026-10-04, ``tpv-server-memory``, openai,
small tier): ``create_relations`` sorted before ``delete_entities`` and was
the one validated and KEPT, even though the SAME scan's ``delete_entities``
attempt reached ``effect-confirmed`` with ``removal_confirmed: true`` and
was never validated at all.

Every scored run (whatever its own classification) therefore also carries
``scan_findings`` -- one entry per ``outcome=="finding"`` attempt in the
REAL scan report, each with its own ``pattern_id``, ``weakness`` class,
``proof_level``, ``removal_confirmed`` (omitted when the attempt's own
``judge_evidence`` never carries that key) and ``validated`` (``True`` only
for the one finding ``generate``/``validate`` actually processed) -- and
``max_scan_proof_level``, the strongest ``proof_level`` among all of them
(``None`` when none carries one). Only the entry with ``validated: true``
may ever be described as kept; every other entry is found, not validated.

Two proof-level axes, and which one a proof-depth bar reads
-------------------------------------------------------------
A scan ATTEMPT's own ``judge_evidence.proof_level`` (``scan_findings[*]
.proof_level``, ``max_scan_proof_level``, and this run's own top-level
``proof_level`` -- unchanged, the single-report path's existing meaning)
is one strongest level read during the SCAN. ``validate``'s own "effect"
gating leg re-runs the attack against the real target and reads it back
again, under whatever calibration held at validate time, and can read a
DIFFERENT level -- confirmed live (2026-10-05, ``tpv-server-memory``,
openai, small tier): the scan attempt for ``delete_entities`` read
``effect-confirmed``, while that same finding's own ``validate`` effect
leg read only ``dispatched-tool-linked`` (``validation_report.json``'s
"effect" outcome detail: "0 effect-confirmed ... 3 dispatched-tool-linked").
:func:`_validated_effect_proof_level` parses that detail text directly
from a ``validation_report.json``; it is the ONE place either axis is
read, shared by the single-report path (``build_e2e_results.py``'s own
``_score_one``, for a classic ``generated/`` directory) and the
multi-report path (:func:`_score_multi_report_run`, once per per-finding
subdirectory) -- never duplicated.

For a multi-report run, each ``validated_findings`` entry therefore carries
BOTH axes under their own names -- ``scan_proof_level`` (the scan attempt's
own level, what the old, now-renamed ``proof_level`` key used to hold here)
and ``validated_effect_proof_level``/``validated_effect_counts`` (validate's
own effect leg for that exact finding) -- and this run's own top-level
``validated_effect_proof_level``/``validated_effect_counts`` come from the
STRONGEST KEPT finding's own validated effect level, never from the scan
axis. A reader asking "did this bar actually prove the confirm-path depth
claim" must read ``validated_effect_proof_level``, never the top-level
``proof_level`` -- that field keeps meaning only "the strongest level a
scan ATTEMPT reached," which a KEPT finding's own validate re-drive can
read weaker (or stronger) than.

Usage
-----

::

    # one run (the directory `validate` wrote validation_report.json into).
    # --scan-dir points at the REAL scan output directory when it differs
    # from the run_dir above (a validated FULL_JOURNEY run's own
    # scan_report.json is only `generate`'s trimmed {model, provider} copy)
    # -- see `_resolve_scan_dir`'s docstring.
    python scripts/score_third_party.py score generated/ \\
        --target tpv-server-memory --scan-dir "out/2026-10-04T21-08-01Z" \\
        --run-log run.log --scan-log scan.log --validate-log validate.log \\
        --out score-run1.json

    # combine N re-drives of the same cell (targets 1-3: N=3, bar 2/3)
    python scripts/score_third_party.py rollup \\
        score-run1.json score-run2.json score-run3.json \\
        --bar-numerator 2 --bar-denominator 3 --out rollup.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from verification._scan_dir import ScanDirIntegrityError, load_scan_dir  # noqa: E402

PRODUCT_DEFECT = "PRODUCT_DEFECT"
INFRA = "INFRA"
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


def _calibration_info(scan_dir: Path) -> dict[str, object]:
    """``{"calibration_status": ..., "calibration_reason_code": ...}``, read
    from ``scan_dir``'s own ``verdicts.json`` -- the artefact
    ``mylonite.scan.artefacts._verdicts_document`` actually writes the
    ``calibration`` block (``CalibrationResult.to_dict()``) into.

    An earlier version of this function read ``scan_report.json`` instead --
    confirmed against a real campaign run (both pilot dispatches of the
    `tpv-server-memory` breadth cell, 2026-10-04) to NEVER carry a
    top-level ``calibration`` key at all, so every live run read
    ``calibration_status: null`` even on a KEPT finding whose target
    declares an effect probe. ``mylonite.scan.artefacts.
    read_verdicts_calibration`` reads the identical file for the identical
    reason -- this mirrors it rather than importing it, so this script's
    pure aggregation logic keeps working without ``mylonite`` installed.
    Both fields are ``None`` when the target has no probe to calibrate (a
    bundled reference target, or a precision cell with no ``seed_arm``/
    ``effect_probe`` at all), ``scan_dir`` has no ``verdicts.json``, or the
    file predates this field."""
    path = scan_dir / "verdicts.json"
    if not path.is_file():
        return {"calibration_status": None, "calibration_reason_code": None}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"calibration_status": None, "calibration_reason_code": None}
    calibration = data.get("calibration") if isinstance(data, dict) else None
    if not isinstance(calibration, dict):
        return {"calibration_status": None, "calibration_reason_code": None}
    return {
        "calibration_status": calibration.get("status"),
        "calibration_reason_code": calibration.get("reason_code"),
    }


def _validated_pattern_id(run_dir: Path) -> str | None:
    """The ``pattern_id`` of the ONE exploit ``generate`` actually emitted a
    test from -- the ``exploit_*.json`` file co-located in ``run_dir``
    itself (never more than one there for a validated run: `generate`'s
    single-finding mode, invoked with one explicit exploit path -- see
    ``third-party-campaign.yml``'s own comment on why). ``None`` when
    ``run_dir`` holds none (a scan-only cell, or before ``generate`` ran) or
    the file can't be read, so every caller falls back to "the first finding
    in attempts order" instead."""
    matches = sorted(run_dir.glob("exploit_*.json"))
    if not matches:
        return None
    try:
        data = json.loads(matches[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    pattern_id = data.get("pattern_id") if isinstance(data, dict) else None
    return str(pattern_id) if pattern_id else None


def _finding_proof_level(raw_report: dict, validated_pattern_id: str | None = None) -> str | None:
    """The ``proof_level`` (``judge_evidence["proof_level"]``) of the
    attempt ``generate``/``validate`` actually acted on.

    With a scan report recording MULTIPLE findings (e.g. ``findings_count``
    2), "the first ``outcome=finding`` attempt in list order" is not
    necessarily the one that was validated -- a real campaign pilot run
    (2026-10-04) found a scan with a `delete_entities` finding listed BEFORE
    the `create_relations` finding `generate`/`validate` actually processed
    (the harness always passes the alphabetically-first `exploit_*.json`
    path, which need not be attempts-list order), so reading the list's
    first match read a weaker proof level than the one the KEPT verdict
    actually proves. ``validated_pattern_id`` (see
    :func:`_validated_pattern_id`) disambiguates this when given; omitted or
    not found among the attempts falls back to the old "first finding"
    behaviour, unchanged for every caller and offline fixture that predates
    this parameter."""
    attempts = raw_report.get("attempts", []) if isinstance(raw_report, dict) else []
    if validated_pattern_id is not None:
        for attempt in attempts:
            if (
                isinstance(attempt, dict)
                and attempt.get("outcome") == "finding"
                and attempt.get("pattern_id") == validated_pattern_id
            ):
                evidence = attempt.get("judge_evidence")
                if isinstance(evidence, dict) and evidence.get("proof_level"):
                    return str(evidence["proof_level"])
                return None
    for attempt in attempts:
        if isinstance(attempt, dict) and attempt.get("outcome") == "finding":
            evidence = attempt.get("judge_evidence")
            if isinstance(evidence, dict) and evidence.get("proof_level"):
                return str(evidence["proof_level"])
            return None
    return None


def _scan_findings(raw_report: dict, validated_pattern_id: str | None) -> list[dict[str, object]]:
    """One entry per FOUND (``outcome=="finding"``) attempt in the REAL scan
    report, in attempts order: its ``pattern_id``, the ``weakness`` class
    (see :func:`_weakness_for_pattern`), the attempt's own ``proof_level``,
    ``removal_confirmed`` (omitted entirely when the attempt's own
    ``judge_evidence`` never carries that key -- e.g. a target with no
    declared removal-confirmation probe at all), and ``validated`` -- True
    only for the ONE finding ``generate``/``validate`` actually processed
    (see :func:`_validated_pattern_id`), never inferred from proof level or
    list order. Every other entry is found, not validated -- it is never
    described as kept.

    This exists because a scan can record several findings while only the
    alphabetically-first ``exploit_*.json`` ever reaches ``generate``/
    ``validate`` (the harness's own documented scope limit -- see the module
    docstring and the real campaign run this was built from, batch 4's
    ``tpv-server-memory`` finding (a)): a stronger, removal-confirmed
    finding can sit in the SAME scan as the one that was actually validated
    and kept, and without this list that finding is invisible to anyone
    reading only the cell's score.

    A thin wrapper over :func:`_scan_findings_for` with a single candidate
    pattern id -- unchanged for every pre-existing caller -- now that the
    harness can validate every finding in one scan (see
    :func:`_scan_findings_for`'s own docstring)."""
    validated_ids = {validated_pattern_id} if validated_pattern_id else set()
    return _scan_findings_for(raw_report, validated_ids)


def _scan_findings_for(
    raw_report: dict, validated_pattern_ids: set[str]
) -> list[dict[str, object]]:
    """Same shape as :func:`_scan_findings`, but ``validated`` is True for
    every ``pattern_id`` in ``validated_pattern_ids`` -- plural, because the
    harness now generates+validates EVERY exploit a scan found (not only the
    alphabetically-first), so more than one finding in the same scan can be
    validated at once (see ``_score_multi_report_run``)."""
    findings: list[dict[str, object]] = []
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict) or attempt.get("outcome") != "finding":
            continue
        pattern_id = str(attempt.get("pattern_id", ""))
        evidence = attempt.get("judge_evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        entry: dict[str, object] = {
            "pattern_id": pattern_id,
            "weakness": _weakness_for_pattern(pattern_id),
            "proof_level": evidence.get("proof_level"),
            "validated": pattern_id in validated_pattern_ids,
        }
        if "removal_confirmed" in evidence:
            entry["removal_confirmed"] = evidence["removal_confirmed"]
        findings.append(entry)
    return findings


def _max_scan_proof_level(scan_findings: list[dict[str, object]]) -> str | None:
    """The strongest ``proof_level`` among every FOUND attempt in the real
    scan report, in ``mylonite.scan.class_verdict.PROOF_LEVEL_ORDER``'s own
    strongest-first order (lazily imported, so this script's pure
    aggregation keeps working without ``mylonite`` installed whenever no
    finding carries a proof level at all). ``None`` when ``scan_findings``
    is empty or no entry has one.

    This is the field batch 4's finding (a) needs: the VALIDATED finding's
    own ``proof_level`` (see :func:`_finding_proof_level`) can be weaker than
    another, unvalidated finding's in the same scan -- the alphabetical
    single-exploit pick, not proof strength, decides which one ``generate``/
    ``validate`` ever sees -- and this field says so plainly instead of
    leaving a reader to assume the validated finding was the strongest one
    the scan actually found."""
    levels = {f["proof_level"] for f in scan_findings if f.get("proof_level")}
    if not levels:
        return None
    from mylonite.scan.class_verdict import PROOF_LEVEL_ORDER

    for level in PROOF_LEVEL_ORDER:
        if level in levels:
            return level
    return sorted(levels)[0]


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


def _classify_missing_report(
    run_dir: Path, log_text: str, *, preflight_failure: bool = False
) -> dict[str, object]:
    """Decide INFRA vs PRODUCT_DEFECT vs INVALID when no report exists at all.

    Called only after the caller has already ruled out a traceback in
    ``log_text`` (see :func:`score_run`). ``preflight_failure`` (see
    :func:`score_run`) takes precedence over everything else here: when
    ``--run-log`` names a file that was never written and neither
    ``--scan-log`` nor ``--validate-log`` has any content either, no
    Mylonite command ran at all -- an earlier pre-flight step failed first,
    which is a target/harness outcome, not a product defect, whatever text
    (or lack of it) happens to be in the log. Otherwise defaults to
    PRODUCT_DEFECT -- an infra failure must be POSITIVELY evidenced, never
    assumed, since PRODUCT_DEFECT is the only classification that keeps a
    real crash from being quietly re-run away.
    """
    if preflight_failure:
        return {
            "classification": INFRA,
            "reason": (
                f"{run_dir}: no run.log was written and no scan.log/validate.log "
                "has any content either -- an earlier pre-flight step (e.g. the "
                "scaffold sanity check or a target install) failed before any "
                "mylonite command ran"
            ),
        }
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


def _resolve_scan_dir(run_dir: Path, scan_dir: Path | None) -> Path:
    """Which directory actually holds the REAL ``scan_report.json`` -- the
    one ``scan --output-dir`` wrote, with its own ``attempts``/
    ``calibration`` blocks -- as opposed to ``generate``'s trimmed
    ``{model, provider}`` copy it leaves beside the emitted test.

    For a scan-only cell (the N=1 smoke targets, or a precision/breadth cell
    scored straight from its scan directory), ``run_dir`` already IS the
    real scan directory. For a FULL_JOURNEY cell that reached
    ``generate``/``validate``, ``run_dir`` is the ``generated/`` directory
    instead, and the real report lives in a SEPARATE directory the
    workflow's own ``scan --output-dir`` wrote into -- callers pass that as
    ``scan_dir`` (``third-party-campaign.yml``'s ``scan_dir`` step output,
    never overwritten the way its ``score_dir`` output is). Prefers
    ``scan_dir`` when its own report carries ``attempts``; falls back to
    ``run_dir`` otherwise -- including every caller before this parameter
    existed, which passes ``None``, and every offline test fixture, which
    writes its report straight into ``run_dir``.
    """
    candidates: list[Path] = []
    for base in (scan_dir, run_dir):
        if base is None:
            continue
        candidates.append(base)
        # `scan --output-dir out` writes into a timestamped child
        # (`out/<ts>/`). When a caller passes the parent, try its children,
        # newest first, so the real report is never silently missed.
        if base.is_dir() and not (base / "scan_report.json").is_file():
            children = sorted(
                (c for c in base.iterdir() if (c / "scan_report.json").is_file()),
                key=lambda c: c.name,
                reverse=True,
            )
            candidates.extend(children)
    for candidate in candidates:
        report_path = candidate / "scan_report.json"
        if not report_path.is_file():
            continue
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and "attempts" in data:
            return candidate
    return run_dir


def _multi_report_subdirs(run_dir: Path) -> list[Path]:
    """Every immediate subdirectory of ``run_dir`` that looks like one
    exploit's own ``generate``+``validate`` output (an ``exploit_*.json``
    and/or a ``validation_report.json`` directly inside it), sorted by name
    for a deterministic pick on a tie.

    ``run_dir`` only ever qualifies for this layout when it carries NEITHER
    ``scan_report.json`` NOR ``validation_report.json`` itself -- the old
    single-report layout always has one or the other directly in
    ``run_dir``, so a pre-existing caller (and every fixture under
    ``tests/fixtures/score_third_party/``) always gets ``[]`` here and falls
    straight through to the unchanged single-report path in
    :func:`score_run`. A non-empty result means the harness generated+
    validated more than one exploit from the same scan, one subdirectory
    per exploit file stem (``third-party-campaign.yml``'s loop)."""
    if (run_dir / "scan_report.json").is_file() or (run_dir / "validation_report.json").is_file():
        return []
    if not run_dir.is_dir():
        return []
    subdirs = []
    for child in sorted(run_dir.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        if (child / "validation_report.json").is_file() or any(child.glob("exploit_*.json")):
            subdirs.append(child)
    return subdirs


def _exploit_tool(exploit_path: Path) -> str | None:
    """The MCP tool name an exploit file's own payload names as the
    consequential tool it exercised -- ``payload.metadata.
    consequential_tool`` (every W4 seed sets this; see ``seed_synth.py``),
    falling back to the first name in ``response.tool_calls`` when that key
    is absent. ``None`` when the file is missing, unreadable, or names
    neither."""
    try:
        data = json.loads(exploit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    payload = data.get("payload")
    if isinstance(payload, dict):
        metadata = payload.get("metadata")
        if isinstance(metadata, dict) and metadata.get("consequential_tool"):
            return str(metadata["consequential_tool"])
    response = data.get("response")
    if isinstance(response, dict):
        tool_calls = response.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            return str(tool_calls[0])
    return None


#: Precedence for picking which per-finding subdirectory's result speaks for
#: the whole multi-finding run's own ``classification``/``proof_level`` --
#: lower wins. Mirrors the module docstring's own classification order. A
#: product defect (or an infra/invalid signal) in ANY one subdirectory --
#: each now scored from its OWN generate.log/validate.log only, never a
#: shared log another exploit could have written into (see
#: ``_score_multi_report_run``'s docstring) -- still overrides a sibling's
#: real KEPT finding here, by deliberate choice: a crash is a product issue
#: that must never be auto-re-run or silently dropped (the module
#: docstring's rule #1), so this run's own top-level classification must
#: keep surfacing it even when another exploit in the same run validated
#: cleanly. The KEPT sibling's own true label/proof_level is NOT lost by
#: this choice -- it is still recorded accurately in ``validated_findings``,
#: which is what Critical finding 1 of the harness review was actually
#: about (the crash used to corrupt the KEPT sibling's OWN recorded data,
#: not merely outrank it). Among ordinary results, KEPT beats every
#: not-kept classification -- "KEPT over not-kept" from the harness's own
#: fix requirement.
_CLASSIFICATION_RANK: dict[str, int] = {
    PRODUCT_DEFECT: 0,
    INFRA: 1,
    INVALID: 2,
    KEPT: 3,
    FOUND_UNVALIDATED: 4,
    NOT_KEPT: 5,
    NOT_TESTED: 6,
}


def _proof_level_rank(level: object) -> int:
    """Lower is stronger, per ``PROOF_LEVEL_ORDER`` (strongest-first) -- an
    unknown or missing level ranks weakest of all, so it never beats a real
    measurement when picking the strongest validated finding."""
    from mylonite.scan.class_verdict import PROOF_LEVEL_ORDER

    if isinstance(level, str) and level in PROOF_LEVEL_ORDER:
        return PROOF_LEVEL_ORDER.index(level)
    return len(PROOF_LEVEL_ORDER)


def _pick_strongest(sub_results: list[dict[str, object]]) -> dict[str, object]:
    """The one sub-result that speaks for the whole multi-finding run:
    lowest classification rank first, then (within the same classification,
    e.g. two KEPT subdirectories) the strongest ``proof_level`` -- "KEPT
    over not-kept; effect-confirmed over dispatched-tool-linked"."""

    def _key(result: dict[str, object]) -> tuple[int, int]:
        rank = _CLASSIFICATION_RANK.get(str(result.get("classification")), 99)
        return (rank, _proof_level_rank(result.get("proof_level")))

    return min(sub_results, key=_key)


def _local_log_text(sub: Path) -> str:
    """This subdirectory's OWN ``generate.log`` + ``validate.log`` text, in
    that order -- never the shared, whole-of-run ``run.log``/``generate.log``/
    ``validate.log`` the workflow's outer ``tee -a`` also writes into, which
    every OTHER exploit's own generate/validate call appends to as well (see
    ``_score_multi_report_run``'s docstring for why that contamination was a
    real bug). A missing file contributes nothing; both missing gives
    ``""``, never ``None`` -- read as "no traceback, no infra signature",
    exactly like a clean run with no log at all."""
    parts = [
        text
        for name in ("generate.log", "validate.log")
        if (text := _read_log(sub / name)) is not None
    ]
    return "\n".join(parts)


#: ``validate``'s own "effect" gating-leg outcome prints this exact shape
#: (``ValidationReport`` outcome for ``stage == "effect"``, see
#: ``reference_validator.py``'s own formatting) -- three counts, always in
#: this order, always summing to the leg's run count. This is a DIFFERENT
#: axis from a scan ATTEMPT's own ``judge_evidence.proof_level`` (what
#: :func:`_finding_proof_level` reads): that is the single strongest level
#: one scan attempt reached; this is how many of VALIDATE's re-drives
#: against the real target reached each proof level, which can -- and for
#: some findings does -- read weaker (or stronger) than the scan attempt's
#: own level, because validate's own effect probe gets to re-run the attack
#: and read the target back multiple times under a calibration that may
#: have changed between the scan and the validate re-drive. See the module
#: docstring's "Two proof-level axes" section.
_EFFECT_COUNTS_RE = re.compile(
    r"by proof level:\s*(\d+)\s*effect-confirmed,\s*(\d+)\s*dispatched,\s*(\d+)\s*dispatched-tool-linked"
)

#: Effect-level strength order, strongest first -- mirrors the gating leg's
#: own priority order inside :func:`_validated_effect_proof_level`. Used
#: only to pick which KEPT finding's own validated effect level speaks for
#: a multi-report run's top-level ``validated_effect_proof_level``.
_EFFECT_LEVEL_ORDER: tuple[str, ...] = (
    "effect-confirmed",
    "dispatched-tool-linked",
    "dispatched",
)


def _effect_level_rank(level: object) -> int:
    """Lower is stronger. An unknown or missing level ranks weakest of all,
    so it never beats a real measurement when picking the strongest
    validated finding."""
    if isinstance(level, str) and level in _EFFECT_LEVEL_ORDER:
        return _EFFECT_LEVEL_ORDER.index(level)
    return len(_EFFECT_LEVEL_ORDER)


def _validated_effect_proof_level(
    report_dir: Path,
) -> tuple[str | None, dict[str, int] | None]:
    """``(strongest_level, counts)`` from ``report_dir/validation_report.json``'s
    own "effect" outcome detail text, or ``(None, None)`` when no validation
    report exists there (the cell never reached ``validate``) or its
    "effect" outcome's detail does not match the expected shape (an
    aborted/short-circuited validate run that never reached the effect
    leg). ``strongest_level`` is ``"effect-confirmed"``,
    ``"dispatched-tool-linked"`` or ``"dispatched"`` (the strongest
    non-zero count, matching the gating leg's own priority order), or
    ``None`` when all three counts are zero.

    This is the ONE place either proof-level axis is parsed -- shared by
    the single-report path (``build_e2e_results.py``'s own ``_score_one``,
    called once against a classic ``generated/`` directory) and the
    multi-report path (:func:`_score_multi_report_run`, called once per
    per-finding subdirectory) -- never duplicated. See the module
    docstring's "Two proof-level axes" section."""
    path = report_dir / "validation_report.json"
    if not path.is_file():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    effect = next((o for o in data.get("outcomes", []) if o.get("stage") == "effect"), None)
    if effect is None:
        return None, None
    match = _EFFECT_COUNTS_RE.search(str(effect.get("detail", "")))
    if match is None:
        return None, None
    n_ec, n_d, n_dtl = (int(g) for g in match.groups())
    counts = {"effect_confirmed": n_ec, "dispatched": n_d, "dispatched_tool_linked": n_dtl}
    if n_ec > 0:
        strongest = "effect-confirmed"
    elif n_dtl > 0:
        strongest = "dispatched-tool-linked"
    elif n_d > 0:
        strongest = "dispatched"
    else:
        strongest = None
    return strongest, counts


def _score_subdir(sub: Path, *, pattern: str | None, scan_dir: Path | None) -> dict[str, object]:
    """Score one per-finding subdirectory using ONLY its own logs -- never
    the shared ``run.log``/``scan.log`` another exploit's crash could have
    written into. Writes :func:`_local_log_text` to a throwaway temp file
    and passes THAT as ``run_log`` (the only way to feed :func:`score_run`
    log text without a path, since its traceback/infra-signature checks are
    path-based); ``scan_log`` is omitted entirely -- a scan-level crash
    happens before any subdirectory exists at all (``generate`` only runs
    after a successful scan), so there is nothing scan-level left to detect
    per subdirectory, and omitting it keeps the shared scan log's own
    behaviour exactly where it already lived: the ordinary, non-multi
    :func:`score_run` path this function never touches. ``validate_log`` is
    this subdirectory's own ``validate.log`` when ``generate`` got that
    far."""
    own_validate_log = sub / "validate.log"
    fd, tmp_name = tempfile.mkstemp(suffix=".log", prefix="score_subdir_")
    os.close(fd)
    local_run_log = Path(tmp_name)
    try:
        local_run_log.write_text(_local_log_text(sub), encoding="utf-8")
        return score_run(
            sub,
            run_log=local_run_log,
            scan_log=None,
            validate_log=own_validate_log if own_validate_log.is_file() else None,
            pattern=pattern,
            scan_dir=scan_dir,
        )
    finally:
        local_run_log.unlink(missing_ok=True)


def _score_multi_report_run(
    run_dir: Path,
    subdirs: list[Path],
    *,
    pattern: str | None,
    scan_dir: Path | None,
) -> dict[str, object]:
    """Score every per-finding subdirectory under ``run_dir`` (one per
    exploit the harness generated+validated -- see
    :func:`_multi_report_subdirs`) and combine them into one cell verdict.

    Each subdirectory is scored by :func:`_score_subdir` from its OWN
    ``generate.log``/``validate.log`` only -- never the shared, whole-of-run
    ``run_log``/``scan_log``/``validate_log`` :func:`score_run` was given at
    the top level (deliberately not forwarded here at all: passing them down
    used to let one exploit's crash corrupt a sibling's own recorded
    label/proof_level; see the harness review this fixes).

    Every validated finding is recorded in ``validated_findings`` (pattern,
    tool, verdict label, BOTH proof-level axes -- ``scan_proof_level`` (the
    scan attempt's own level) and ``validated_effect_proof_level``/
    ``validated_effect_counts`` (that exact finding's own ``validate``
    effect leg, parsed by :func:`_validated_effect_proof_level` -- the same
    parser the single-report path uses, never duplicated) -- AND that
    subdirectory's own ``classification`` -- ``label`` is ``None`` and
    ``classification`` names the failure, e.g. ``PRODUCT_DEFECT``, when that
    exploit's own generate/validate crashed; the crash is recorded, never
    silently dropped). See the module docstring's "Two proof-level axes"
    section for why a finding's scan-level and validate-level proof can
    differ, and which one a proof-depth bar must read.

    The cell's own top-level ``classification`` and ``proof_level`` are the
    STRONGEST sub-result's (see :func:`_pick_strongest`) -- never the
    alphabetically-first subdirectory, which is exactly the bug the
    single-exploit harness had (see the module docstring's batch-4
    finding). ``proof_level`` keeps its existing, scan-attempt meaning
    unchanged. The run's own top-level ``validated_effect_proof_level``/
    ``validated_effect_counts`` are a SEPARATE field, computed from the
    STRONGEST KEPT finding's own validated effect level (never from the
    scan axis) -- ``(None, None)`` when no finding here was KEPT.

    Deliberate choice on a mixed run (one exploit crashed, a sibling KEPT):
    the top-level ``classification`` reads the CRASH (``PRODUCT_DEFECT``
    outranks ``KEPT`` in :data:`_CLASSIFICATION_RANK`), because a product
    defect must never be silently outranked by an unrelated sibling's good
    result -- the module docstring's rule #1 ("PRODUCT_DEFECT is NEVER
    counted toward the N=3 bar and is NEVER auto-re-run"). The KEPT
    sibling's own finding is never hidden by this choice: it is still
    present, with its real label and proof_level, in ``validated_findings``
    and in ``scan_findings`` (``validated: true``) -- a reader of this run's
    score sees BOTH the crash that needs investigating and the real finding
    that was proven anyway.

    ``scan_findings``/``max_scan_proof_level`` mark EVERY validated
    pattern_id, not only one."""
    sub_results = [_score_subdir(sub, pattern=pattern, scan_dir=scan_dir) for sub in subdirs]

    validated_findings: list[dict[str, object]] = []
    kept_pattern_ids: set[str] = set()
    for sub, sub_result in zip(subdirs, sub_results, strict=True):
        pattern_id = _validated_pattern_id(sub)
        if pattern_id is None:
            continue
        exploit_matches = sorted(sub.glob("exploit_*.json"))
        tool = _exploit_tool(exploit_matches[0]) if exploit_matches else None
        label = sub_result.get("label")
        effect_level, effect_counts = _validated_effect_proof_level(sub)
        validated_findings.append(
            {
                "pattern_id": pattern_id,
                "tool": tool,
                "label": label,
                "scan_proof_level": sub_result.get("proof_level"),
                "validated_effect_proof_level": effect_level,
                "validated_effect_counts": effect_counts,
                "classification": sub_result.get("classification"),
            }
        )
        if label == "KEPT":
            kept_pattern_ids.add(pattern_id)

    # The run's own top-level validated-effect level/counts: the STRONGEST
    # KEPT finding's own validate effect leg -- a separate axis from the
    # scan-based `proof_level` below (see the module docstring). `(None,
    # None)` when nothing here was KEPT, matching the single-report path's
    # own "no validation_report.json/effect outcome" default.
    kept_findings = [f for f in validated_findings if f.get("label") == "KEPT"]
    if kept_findings:
        strongest_kept = min(
            kept_findings,
            key=lambda f: _effect_level_rank(f.get("validated_effect_proof_level")),
        )
        top_validated_effect_level = strongest_kept.get("validated_effect_proof_level")
        top_validated_effect_counts = strongest_kept.get("validated_effect_counts")
    else:
        top_validated_effect_level = None
        top_validated_effect_counts = None

    real_scan_dir = _resolve_scan_dir(run_dir, scan_dir)
    raw_report = _read_raw_report_safe(real_scan_dir)
    validated_ids = {f["pattern_id"] for f in validated_findings if f["pattern_id"]}
    scan_findings = _scan_findings_for(raw_report, validated_ids)
    max_scan_proof_level = _max_scan_proof_level(scan_findings)

    weakness_classes = sorted({w for sr in sub_results for w in (sr.get("weakness_classes") or [])})
    pattern_blocks = _pattern_blocks_for(raw_report, pattern)
    for pid in sorted(kept_pattern_ids):
        _mark_kept(
            pattern_blocks,
            pattern=pattern,
            weakness_classes=weakness_classes,
            raw_report=raw_report,
            validated_pattern_id=pid,
        )

    winner = _pick_strongest(sub_results)
    result = dict(winner)
    for weakness_key in ("w1", "w2", "w3", "w4"):
        result.pop(weakness_key, None)
    result.update(pattern_blocks)
    result["weakness_classes"] = weakness_classes
    result["validated_findings"] = validated_findings
    result["scan_findings"] = scan_findings
    result["max_scan_proof_level"] = max_scan_proof_level
    result["exercised"] = any(sr.get("exercised") for sr in sub_results)
    # Separate from `proof_level` above (the scan axis, unchanged) -- see
    # the module docstring's "Two proof-level axes" section.
    result["validated_effect_proof_level"] = top_validated_effect_level
    result["validated_effect_counts"] = top_validated_effect_counts
    return result


def score_run(
    run_dir: Path,
    *,
    run_log: Path | None = None,
    scan_log: Path | None = None,
    validate_log: Path | None = None,
    pattern: str | None = None,
    scan_dir: Path | None = None,
) -> dict[str, object]:
    """Classify one run directory per the prereg's pass rule.

    ``run_log`` is the whole captured output, used for the traceback check
    and, when no ``scan_log`` is given, for scan-stage reason codes.
    ``scan_log`` and ``validate_log`` are each stage's own output; a
    ``validate_log`` path whose file does not exist means validate never ran.
    ``pattern`` is the cell's own ``--weakness-class``/``pattern`` dispatch
    value (``W1``-``W4``, or ``None``/blank when the cell runs unfiltered --
    see :func:`_score_run_normally`'s per-declared-class handling of a blank
    pattern). ``scan_dir`` is the REAL scan output directory, when it
    differs from ``run_dir`` (see :func:`_resolve_scan_dir`); omitted for a
    scan-only ``run_dir`` or an offline test fixture.

    When ``run_dir`` holds several per-finding subdirectories instead of a
    single flat report (the harness now generates+validates EVERY exploit a
    scan found, not only the alphabetically-first -- see
    :func:`_multi_report_subdirs`), this scores each one and combines them
    (:func:`_score_multi_report_run`); a run with the old single-report
    layout is unaffected and scores exactly as it always has.
    """
    subdirs = _multi_report_subdirs(run_dir)
    if subdirs:
        return _score_multi_report_run(
            run_dir,
            subdirs,
            pattern=pattern,
            scan_dir=scan_dir,
        )

    scan_text = _read_log(scan_log)
    validate_text = _read_log(validate_log)
    log_text = _read_log(run_log)
    # A run-log PATH was given (the campaign workflow always passes
    # `--run-log run.log`) but no such file exists, and neither of the two
    # per-stage logs has any content either -- every stage log the harness
    # could have written is absent, so no mylonite command ran at all (see
    # `_classify_missing_report`'s docstring). `run_log is None` (no
    # `--run-log` given at all) is a different, legacy call shape some
    # callers and tests still use and is deliberately left out of this
    # check.
    preflight_failure = (
        run_log is not None
        and not run_log.is_file()
        and scan_text is None
        and validate_text is None
    )
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
            result = _score_run_normally(
                run_dir,
                log_text,
                codes_text,
                pattern=pattern,
                scan_dir=scan_dir,
                preflight_failure=preflight_failure,
            )
    if target_noise_traceback:
        result["target_noise_traceback"] = True
    result["exercised"] = _run_exercised(run_dir, result, scan_dir=scan_dir)

    # Integrity rule 7 (the prereg): calibration status and proof level
    # travel with EVERY scored run, not only KEPT/NOT_KEPT/FOUND_UNVALIDATED
    # -- a NOT_TESTED/PRODUCT_DEFECT/INVALID run gets both as an explicit
    # ``None`` (present, not omitted) rather than leaving a downstream
    # reader to ``dict.get()`` defensively. ``setdefault`` is a no-op for
    # every branch above that already computed a real value. Read from the
    # REAL scan directory (see :func:`_resolve_scan_dir`) -- a validated
    # run's own ``run_dir`` may hold only ``generate``'s trimmed report, and
    # calibration lives in that directory's ``verdicts.json``, never in
    # ``scan_report.json`` at all (see :func:`_calibration_info`).
    real_scan_dir_for_defaults = _resolve_scan_dir(run_dir, scan_dir)
    raw_report_for_defaults = _read_raw_report_safe(real_scan_dir_for_defaults)
    defaults = _calibration_info(real_scan_dir_for_defaults)
    validated_pattern_id_for_defaults = _validated_pattern_id(run_dir)
    result.setdefault("calibration_status", defaults["calibration_status"])
    result.setdefault("calibration_reason_code", defaults["calibration_reason_code"])
    result.setdefault(
        "proof_level",
        _finding_proof_level(raw_report_for_defaults, validated_pattern_id_for_defaults),
    )
    # scan_findings/max_scan_proof_level travel with EVERY scored run, same
    # as calibration_status/proof_level above (integrity rule 7) -- a scan
    # can record more FOUND attempts than the one that was ever validated
    # (see _scan_findings's docstring), and that must stay visible whatever
    # this run's own classification turned out to be.
    scan_findings = _scan_findings(raw_report_for_defaults, validated_pattern_id_for_defaults)
    result.setdefault("scan_findings", scan_findings)
    result.setdefault("max_scan_proof_level", _max_scan_proof_level(scan_findings))
    return result


def _run_exercised(
    run_dir: Path, result: dict[str, object], *, scan_dir: Path | None = None
) -> bool:
    """Whether at least one attempt in this run reached a real verdict
    (``finding``/``no_finding``) -- the integrity rule's "a cell counts only
    if attacks were actually exercised" (used by :func:`precision_rollup`).

    Prefers re-reading the REAL ``scan_report.json`` (see
    :func:`_resolve_scan_dir`: ``scan_dir`` when its own report carries
    ``attempts``, else ``run_dir``) and the same ``ScanDirResult.exercised``
    every other classification already trusts. Reading ``run_dir``'s own
    file unconditionally was the bug this parameter closes: for a validated
    FULL_JOURNEY run, that file is only ``generate``'s trimmed
    ``{model, provider}`` copy, with no ``attempts`` list at all, which made
    every such run read as unexercised even on a KEPT verdict. When no real
    scan report is found anywhere but ``validate`` ran anyway -- the "scan
    stopped at its ceiling but still recorded a finding" path, scored from
    ``validate``'s own log -- the prereg says that always follows a real
    recorded finding, so it counts as exercised even though the finding
    itself lives in a directory this function was not pointed at. Anything
    else defaults to whether the classification itself required a judged
    outcome.
    """
    real_dir = _resolve_scan_dir(run_dir, scan_dir)
    report_path = real_dir / "scan_report.json"
    if report_path.is_file():
        try:
            return load_scan_dir(real_dir).exercised
        except ScanDirIntegrityError:
            return False
    if result.get("stage") == "validate":
        return True
    return result.get("classification") in (KEPT, NOT_KEPT, FOUND_UNVALIDATED)


def _first_finding_weakness(
    raw_report: dict, validated_pattern_id: str | None = None
) -> str | None:
    """The W1-W4 class of the attempt ``generate``/``validate`` actually
    acted on. Used only for the blank-``pattern`` per-declared-class
    breakdown, to decide which class's block gets ``kept=1`` on a KEPT
    verdict. Prefers the attempt matching ``validated_pattern_id`` (see
    :func:`_validated_pattern_id`) -- with multiple findings, the first
    ``outcome=finding`` attempt in list order need not be the one that was
    actually validated (the same mismatch :func:`_finding_proof_level`
    guards against); falls back to that "first finding" behaviour when
    omitted or not found."""
    attempts = raw_report.get("attempts", []) if isinstance(raw_report, dict) else []
    if validated_pattern_id is not None:
        for attempt in attempts:
            if (
                isinstance(attempt, dict)
                and attempt.get("outcome") == "finding"
                and attempt.get("pattern_id") == validated_pattern_id
            ):
                return _weakness_for_pattern(validated_pattern_id)
    for attempt in attempts:
        if isinstance(attempt, dict) and attempt.get("outcome") == "finding":
            return _weakness_for_pattern(str(attempt.get("pattern_id", "")))
    return None


def _pattern_blocks_for(raw_report: dict, pattern: str | None) -> dict[str, dict[str, int]]:
    """The fired/resisted/kept block(s) to merge into a score result, keyed
    by weakness class in lowercase (``"w1"``, ``"w2"``, ...).

    An explicit ``--weakness-class``/``pattern`` dispatch (``W1``-``W4``)
    always gets exactly one block, under its own key, whether or not any
    attempt actually belongs to it (the e2e-reference-w1 breadth cell
    depends on this: a clean resist still reports a `"w1"` block showing
    0 fired).

    A BLANK pattern (the unfiltered cells) never defaults to a hardcoded
    `"w1"` -- a target whose scan declared W2/W4 and never ran a single W1
    seed must not read an all-zero `"w1"` block as if W1 had been measured.
    Instead, one block per class actually present among the run's own
    attempts (via :func:`_weakness_for_pattern`), empty (no block at all)
    when none resolve to a known class.
    """
    if pattern:
        key = pattern.upper()
        return {key.lower(): _weakness_counts(raw_report, key)}
    classes_seen: set[str] = set()
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict):
            continue
        weakness = _weakness_for_pattern(str(attempt.get("pattern_id", "")))
        if weakness:
            classes_seen.add(weakness)
    return {w.lower(): _weakness_counts(raw_report, w) for w in sorted(classes_seen)}


def _mark_kept(
    pattern_blocks: dict[str, dict[str, int]],
    *,
    pattern: str | None,
    weakness_classes: list[str],
    raw_report: dict,
    validated_pattern_id: str | None = None,
) -> None:
    """Set ``kept=1`` on the one block the validated finding belongs to.

    An explicit pattern is marked only when the target actually declared
    that class (unchanged from before this function existed); a blank
    pattern looks at the finding's own attempt instead, since several
    classes' blocks may be present at once.
    """
    if pattern:
        key = pattern.upper()
        if key in weakness_classes and key.lower() in pattern_blocks:
            pattern_blocks[key.lower()]["kept"] = 1
        return
    found_weakness = _first_finding_weakness(raw_report, validated_pattern_id)
    if found_weakness and found_weakness.lower() in pattern_blocks:
        pattern_blocks[found_weakness.lower()]["kept"] = 1


def _score_run_normally(
    run_dir: Path,
    log_text: str,
    codes_text: str,
    *,
    pattern: str | None = None,
    scan_dir: Path | None = None,
    preflight_failure: bool = False,
) -> dict[str, object]:
    """Every classification branch except rule #1 (the traceback check,
    handled by the caller, :func:`score_run`, before this is reached).
    ``log_text`` is the whole log, searched for infra signatures;
    ``codes_text`` is the scored stage's own log, the only place reason
    codes are read from. ``pattern`` is the cell's own weakness-class
    filter (``W1``-``W4``); blank/``None`` reports counts per class actually
    present (see :func:`_pattern_blocks_for`). ``scan_dir`` is the REAL scan
    output directory when it differs from ``run_dir`` (see
    :func:`_resolve_scan_dir`) -- used only to source the data fields below
    (calibration, proof level, weakness counts, reason codes FROM attempts);
    the structural "does this directory exist at all" checks below still
    read ``run_dir`` itself. ``preflight_failure`` (see :func:`score_run`)
    is forwarded to :func:`_classify_missing_report` unchanged.
    """
    report_path = run_dir / "scan_report.json"
    validation_path = run_dir / "validation_report.json"

    if not report_path.is_file() and not validation_path.is_file():
        return _classify_missing_report(run_dir, log_text, preflight_failure=preflight_failure)

    scan_result = None
    if report_path.is_file():
        try:
            scan_result = load_scan_dir(run_dir)
        except ScanDirIntegrityError as exc:
            # A partial copy (a finding with no exploit file) is untrustworthy
            # in the same way a missing report is -- no traceback was found
            # above, so this is a product/harness defect, not an infra one.
            return {"classification": PRODUCT_DEFECT, "reason": str(exc)}

    # The REAL scan directory -- scan's own output, with its own
    # `scan_report.json` `attempts` list and its own `verdicts.json`
    # (calibration lives there, never in `scan_report.json` -- see
    # `_calibration_info`) -- not `generate`'s trimmed `{model, provider}`
    # `scan_report.json` copy that may sit in `run_dir` instead (see
    # `_resolve_scan_dir`'s docstring). Falls back to run_dir itself when no
    # better directory is found, so every caller that predates this
    # parameter (and every offline test fixture) is unaffected.
    real_scan_dir = _resolve_scan_dir(run_dir, scan_dir)
    real_report_path = real_scan_dir / "scan_report.json"
    raw_report: dict = {}
    if real_report_path.is_file():
        raw_report = json.loads(real_report_path.read_text(encoding="utf-8"))
    log_reason_codes = _REASON_CODE_RE.findall(codes_text)
    reason_codes = _dedupe(_reason_codes_in_attempts(raw_report) + log_reason_codes)
    weakness_classes = sorted(scan_result.weakness_classes) if scan_result is not None else []
    calibration_info = _calibration_info(real_scan_dir)
    proof_level = _finding_proof_level(raw_report, _validated_pattern_id(run_dir))
    pattern_blocks = _pattern_blocks_for(raw_report, pattern)

    if validation_path.is_file():
        from mylonite._verdict import verdict_label
        from mylonite.contracts import ValidationReport

        report = ValidationReport.model_validate_json(validation_path.read_text(encoding="utf-8"))
        label = verdict_label(report)
        if label == "KEPT":
            _mark_kept(
                pattern_blocks,
                pattern=pattern,
                weakness_classes=weakness_classes,
                raw_report=raw_report,
                validated_pattern_id=_validated_pattern_id(run_dir),
            )
            return {
                "classification": KEPT,
                "label": label,
                "weakness_classes": weakness_classes,
                "reason_codes": reason_codes,
                "proof_level": proof_level,
                **pattern_blocks,
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
            **pattern_blocks,
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
            **pattern_blocks,
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
        **pattern_blocks,
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
        help="The cell's own --weakness-class/pattern value (W1-W4). An explicit value "
        "always reports exactly that class's fired/resisted/kept counts, under its own "
        "key ('w2' for W2, etc.), whether or not any attempt belongs to it; blank/omitted "
        "reports one block per class actually present among the run's own attempts "
        "instead of guessing W1.",
    )
    score_p.add_argument(
        "--scan-dir",
        type=Path,
        default=None,
        help="The REAL scan output directory (scan --output-dir's own timestamped dir), "
        "when it differs from RUN_DIR -- RUN_DIR is `generated/` for a validated "
        "FULL_JOURNEY run, whose own scan_report.json is only generate's trimmed "
        "{model, provider} copy; this points at the one with the real attempts/"
        "calibration blocks. Omitted when RUN_DIR already is the real scan directory.",
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
            scan_dir=args.scan_dir,
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
