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
   **A Python traceback with at least one ``mylonite`` stack frame anywhere
   in the captured log wins this classification outright**, before anything
   else is even considered: Mylonite's own code is designed to catch and
   cleanly report provider and config errors (``aborted``,
   ``classify_provider_error``), so a raw traceback FROM MYLONITE'S OWN CODE
   leaking to stdout means something it did not anticipate, regardless of
   what the traceback's text happens to contain. A traceback with NO
   ``mylonite`` frame at all -- the target server's own crash -- is target
   noise, not a Mylonite defect: the stdio adapter spawns each target server
   without separating its stderr from Mylonite's own
   (``_session_adapter.py``'s ``stdio_client`` call carries no ``errlog``),
   so a third-party server's own traceback (e.g. on shutdown, or a tool
   error) lands in the same captured log. Properly separating the two
   streams needs a ``src/mylonite`` change (passing ``errlog=`` through to
   ``stdio_client``) that this harness does not make; filtering by stack
   frame here is the workaround that needs none. A target-only traceback is
   recorded (``target_noise_traceback: true`` in the output) but never
   blocks the cell. The PRODUCT_DEFECT classification also covers: a
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

Usage
-----

::

    # one run (the directory `validate` wrote validation_report.json into)
    python scripts/score_third_party.py score out/generated/<slug>/ \\
        --target tpv-server-memory --run-log run.log --out score-run1.json

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
#: stderr from ours" -- see the module docstring's point #1. A simple
#: substring check on a `File "..."` frame's path, not anchored further:
#: Mylonite's own installed location always contains this component,
#: whether run from a wheel's site-packages or an editable checkout.
_MYLONITE_FRAME_MARKER = "mylonite"


def _mylonite_traceback_present(log_text: str) -> bool:
    """True when at least one traceback block carries a ``mylonite`` stack
    frame -- as opposed to one raised entirely inside a spawned third-party
    server, whose own stderr the stdio adapter does not currently separate
    from Mylonite's own captured output."""
    return any(
        _MYLONITE_FRAME_MARKER in match.group(0) for match in _TRACEBACK_BLOCK_RE.finditer(log_text)
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


def score_run(run_dir: Path, *, run_log: Path | None = None) -> dict[str, object]:
    """Classify one run directory per the prereg's pass rule."""
    log_text = ""
    if run_log is not None and run_log.is_file():
        log_text = run_log.read_text(encoding="utf-8", errors="replace")

    # Rule #1, checked before anything else: a traceback with a mylonite
    # stack frame anywhere is a product defect, full stop -- see the module
    # docstring. A traceback with NO mylonite frame (the target server's own
    # crash, inseparable from our log without a src/ change) is recorded,
    # not blocked -- it falls through to ordinary classification below.
    has_traceback = _TRACEBACK_MARKER in log_text
    target_noise_traceback = False
    if has_traceback:
        if _mylonite_traceback_present(log_text):
            return {
                "classification": PRODUCT_DEFECT,
                "reason": (
                    "a Python traceback with a mylonite stack frame is present in "
                    "run.log -- investigate as a product crash, never auto-re-run"
                ),
            }
        target_noise_traceback = True

    result = _score_run_normally(run_dir, log_text)
    if target_noise_traceback:
        result["target_noise_traceback"] = True
    return result


def _score_run_normally(run_dir: Path, log_text: str) -> dict[str, object]:
    """Every classification branch except rule #1 (the traceback check,
    handled by the caller, :func:`score_run`, before this is reached)."""
    report_path = run_dir / "scan_report.json"
    validation_path = run_dir / "validation_report.json"

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
    log_reason_codes = _REASON_CODE_RE.findall(log_text)
    reason_codes = _dedupe(_reason_codes_in_attempts(raw_report) + log_reason_codes)
    weakness_classes = sorted(scan_result.weakness_classes) if scan_result is not None else []

    if validation_path.is_file():
        from mylonite._verdict import verdict_label
        from mylonite.contracts import ValidationReport

        report = ValidationReport.model_validate_json(validation_path.read_text(encoding="utf-8"))
        label = verdict_label(report)
        if label == "KEPT":
            return {
                "classification": KEPT,
                "label": label,
                "weakness_classes": weakness_classes,
                "reason_codes": reason_codes,
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
    score_p.add_argument("--out", type=Path, required=True)

    rollup_p = sub.add_parser(
        "rollup", help="Combine N per-run score.json files into one cell verdict."
    )
    rollup_p.add_argument("score_files", nargs="+", type=Path)
    rollup_p.add_argument("--bar-numerator", type=int, default=2)
    rollup_p.add_argument("--bar-denominator", type=int, default=3)
    rollup_p.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)

    if args.command == "score":
        result = score_run(args.run_dir, run_log=args.run_log)
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

    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
