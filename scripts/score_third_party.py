#!/usr/bin/env python3
"""Score a third-party-campaign run against verification/PREREG_THIRD_PARTY_2026_10.md.

Why this exists
----------------
``.github/workflows/third-party-campaign.yml`` runs Mylonite's own CLI
against six systems it has never run against before (see
``verification/SOURCE.md`` and ``verification/PREREG_THIRD_PARTY_2026_10.md``).
Each cell runs the real journey -- ``scan`` then ``generate --latest`` then
``validate`` -- so a ``validation_report.json`` is written next to the
generated test REGARDLESS of whether the finding was kept (the standalone
``validate`` command always persists one; only ``gate``'s orchestrator skips
it for a rejected finding, which is why this harness drives the three
commands directly rather than ``gate``). This script turns one such
directory into a single classification the prereg's pass rule defines, and
then combines N classifications (the N=3, >=2/3 bar for targets 1-3) into
one cell verdict.

Classification, in order
-------------------------
1. ``PRODUCT_DEFECT`` -- the run cannot be trusted as a clean result AND
   there is no evidence of an infrastructure cause: a missing/partial report
   with no recognisable infra signature in the captured log, or a scan whose
   attempts include one that is neither ``finding`` nor ``no_finding`` and
   carries NO reason code, alongside zero findings. Per the prereg, this is
   NEVER counted toward the N=3 bar and is NEVER auto-re-run -- re-running a
   product crash as if it were a flaky runner would hide the bug this
   campaign exists to surface. It is logged as a product issue instead.
2. ``INVALID`` -- the run directory is missing or unreadable AND the
   captured log carries a recognised infrastructure signature (a runner
   crash, a provider 5xx, a timeout). This is the ONLY classification a
   re-run is allowed for.
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
   ``validation_report.json`` sits beside it. Under never-keep-unproven this
   is a candidate, never a verdict -- deliberately NOT folded into KEPT.
6. ``NOT_TESTED`` -- no attempt reached a verdict at all (every attempt
   skipped, not-applicable, or undecided), and every such attempt carries a
   named reason code.

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

#: Case-insensitive substrings in a captured run.log that indicate an
#: infrastructure failure rather than a product defect -- the ONLY signal
#: that makes a missing/partial report re-runnable (INVALID) rather than a
#: logged product issue (PRODUCT_DEFECT). Deliberately narrow: an absent or
#: ambiguous log defaults to PRODUCT_DEFECT, never to the re-runnable case.
_INFRA_SIGNATURES: tuple[str, ...] = (
    "connection reset",
    "connection refused",
    "temporary failure in name resolution",
    "timed out",
    "timeout",
    "502 bad gateway",
    "503",
    "service unavailable",
    "overloaded_error",
    "rate_limit_error",
    "internal server error",
    "the runner has received a shutdown signal",
    "lost communication with the server",
)

_TRACEBACK_MARKER = "Traceback (most recent call last):"


def _reason_codes(raw_report: dict) -> list[str]:
    """Every ``MYL-...`` reason code mentioned anywhere in the attempts list."""
    codes: list[str] = []
    for attempt in raw_report.get("attempts", []) if isinstance(raw_report, dict) else []:
        if not isinstance(attempt, dict):
            continue
        for field in ("verdict_reason", "not_applicable_reason", "error_detail"):
            text = attempt.get(field)
            if isinstance(text, str):
                codes.extend(_REASON_CODE_RE.findall(text))
    return codes


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


def _infra_signature_in(log_text: str) -> str | None:
    lowered = log_text.lower()
    for signature in _INFRA_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def _classify_missing_report(run_dir: Path, run_log: Path | None) -> dict[str, object]:
    """Decide PRODUCT_DEFECT vs INVALID when no report exists at all.

    Defaults to PRODUCT_DEFECT -- an infra failure must be POSITIVELY
    evidenced in the log, never assumed, since PRODUCT_DEFECT is the only
    classification that keeps a real crash from being quietly re-run away.
    """
    log_text = (
        run_log.read_text(encoding="utf-8", errors="replace")
        if run_log and run_log.is_file()
        else ""
    )
    signature = _infra_signature_in(log_text)
    if signature is not None:
        return {
            "classification": INVALID,
            "reason": f"{run_dir}: no report found; infra signature in run.log: {signature!r}",
        }
    has_traceback = _TRACEBACK_MARKER in log_text
    reason = (
        f"{run_dir}: no scan_report.json or validation_report.json found, and no "
        "recognised infrastructure signature in run.log"
    )
    if has_traceback:
        reason += " (a Python traceback IS present -- investigate as a product crash)"
    return {"classification": PRODUCT_DEFECT, "reason": reason}


def score_run(run_dir: Path, *, run_log: Path | None = None) -> dict[str, object]:
    """Classify one run directory per the prereg's pass rule."""
    report_path = run_dir / "scan_report.json"
    validation_path = run_dir / "validation_report.json"

    if not report_path.is_file() and not validation_path.is_file():
        return _classify_missing_report(run_dir, run_log)

    scan_result = None
    if report_path.is_file():
        try:
            scan_result = load_scan_dir(run_dir)
        except ScanDirIntegrityError as exc:
            # A partial copy (a finding with no exploit file) is untrustworthy,
            # same reasoning as a missing report: evidenced infra cause only.
            signature = None
            if run_log is not None and run_log.is_file():
                signature = _infra_signature_in(
                    run_log.read_text(encoding="utf-8", errors="replace")
                )
            if signature is not None:
                return {
                    "classification": INVALID,
                    "reason": f"{exc} (infra signature: {signature!r})",
                }
            return {"classification": PRODUCT_DEFECT, "reason": str(exc)}

    raw_report: dict = {}
    if report_path.is_file():
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    reason_codes = _reason_codes(raw_report)
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
        return {
            "classification": NOT_TESTED,
            "reason": f"scan aborted: {aborted}",
            "reason_codes": reason_codes,
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
        return {
            "classification": NOT_TESTED,
            "reason": "no attempt reached a verdict (all skipped/not_applicable/undecided)",
            "reason_codes": reason_codes,
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
    SAME reason code(s) -- two NOT_TESTED runs for different reasons do not
    agree with each other."""
    classification = score.get("classification")
    if classification == NOT_TESTED:
        return (classification, tuple(sorted(score.get("reason_codes", []) or [])))
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
        help="Captured stdout log for this run, used only to tell a product defect from an infra failure.",
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
