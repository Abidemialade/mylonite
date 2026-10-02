#!/usr/bin/env python3
"""Score a third-party-campaign run against verification/PREREG_L2_THIRD_PARTY.md.

Why this exists
----------------
``.github/workflows/third-party-campaign.yml`` runs Mylonite's own CLI
against six systems it has never run against before (see
``verification/SOURCE.md`` and ``verification/PREREG_L2_THIRD_PARTY.md``).
Each run writes a ``scan_report.json`` (and, once a finding is generated and
validated, a ``validation_report.json``) under its own output directory.
This script turns one such directory into a single classification the
prereg's pass rule defines, and then combines N classifications (the N=3,
>=2/3 bar for targets 1-3) into one cell verdict.

Classification, in order
-------------------------
1. ``INVALID`` -- the run directory is missing, unreadable, or (reusing
   :func:`verification._scan_dir.load_scan_dir`'s existing guard) a partial
   copy whose findings can't be trusted. This is the ONLY classification a
   re-run is allowed for, and only for a genuine infrastructure failure
   (never because the result is unwelcome).
2. ``KEPT`` -- a ``validation_report.json`` exists and ``kept`` is true.
3. ``NOT_KEPT`` -- a ``validation_report.json`` exists and ``kept`` is
   false, or the scan was exercised and found nothing.
4. ``FOUND_UNVALIDATED`` -- ``scan_report.json`` recorded a finding but no
   ``validation_report.json`` sits beside it. Under never-keep-unproven this
   is a candidate, never a verdict -- deliberately NOT folded into KEPT.
5. ``NOT_TESTED`` -- the scan aborted, or no attempt reached a verdict at
   all (every attempt skipped, not-applicable, or undecided).

Usage
-----

::

    # one run
    python scripts/score_third_party.py score out/2026-10-15T.../ \\
        --target tpv-server-memory --out score-run1.json

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

KEPT = "KEPT"
NOT_KEPT = "NOT_KEPT"
FOUND_UNVALIDATED = "FOUND_UNVALIDATED"
NOT_TESTED = "NOT_TESTED"
INVALID = "INVALID"

_REASON_CODE_RE = re.compile(r"MYL-[A-Z]+-\d+")


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


def score_run(run_dir: Path) -> dict[str, object]:
    """Classify one run directory per the prereg's pass rule."""
    report_path = run_dir / "scan_report.json"
    validation_path = run_dir / "validation_report.json"

    if not report_path.is_file() and not validation_path.is_file():
        return {
            "classification": INVALID,
            "reason": (
                f"{run_dir}: neither scan_report.json nor validation_report.json "
                "found -- not a recognised run directory."
            ),
        }

    scan_result = None
    if report_path.is_file():
        try:
            scan_result = load_scan_dir(run_dir)
        except ScanDirIntegrityError as exc:
            return {"classification": INVALID, "reason": str(exc)}

    raw_report: dict = {}
    if report_path.is_file():
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    reason_codes = _reason_codes(raw_report)
    weakness_classes = sorted(scan_result.weakness_classes) if scan_result is not None else []

    if validation_path.is_file():
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        if validation.get("kept"):
            return {
                "classification": KEPT,
                "weakness_classes": weakness_classes,
                "reason_codes": reason_codes,
            }
        failing = next(
            (o for o in validation.get("outcomes", []) if not o.get("passed", True)),
            None,
        )
        detail = (failing or {}).get("detail") or validation.get("notes") or "not kept"
        return {
            "classification": NOT_KEPT,
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
        "detail": "exercised, 0 findings",
        "weakness_classes": weakness_classes,
        "reason_codes": reason_codes,
    }


def rollup(
    classifications: list[str], *, bar_numerator: int, bar_denominator: int
) -> dict[str, object]:
    """Apply the fixed-N, >=bar-numerator/bar-denominator rule across re-drives."""
    counts = Counter(classifications)
    winner, n = counts.most_common(1)[0] if counts else (None, 0)
    met_bar = len(classifications) == bar_denominator and n >= bar_numerator and winner is not None
    return {
        "n": len(classifications),
        "counts": dict(counts),
        "result": winner if met_bar else "NO_CONSENSUS",
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
        result = score_run(args.run_dir)
        result["target"] = args.target
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "rollup":
        classifications = [
            json.loads(f.read_text(encoding="utf-8"))["classification"] for f in args.score_files
        ]
        result = rollup(
            classifications,
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
