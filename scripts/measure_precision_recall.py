"""Measure the differential oracle's precision/recall on the offline corpus.

Run from the repo root::

    python scripts/measure_precision_recall.py [--out corpus_report.json]

Drives the bundled kitchen-sink twins across the W1-W4 seeded weaknesses with no
LLM and no network, then prints a confusion matrix + precision / recall / FPR and
writes a JSON report. Requires the reference target::

    pip install -e ./reference_targets/mcp_kitchen_sink

This turns "the oracle is reliable" into a measured number CI can track.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from mylonite.corpus import run_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("corpus_report.json"),
        help="Where to write the JSON report (default: corpus_report.json).",
    )
    args = parser.parse_args()

    results, cm = run_corpus()

    print("Differential-oracle precision/recall corpus (offline, no LLM)\n")
    print(f"{'weakness':<10} {'variant':<11} {'expected':<10} {'detected':<10} {'ok':<3}")
    for r in results:
        print(
            f"{r.weakness:<10} {r.variant:<11} "
            f"{'exploit' if r.expected_exploited else 'clean':<10} "
            f"{'exploit' if r.detected_exploited else 'clean':<10} "
            f"{'+' if r.correct else 'x':<3}"
        )
    print(
        f"\nconfusion: TP={cm.tp} FP={cm.fp} FN={cm.fn} TN={cm.tn} (n={cm.total})\n"
        f"precision={cm.precision:.3f}  recall={cm.recall:.3f}  "
        f"FPR={cm.false_positive_rate:.3f}  F1={cm.f1:.3f}"
    )

    report = {
        "confusion_matrix": asdict(cm),
        "precision": cm.precision,
        "recall": cm.recall,
        "false_positive_rate": cm.false_positive_rate,
        "f1": cm.f1,
        "cases": [asdict(r) for r in results],
    }
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
