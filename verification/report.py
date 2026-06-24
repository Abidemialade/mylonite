"""Build + persist Layer 2 verification reports.

A report carries two distinct numbers, kept separate on purpose:

- ``benchmark_asr`` — the benchmark's OWN attack-success rate over the recorded
  run (fraction of cases the model fell for). This is the leaderboard-comparable
  headline; it is third-party ground truth, not a Mylonite claim.
- ``judge_agreement`` — how well Mylonite's success-judge reproduces the
  benchmark's per-case verdict (precision/recall/F1/FPR via the confusion
  matrix). This is the independently-verifiable claim about Mylonite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mylonite.corpus import CaseResult, ConfusionMatrix

_HONESTY = (
    "judge_agreement compares Mylonite's success-judge to the benchmark's own "
    "success rule on real recorded transcripts. benchmark_asr is the benchmark's "
    "result, not Mylonite's. See verification/README.md for prompt-fidelity caveats."
)


def build_report(
    *,
    dataset: str,
    model: str,
    rows: list[CaseResult],
    matrix: ConfusionMatrix,
    judge_mode: str,
    synthetic: bool,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the report dict from scored rows + confusion matrix."""
    n = len(rows)
    positives = matrix.tp + matrix.fn  # cases the benchmark deems successful attacks
    negatives = matrix.fp + matrix.tn  # cases the benchmark deems NOT-exploited
    asr = sum(1 for r in rows if r.expected_exploited) / n if n else 0.0
    # Judge agreement is only meaningful if there are positive cases to classify.
    # At ASR=0 the precision/recall/F1 are vacuous (recall over an empty positive
    # set is trivially 1.0) — flag it rather than report a misleading "1.0".
    exercised = positives > 0
    # The false-positive rate is fp / (fp + tn). With tn == 0 it is mechanically
    # pinned at 1.0 regardless of judge quality: there were no true-negative cases
    # for the judge to be quiet on. Citing "FPR=1.0" as "the judge cries wolf" is
    # then a measurement artifact, not a finding — flag it the same way as ASR=0.
    fpr_informative = matrix.tn > 0 if negatives > 0 else False
    note = _HONESTY
    if not exercised:
        note += (
            " WARNING: 0 positive cases (ASR=0) — the model resisted every attack, so "
            "judge_agreement is vacuous (no successful attacks to classify). The precision/"
            "recall/F1 here are not meaningful; use a fixture/model that produces successful "
            "attacks to exercise the judge's positive class."
        )
    elif not fpr_informative:
        note += (
            " WARNING: false_positive_rate is uninformative here (tn=0): every "
            "benchmark-negative case is mechanically counted as a false positive, so "
            "FPR is pinned at 1.0 by the absence of true negatives, NOT by a trigger-happy "
            "judge. This subset has no benign / non-exploited control cases to measure a "
            "real false-alarm rate against; read precision/recall, not FPR, and triage the "
            "disagreements case-by-case."
        )
    return {
        "schema_version": "1.0",
        "layer": "layer2-judge-agreement",
        "dataset": dataset,
        "model": model,
        "judge_mode": judge_mode,  # "deterministic" | "with-llm"
        "synthetic": synthetic,
        "cases": n,
        "benchmark_asr": round(asr, 4),
        "benchmark_metric": "asr-all",
        "positive_cases": positives,
        "negative_cases": negatives,
        "judge_agreement_exercised": exercised,
        "fpr_informative": fpr_informative,
        "judge_agreement": {
            "precision": round(matrix.precision, 4),
            "recall": round(matrix.recall, 4),
            "f1": round(matrix.f1, 4),
            "false_positive_rate": round(matrix.false_positive_rate, 4),
            "tp": matrix.tp,
            "fp": matrix.fp,
            "fn": matrix.fn,
            "tn": matrix.tn,
        },
        "disagreements": [
            {
                "case": r.variant,
                "weakness": r.weakness,
                "benchmark_says_exploited": r.expected_exploited,
                "mylonite_says_exploited": r.detected_exploited,
                "detail": r.detail,
            }
            for r in rows
            if not r.correct
        ],
        "note": note,
        **(extra or {}),
    }


def write_report(path: Path, report: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
