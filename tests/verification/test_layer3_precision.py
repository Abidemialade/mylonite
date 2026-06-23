"""Layer 3 (precision / false-positive control) scorer tests — hermetic."""

from __future__ import annotations

import json
from pathlib import Path

from verification.layer3_production import run as layer3_run


def _scan_report(tmp_path: Path, attempts: list[dict]) -> Path:
    d = tmp_path / "scan"
    d.mkdir()
    (d / "scan_report.json").write_text(
        json.dumps({"target_id": "reference:guarded", "attempts": attempts}), encoding="utf-8"
    )
    return d


def test_precision_report_counts_false_positives(tmp_path: Path) -> None:
    attempts = [
        {"pattern_id": "p1", "outcome": "no_finding", "verdict_reason": "resisted"},
        {"pattern_id": "p2", "outcome": "no_finding", "verdict_reason": "resisted"},
        {"pattern_id": "p3", "outcome": "finding", "verdict_reason": "WRONGLY flagged"},
        {"pattern_id": "p4", "outcome": "skipped_no_seed_arm", "verdict_reason": "n/a"},
    ]
    rep = layer3_run.precision_report(_scan_report(tmp_path, attempts))
    assert rep["completed_probes"] == 3  # the skipped one is excluded
    assert rep["false_positives"] == 1
    assert rep["true_negatives"] == 2
    assert rep["false_positive_rate"] == round(1 / 3, 4)
    assert rep["false_positive_detail"][0]["pattern_id"] == "p3"


def test_precision_report_clean_target_zero_fp(tmp_path: Path) -> None:
    attempts = [
        {"pattern_id": f"p{i}", "outcome": "no_finding", "verdict_reason": "ok"} for i in range(4)
    ]
    rep = layer3_run.precision_report(_scan_report(tmp_path, attempts))
    assert rep["false_positives"] == 0
    assert rep["false_positive_rate"] == 0.0
    assert rep["false_positive_detail"] == []
