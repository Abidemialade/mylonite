"""Layer 3 (precision / false-positive control) scorer tests — hermetic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
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


def test_precision_report_survives_a_null_verdict_reason(tmp_path: Path) -> None:
    """DCR-0015: ``verdict_reason`` is schema-legal ``null``. The unguarded
    ``a.get("verdict_reason", "")[:200]`` only substitutes the default when the
    KEY is absent, not when it's present with value ``None`` — so a null
    reason on a FINDING (the branch that slices it a second time for the
    false-positive detail) crashed with ``TypeError: 'NoneType' object is not
    subscriptable``.
    """
    attempts = [
        {"pattern_id": "p1", "outcome": "finding", "verdict_reason": None},
    ]
    rep = layer3_run.precision_report(_scan_report(tmp_path, attempts))
    assert rep["false_positives"] == 1
    assert rep["false_positive_detail"][0]["reason"] == ""


def test_load_scan_report_picks_the_most_recent_of_several_and_warns(
    tmp_path: Path, caplog
) -> None:
    """#41: multiple ``scan_report.json`` files under the scan dir (e.g. two
    timestamped runs written to the same output root) must resolve to the
    MOST RECENT one, not whichever ``rglob`` happens to yield first — and the
    ambiguity must be logged, not silent.
    """
    old_dir = tmp_path / "2020-01-01T00-00-00Z"
    new_dir = tmp_path / "2030-01-01T00-00-00Z"
    old_dir.mkdir()
    new_dir.mkdir()
    (old_dir / "scan_report.json").write_text(
        json.dumps({"target_id": "old", "attempts": []}), encoding="utf-8"
    )
    (new_dir / "scan_report.json").write_text(
        json.dumps({"target_id": "new", "attempts": []}), encoding="utf-8"
    )
    with caplog.at_level("WARNING", logger="verification.layer3_production.run"):
        report = layer3_run._load_scan_report(tmp_path)
    assert report["target_id"] == "new"
    assert any("multiple" in r.message.lower() for r in caplog.records)


def test_load_scan_report_raises_on_a_non_mapping_json_body(tmp_path: Path) -> None:
    """DCR-0014: a ``scan_report.json`` that parses but isn't a JSON object
    (e.g. an array, or ``null``) must raise HERE, not silently fall back to
    ``attempts = []`` deep in ``precision_report`` — which would fabricate a
    clean (0 false positives) report from a malformed file.
    """
    d = tmp_path / "scan"
    d.mkdir()
    (d / "scan_report.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ValueError, match=r"scan_report\.json"):
        layer3_run._load_scan_report(d)
