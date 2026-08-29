"""Guards for the campaign orchestrator.

The campaign is the one place that decides what a committed result set contains,
so its failure modes are all "a wrong file exists and looks authoritative"
rather than "something crashed". These pin the properties that keep a committed
result honest.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification._sanitise import FieldNotAllowed

from verification import campaign, trends


def test_result_filenames_agree_with_the_trend_renderer() -> None:
    """A rename in one module must not silently orphan the other.

    ``campaign`` writes these files and ``trends`` reads them. Nothing else
    connects the two, so a rename on either side would produce a trend table
    quietly full of ``error`` cells against result files that are perfectly fine.
    Two agents building these independently already disagreed once, which is why
    this exists.
    """
    assert campaign.LAYER_FILES == trends._LAYER_FILES


def test_refuses_to_clobber_an_existing_result_set(tmp_path: Path) -> None:
    """Re-running without --force must not mix two measurements under one stamp."""
    existing = tmp_path / "0.9.0"
    existing.mkdir(parents=True)
    (existing / "meta.json").write_text("{}", encoding="utf-8")

    with pytest.raises(campaign.CampaignError, match="already holds a result set"):
        campaign.prepare_results_dir(tmp_path, "0.9.0", force=False)

    # --force is the deliberate escape hatch, not the default.
    assert campaign.prepare_results_dir(tmp_path, "0.9.0", force=True) == existing


def test_an_empty_directory_is_not_treated_as_an_existing_set(tmp_path: Path) -> None:
    (tmp_path / "0.9.0").mkdir(parents=True)
    assert campaign.prepare_results_dir(tmp_path, "0.9.0", force=False).exists()


def test_a_local_path_in_a_report_is_scrubbed_before_it_lands(tmp_path: Path) -> None:
    """The whole point: local-machine detail must not reach a committed file."""
    results_dir = tmp_path / "0.9.0"
    results_dir.mkdir(parents=True)
    source = tmp_path / "layer1.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layer": "layer1-recall",
                "target": "dvmcp",
                "in_scope_challenges": 1,
                "recall": 0.5,
                "found": 1,
                "missed": 1,
                "per_challenge": [
                    {
                        "challenge": "c1",
                        "weakness": "W3",
                        "found": True,
                        # Both leak shapes the real harness can emit.
                        "detail": "fetched http://127.0.0.1:9001/x from C:\\Users\\somebody\\dvmcp",
                    }
                ],
                "note": "n",
            }
        ),
        encoding="utf-8",
    )

    campaign.fold_in_prebuilt(results_dir, "layer1", source)

    written = (results_dir / "layer1-recall.json").read_text(encoding="utf-8")
    assert "127.0.0.1" not in written
    assert "somebody" not in written
    assert "Users" not in written
    assert "<path>" in written or "<host>" in written


def test_an_unvetted_field_cannot_reach_disk(tmp_path: Path) -> None:
    """``build_report`` ends with ``**(extra or {})``, so callers CAN inject keys.

    The allowlist is what stops an injected field from being committed before a
    human has looked at whether it carries local-machine content.
    """
    results_dir = tmp_path / "0.9.0"
    results_dir.mkdir(parents=True)
    source = tmp_path / "layer3.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layer": "layer3-precision",
                "target": "reference:guarded",
                "completed_probes": 4,
                "false_positives": 0,
                "true_negatives": 4,
                "false_positive_rate": 0.0,
                "false_positive_detail": [],
                "note": "n",
                "scan_output_dir": "/home/someone/scans/run-1",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(FieldNotAllowed, match="scan_output_dir"):
        campaign.fold_in_prebuilt(results_dir, "layer3", source)

    assert not (results_dir / "layer3-precision.json").exists(), (
        "a rejected report must leave nothing behind; a partially-written file "
        "could be committed by an unlucky `git add`"
    )


def test_a_missing_prebuilt_report_is_an_error_not_a_silent_not_run(tmp_path: Path) -> None:
    results_dir = tmp_path / "0.9.0"
    results_dir.mkdir(parents=True)
    with pytest.raises(campaign.CampaignError, match="could not read"):
        campaign.fold_in_prebuilt(results_dir, "layer1", tmp_path / "absent.json")


def test_finalise_records_a_skipped_layer_and_validates(tmp_path: Path) -> None:
    """A layer that did not run is present and says so -- never absent, never 0."""
    results_dir = tmp_path / "0.9.0"
    results_dir.mkdir(parents=True)

    campaign.finalise(
        results_dir,
        version="0.9.0",
        model="anthropic/claude-haiku-4-5-20251001",
        layers={"layer1": "not-run", "layer2-agentdojo": "ran", "layer3": "not-run"},
        harness_sha="abc1234",
    )

    meta = json.loads((results_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["layers"] == {
        "layer1": "not-run",
        "layer2-agentdojo": "ran",
        "layer3": "not-run",
    }
    assert meta["mylonite_version"] == "0.9.0"
    assert meta["git_sha"]
    assert meta["harness_sha"] == "abc1234"
