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


def test_another_result_set_in_the_version_directory_is_not_this_campaigns(
    tmp_path: Path,
) -> None:
    """A sibling result set (its own subdirectory) never blocks the campaign."""
    other = tmp_path / "0.9.0" / "third-party"
    other.mkdir(parents=True)
    (other / "README.md").write_text("other campaign", encoding="utf-8")
    assert campaign.prepare_results_dir(tmp_path, "0.9.0", force=False).exists()
    assert (other / "README.md").read_text(encoding="utf-8") == "other campaign"


def test_a_layer_file_alone_still_counts_as_an_existing_set(tmp_path: Path) -> None:
    existing = tmp_path / "0.9.0"
    existing.mkdir(parents=True)
    (existing / campaign.LAYER_FILES["layer2-agentdojo"]).write_text("{}", encoding="utf-8")
    with pytest.raises(campaign.CampaignError, match="already holds a result set"):
        campaign.prepare_results_dir(tmp_path, "0.9.0", force=False)


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


def test_measured_sha_resolves_the_release_tag_not_head(monkeypatch: pytest.MonkeyPatch) -> None:
    """``git_sha`` must name the tag that built the measured wheel, not HEAD.

    A campaign can only run AFTER the tag is published (the silo needs an
    installed artifact), so HEAD has usually moved on -- frequently onto the
    verification work itself. An earlier version read HEAD for both fields, which
    made them always identical and quietly reduced "distinguish the tool from the
    scorer" to a claim the data could not support.
    """
    calls: list[str] = []

    def fake_rev_parse(rev: str) -> str:
        calls.append(rev)
        return "tagsha1" if rev.startswith("v0.9.0") else "headsha"

    monkeypatch.setattr(campaign, "_rev_parse", fake_rev_parse)
    assert campaign.measured_sha("0.9.0") == "tagsha1"
    assert calls == ["v0.9.0^{}"], "must ask for the tag's COMMIT, not the tag object"


def test_measured_sha_falls_back_to_head_when_the_tag_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unfetched tag costs precision, never the whole campaign.

    The fields going equal is then itself the signal that the tag was not found.
    """
    monkeypatch.setattr(
        campaign, "_rev_parse", lambda rev: "unknown" if rev.startswith("v") else "headsha"
    )
    assert campaign.measured_sha("0.9.0") == "headsha"


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


# --- the command line the release workflow runs ------------------------------


def _layer2_report(tmp_path: Path, name: str) -> Path:
    """A scored layer-2 report shaped like ``runner score`` output."""
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layer": "layer2-judge-agreement",
                "dataset": "injecagent",
                "model": "",
                "cases": 2,
                "positive_cases": 1,
                "negative_cases": 1,
                "benchmark_asr": 0.5,
                "benchmark_metric": "asr-all",
                "judge_mode": "deterministic",
                "judge_agreement_exercised": True,
                "fpr_informative": True,
                "judge_agreement": {"tp": 1, "fp": 0, "fn": 0, "tn": 1},
                "disagreements": [],
                "synthetic": False,
                "note": "n",
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def _siloed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stand in for an installed wheel; record the versions the silo was asked about."""
    asked: list[str] = []
    monkeypatch.setattr(
        campaign, "assert_siloed", lambda expected_version: asked.append(expected_version)
    )
    monkeypatch.setattr(campaign, "_rev_parse", lambda rev: "abc1234")
    return asked


def test_cli_folds_in_reports_and_records_the_rest_as_not_run(
    tmp_path: Path, _siloed: list[str]
) -> None:
    """The three core layers land as 'ran'; layers not passed are present as 'not-run'."""
    root = tmp_path / "results"
    argv = ["--mylonite-version", "0.11.0", "--model", "anthropic/m", "--results-root", str(root)]
    for layer in ("layer2-agentdojo", "layer2-injecagent-dh", "layer2-injecagent-ds"):
        argv += ["--report", f"{layer}={_layer2_report(tmp_path, layer + '.json')}"]

    assert campaign.main(argv) == 0

    assert _siloed == ["0.11.0"], "the silo must be asserted against the filed version"
    meta = json.loads((root / "0.11.0" / "meta.json").read_text(encoding="utf-8"))
    assert meta["layers"] == {
        "layer1": "not-run",
        "layer2-agentdojo": "ran",
        "layer2-injecagent-dh": "ran",
        "layer2-injecagent-ds": "ran",
        "layer3": "not-run",
    }
    assert meta["model"] == "anthropic/m"
    for layer in ("layer2-agentdojo", "layer2-injecagent-dh", "layer2-injecagent-ds"):
        assert (root / "0.11.0" / campaign.LAYER_FILES[layer]).is_file()


def test_cli_writes_nothing_when_the_silo_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A working-tree import must stop the run before any result file exists."""

    def refuse(expected_version: str) -> None:
        raise campaign.SiloViolation("imported from the working tree")

    monkeypatch.setattr(campaign, "assert_siloed", refuse)
    root = tmp_path / "results"
    report = _layer2_report(tmp_path, "dh.json")
    argv = ["--mylonite-version", "0.11.0", "--model", "m", "--results-root", str(root)]
    argv += ["--report", f"layer2-injecagent-dh={report}"]

    assert campaign.main(argv) == 2
    assert not root.exists()
    assert "working tree" in capsys.readouterr().err


def test_cli_silo_only_checks_and_writes_nothing(tmp_path: Path, _siloed: list[str]) -> None:
    root = tmp_path / "results"
    argv = ["--mylonite-version", "0.11.0", "--model", "m", "--results-root", str(root)]
    assert campaign.main([*argv, "--silo-only"]) == 0
    assert _siloed == ["0.11.0"]
    assert not root.exists()


def test_cli_refuses_a_report_for_an_unknown_layer(tmp_path: Path, _siloed: list[str]) -> None:
    argv = ["--mylonite-version", "0.11.0", "--model", "m", "--results-root", str(tmp_path)]
    with pytest.raises(SystemExit):
        campaign.main([*argv, "--report", "layer9=x.json"])


def test_cli_refuses_the_same_layer_twice(
    tmp_path: Path, _siloed: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Two reports for one layer would leave the second silently overwriting the first."""
    root = tmp_path / "results"
    report = _layer2_report(tmp_path, "dh.json")
    argv = ["--mylonite-version", "0.11.0", "--model", "m", "--results-root", str(root)]
    argv += ["--report", f"layer2-injecagent-dh={report}"] * 2

    assert campaign.main(argv) == 2
    assert not (root / "0.11.0" / "meta.json").exists()
    assert "more than once" in capsys.readouterr().err


def test_cli_leaves_no_meta_when_a_report_is_missing(tmp_path: Path, _siloed: list[str]) -> None:
    """A half-built set has no meta.json, which the freshness gate reads as absent."""
    root = tmp_path / "results"
    argv = ["--mylonite-version", "0.11.0", "--model", "m", "--results-root", str(root)]
    argv += ["--report", f"layer2-agentdojo={tmp_path / 'absent.json'}"]

    assert campaign.main(argv) == 2
    assert not (root / "0.11.0" / "meta.json").exists()
