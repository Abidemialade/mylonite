"""`build_e2e_results.py` re-scores the end-to-end campaign's local run
artifacts and applies each cell's own pass bar from
`verification/PREREG_E2E_2026_10.md`. These are pure unit tests on the
bar-arithmetic and adjudication-lookup helpers -- no filesystem, no network,
no LLM call, and no dependency on the local, gitignored campaign artifacts
this script reads at build time."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build_e2e_results as builder


def _run(classification: str, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "classification": classification,
        "label": None,
        "proof_level": None,
        "calibration_status": None,
        "reason_codes": [],
        "exercised": True,
    }
    base.update(over)
    return base


class TestEffectConfirmedProofDepth:
    """Integrity rule 7: a proof-depth cell's bar needs KEPT at
    `effect-confirmed` under a `certified` calibration -- a plain KEPT
    rollup is not enough."""

    def test_not_met_when_calibration_is_confirm_only(self) -> None:
        by_provider = {
            "anthropic": [
                _run(
                    "KEPT", proof_level="dispatched-tool-linked", calibration_status="confirm_only"
                )
                for _ in range(3)
            ],
            "openai": [
                _run(
                    "KEPT", proof_level="dispatched-tool-linked", calibration_status="confirm_only"
                )
                for _ in range(3)
            ],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        _, met_bar = builder._apply_cell_bar(
            "effect_confirmed_proof_depth", {}, by_provider, cell_runs
        )
        assert met_bar is False

    def test_met_when_two_of_three_runs_are_certified_and_effect_confirmed(self) -> None:
        certified = _run("KEPT", proof_level="effect-confirmed", calibration_status="certified")
        dispatched = _run(
            "KEPT", proof_level="dispatched-tool-linked", calibration_status="certified"
        )
        by_provider = {
            "anthropic": [certified, certified, dispatched],
            "openai": [certified, certified, dispatched],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        provider_results, met_bar = builder._apply_cell_bar(
            "effect_confirmed_proof_depth", {}, by_provider, cell_runs
        )
        assert met_bar is True
        assert provider_results["anthropic"]["effect_confirmed_certified_count"] == 2

    def test_not_met_when_only_one_provider_qualifies(self) -> None:
        certified = _run("KEPT", proof_level="effect-confirmed", calibration_status="certified")
        confirm_only = _run(
            "KEPT", proof_level="dispatched-tool-linked", calibration_status="confirm_only"
        )
        by_provider = {
            "anthropic": [certified, certified, certified],
            "openai": [confirm_only, confirm_only, confirm_only],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        _, met_bar = builder._apply_cell_bar(
            "effect_confirmed_proof_depth", {}, by_provider, cell_runs
        )
        # The bar is "per provider" -- both must clear it.
        assert met_bar is False


class TestLabelThresholdBothProviders:
    """Fix re-test 2's bar counts the verdict LABEL (`STABLE, NOT PROVEN`),
    not the broader NOT_KEPT classification a plain REJECTED also has."""

    def test_rejected_never_counts_as_the_candidate_label(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_KEPT", label=None) for _ in range(3)],
            "openai": [
                _run("NOT_KEPT", label="REJECTED"),
                _run("NOT_KEPT", label="STABLE, NOT PROVEN"),
                _run("NOT_KEPT", label=None),
            ],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        meta = {"label": "STABLE, NOT PROVEN", "threshold": 2}
        provider_results, met_bar = builder._apply_cell_bar(
            "label_threshold_both_providers", meta, by_provider, cell_runs
        )
        assert met_bar is False
        assert provider_results["openai"]["met_bar"] is False

    def test_met_when_both_providers_reach_the_threshold(self) -> None:
        candidate = _run("NOT_KEPT", label="STABLE, NOT PROVEN")
        by_provider = {
            "anthropic": [candidate, candidate, _run("NOT_KEPT", label=None)],
            "openai": [candidate, candidate, candidate],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        meta = {"label": "STABLE, NOT PROVEN", "threshold": 2}
        _, met_bar = builder._apply_cell_bar(
            "label_threshold_both_providers", meta, by_provider, cell_runs
        )
        assert met_bar is True


class TestKeptThresholdAnyProvider:
    """Breadth 1's bar is a bare KEPT-count threshold across a cell that
    grew past a fixed N=3 (a ceiling amendment raised it to 12 runs), met
    on at least one provider -- not a fixed-N rollup."""

    def test_not_met_with_zero_kept_across_twelve_runs(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_KEPT") for _ in range(6)],
            "openai": [_run("NOT_KEPT") for _ in range(6)],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        _, met_bar = builder._apply_cell_bar(
            "kept_threshold_any_provider", {"threshold": 2}, by_provider, cell_runs
        )
        assert met_bar is False

    def test_met_when_one_provider_alone_clears_the_threshold(self) -> None:
        by_provider = {
            "anthropic": [_run("KEPT"), _run("KEPT"), _run("NOT_KEPT")],
            "openai": [_run("NOT_KEPT"), _run("NOT_KEPT"), _run("NOT_KEPT")],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        provider_results, met_bar = builder._apply_cell_bar(
            "kept_threshold_any_provider", {"threshold": 2}, by_provider, cell_runs
        )
        assert met_bar is True
        assert provider_results["openai"]["met_bar"] is False


class TestHonestEitherWay:
    """Breadth 2's bar has no failing outcome -- it is met as soon as every
    dispatched run is actually published, landed or not."""

    def test_met_whenever_any_runs_exist(self) -> None:
        by_provider = {"anthropic": [_run("NOT_KEPT")], "openai": [_run("KEPT")]}
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        provider_results, met_bar = builder._apply_cell_bar(
            "honest_either_way", {}, by_provider, cell_runs
        )
        assert met_bar is True
        assert provider_results["openai"]["classifications"] == ["KEPT"]

    def test_not_met_on_an_empty_cell(self) -> None:
        _, met_bar = builder._apply_cell_bar("honest_either_way", {}, {}, [])
        assert met_bar is False


class TestClassificationRollupBothProviders:
    """The generic N=3, >=2/3 classification-agreement rule, required on
    EACH provider independently."""

    def test_not_met_when_only_one_provider_reaches_consensus(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_TESTED", reason_codes=["MYL-NT-005"]) for _ in range(3)],
            "openai": [
                _run("NOT_TESTED", reason_codes=["MYL-NT-005"]),
                _run("KEPT"),
                _run("NOT_KEPT"),
            ],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        meta = {"bar_numerator": 2, "bar_denominator": 3}
        _, met_bar = builder._apply_cell_bar(
            "classification_rollup_both_providers", meta, by_provider, cell_runs
        )
        assert met_bar is False

    def test_met_when_both_providers_agree(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_TESTED", reason_codes=["MYL-NT-005"]) for _ in range(3)],
            "openai": [_run("NOT_TESTED", reason_codes=["MYL-NT-005"]) for _ in range(3)],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        meta = {"bar_numerator": 2, "bar_denominator": 3}
        _, met_bar = builder._apply_cell_bar(
            "classification_rollup_both_providers", meta, by_provider, cell_runs
        )
        assert met_bar is True


class TestPrecisionKind:
    def test_inconclusive_when_any_run_is_unexercised(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_TESTED", exercised=False)]
            + [_run("NOT_KEPT") for _ in range(2)],
            "openai": [_run("NOT_KEPT") for _ in range(3)],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        provider_results, met_bar = builder._apply_cell_bar("precision", {}, by_provider, cell_runs)
        assert met_bar is False
        assert provider_results["anthropic"]["result"] == "INCONCLUSIVE"

    def test_pass_when_every_run_exercised_and_zero_kept(self) -> None:
        by_provider = {
            "anthropic": [_run("NOT_KEPT") for _ in range(3)],
            "openai": [_run("NOT_KEPT") for _ in range(3)],
        }
        cell_runs = by_provider["anthropic"] + by_provider["openai"]
        _, met_bar = builder._apply_cell_bar("precision", {}, by_provider, cell_runs)
        assert met_bar is True


class TestAdjudicate:
    """Every KEPT run's adjudication is looked up from the validated
    finding's own pattern_id in `scan_findings` -- never guessed from the
    target name alone."""

    def test_known_pattern_reads_true_positive_with_a_grounded_reason(self) -> None:
        entry = {
            "target": "tpv-server-memory",
            "scan_findings": [
                {"pattern_id": "synth-w4-unconfirmed-delete_entities", "validated": True}
            ],
        }
        result = builder._adjudicate(entry)
        assert result["status"] == "true_positive"
        assert "delete_entities" in result["reason"]

    def test_no_validated_finding_is_unadjudicated_not_fabricated(self) -> None:
        entry = {"target": "tpv-server-memory", "scan_findings": []}
        result = builder._adjudicate(entry)
        assert result["status"] == "unadjudicated"
        assert result["reason"]

    def test_unknown_pattern_is_unadjudicated_not_fabricated(self) -> None:
        entry = {
            "target": "some-new-target",
            "scan_findings": [{"pattern_id": "synth-w4-something-new", "validated": True}],
        }
        result = builder._adjudicate(entry)
        assert result["status"] == "unadjudicated"
        assert result["reason"]


class TestShortSha:
    def test_shortens_a_full_length_hex_sha(self) -> None:
        full = "0" * 40  # a synthetic, all-zero 40-hex-char SHA shape
        assert builder._short_sha(full) == "00000000"

    def test_passes_through_none_and_short_refs(self) -> None:
        assert builder._short_sha(None) is None
        assert builder._short_sha("already-short") == "already-short"


class TestLongPath:
    def test_no_op_off_windows(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert builder._long_path(tmp_path) == tmp_path

    def test_prefixes_once_on_windows(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        prefix = chr(92) * 2 + "?" + chr(92)
        once = builder._long_path(tmp_path)
        assert str(once).startswith(prefix)
        # Idempotent: prefixing an already-prefixed path must not double it.
        twice = builder._long_path(once)
        assert str(twice) == str(once)


class TestValidatedEffectProofLevel:
    """validate's own "effect" gating-leg counts are a different axis from
    the scan attempt's own `proof_level` -- read from `validation_report.json`
    directly, never inferred from the scan-level field."""

    def _write_report(self, tmp_path: Path, detail: str) -> Path:
        report = {
            "outcomes": [
                {"stage": "stability", "detail": "irrelevant"},
                {"stage": "effect", "detail": detail},
            ]
        }
        (tmp_path / "validation_report.json").write_text(json.dumps(report), encoding="utf-8")
        return tmp_path

    def test_effect_confirmed_wins_when_present(self, tmp_path: Path) -> None:
        run_dir = self._write_report(
            tmp_path,
            "3/3 runs showed the damage (need >= 2), by proof level: 3 effect-confirmed, "
            "0 dispatched, 0 dispatched-tool-linked",
        )
        level, counts = builder._validated_effect_proof_level(run_dir)
        assert level == "effect-confirmed"
        assert counts == {"effect_confirmed": 3, "dispatched": 0, "dispatched_tool_linked": 0}

    def test_dispatched_tool_linked_when_zero_effect_confirmed(self, tmp_path: Path) -> None:
        run_dir = self._write_report(
            tmp_path,
            "3/3 runs showed the damage (need >= 2), by proof level: 0 effect-confirmed, "
            "0 dispatched, 3 dispatched-tool-linked",
        )
        level, counts = builder._validated_effect_proof_level(run_dir)
        assert level == "dispatched-tool-linked"
        assert counts is not None and counts["dispatched_tool_linked"] == 3

    def test_no_report_reads_none(self, tmp_path: Path) -> None:
        assert builder._validated_effect_proof_level(tmp_path) == (None, None)

    def test_no_effect_outcome_reads_none(self, tmp_path: Path) -> None:
        report = {"outcomes": [{"stage": "stability", "detail": "x"}]}
        (tmp_path / "validation_report.json").write_text(json.dumps(report), encoding="utf-8")
        assert builder._validated_effect_proof_level(tmp_path) == (None, None)


class TestCeilingFloorCalls:
    """A validate leg that aborts at its own request ceiling never prints its
    own `llm: N calls` summary, so cost.json undercounts by exactly the
    ceiling value -- a known floor, not an estimate."""

    def test_ceiling_hit_with_one_spend_line_returns_the_ceiling(self) -> None:
        text = (
            "Estimated LLM calls for this validation: 12-36\n"
            "llm: 17 calls (judge 1, planner 16) of 60 cap\n"
            "LLMRequestCeilingError: LLM request ceiling of 40 reached\n"
        )
        assert builder._ceiling_floor_calls(text) == 40

    def test_no_ceiling_hit_returns_zero(self) -> None:
        text = "Estimated LLM calls for this validation: 12-36\nllm: 20 calls (judge 2, planner 18) of 40 cap\n"
        assert builder._ceiling_floor_calls(text) == 0

    def test_validate_never_started_returns_zero(self) -> None:
        text = "llm: 17 calls (judge 1, planner 16) of 60 cap\nceiling of 40 reached\n"
        assert builder._ceiling_floor_calls(text) == 0

    def test_two_spend_lines_means_nothing_missing(self) -> None:
        text = (
            "Estimated LLM calls for this validation: 12-36\n"
            "llm: 17 calls (judge 1, planner 16) of 60 cap\n"
            "ceiling of 40 reached\n"
            "llm: 40 calls (judge 2, planner 38) of 40 cap\n"
        )
        assert builder._ceiling_floor_calls(text) == 0


class TestCellRounds:
    """Every non-void round is published, labelled with the fix that ended
    it -- a superseded round is never dropped just because a later round
    replaced it."""

    def _run(self, run_id: str, cell: str, classification: str) -> dict[str, object]:
        return {
            "run_id": run_id,
            "cell": cell,
            "status": "superseded" if run_id.startswith("e2e-batch2") else "active",
            "classification": classification,
        }

    def test_groups_two_batches_under_one_round_label(self) -> None:
        runs = [
            self._run("e2e-batch2/tpv-mcp-redis-anthropic-1", "proof_depth_2", "KEPT"),
            self._run("e2e-batch3/tpv-mcp-redis-openai-3r", "proof_depth_2", "KEPT"),
        ]
        rounds = builder._cell_rounds(runs)
        assert len(rounds) == 1
        assert rounds[0]["n"] == 2
        assert rounds[0]["kept"] == 2

    def test_void_runs_are_excluded(self) -> None:
        runs = [
            {
                "run_id": "e2e-batch8/openai-1",
                "cell": "proof_depth_2",
                "status": "void",
                "classification": "KEPT",
            }
        ]
        assert builder._cell_rounds(runs) == []

    def test_unlabelled_batch_falls_back_to_counted(self) -> None:
        runs = [self._run("e2e-batch99/some-run", "fix_retest_1", "NOT_TESTED")]
        rounds = builder._cell_rounds(runs)
        assert rounds[0]["label"] == "counted"


# --- a shared-state sweep flagged two unenforced "exactly one candidate"
# invariants: `_resolve_dirs`'s `out/` child and `_score_one`'s inner run
# directory were both picked via an unchecked `children[0]`, so a stray
# second candidate (a duplicate download, a leftover scan dir) would be
# silently picked or dropped rather than failing loudly. Zero candidates is
# unchanged in both; more than one now raises, naming the folder and every
# candidate.


class TestResolveDirsCandidateCount:
    def test_single_scan_dir_candidate_is_used(self, tmp_path: Path) -> None:
        inner = tmp_path
        scan_child = inner / "out" / "2026-01-01T00-00-00Z"
        scan_child.mkdir(parents=True)
        run_dir, scan_dir = builder._resolve_dirs(inner)
        assert scan_dir == scan_child
        # No `generated/` at all -- falls back to the scan directory itself.
        assert run_dir == scan_child

    def test_two_scan_dir_candidates_raises(self, tmp_path: Path) -> None:
        inner = tmp_path
        (inner / "out" / "2026-01-01T00-00-00Z").mkdir(parents=True)
        (inner / "out" / "2026-01-02T00-00-00Z").mkdir(parents=True)
        with pytest.raises(RuntimeError, match="expected at most one scan output directory"):
            builder._resolve_dirs(inner)

    def test_zero_scan_dir_candidates_is_unchanged(self, tmp_path: Path) -> None:
        inner = tmp_path
        (inner / "out").mkdir()
        run_dir, scan_dir = builder._resolve_dirs(inner)
        assert scan_dir is None
        # Preflight-failure fallback: run_dir is `inner` itself.
        assert run_dir == inner

    def test_multi_report_layout_under_generated_is_detected(self, tmp_path: Path) -> None:
        """The new per-exploit `generated/<stem>/` shape (one subdirectory
        per validated exploit) must still resolve `run_dir` to `generated`
        -- unaffected by the candidate-count check above, which only
        applies to `out/`'s own children."""
        inner = tmp_path
        scan_child = inner / "out" / "2026-01-01T00-00-00Z"
        scan_child.mkdir(parents=True)
        sub = inner / "generated" / "create_relations"
        sub.mkdir(parents=True)
        (sub / "validation_report.json").write_text("{}", encoding="utf-8")
        run_dir, scan_dir = builder._resolve_dirs(inner)
        assert run_dir == inner / "generated"
        assert scan_dir == scan_child


class TestScoreOneCandidateCount:
    def test_single_inner_candidate_succeeds(self, tmp_path: Path) -> None:
        batch_dir = tmp_path / "e2e-batch1" / "folder"
        (batch_dir / "run123").mkdir(parents=True)
        result = builder._score_one(tmp_path, "e2e-batch1", "folder", "my-target", None)
        assert result["target"] == "my-target"

    def test_two_inner_candidates_raises(self, tmp_path: Path) -> None:
        batch_dir = tmp_path / "e2e-batch1" / "folder"
        (batch_dir / "run-a").mkdir(parents=True)
        (batch_dir / "run-b").mkdir(parents=True)
        with pytest.raises(RuntimeError, match="expected exactly one inner run directory"):
            builder._score_one(tmp_path, "e2e-batch1", "folder", "my-target", None)

    def test_zero_inner_candidates_is_unchanged(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            builder._score_one(tmp_path, "e2e-batch1", "folder", "my-target", None)
