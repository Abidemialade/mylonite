"""The per-class summary: FINDING / RESISTED / RESISTED (server-reported) / NOT TESTED.

The summary is computed from the report's own attempts (plus an optional
calibration summary), so ``mylonite report`` on a saved directory gives the
same result the scan printed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mylonite.contracts import ScanReport
from mylonite.contracts._types import ScanAttempt
from mylonite.scan import class_verdict as cv
from mylonite.scan.coverage import ScanOutcome

_FIXTURE_0_10_4 = Path(__file__).resolve().parents[1] / "fixtures" / "scan_report_0_10_4.json"

# One catalogue seed per class, so the class resolves from the seed id alone.
_W1 = "tool-description-send-licence-smuggle"
_W2 = "indirect-injection-note-body-direct"
_W3 = "excessive-agency-fetch-attacker-url-direct"
_W4 = "excessive-agency-send-email-direct-unconfirmed"
_W4_B = "excessive-agency-send-email-via-note-injection"


def _attempt(seed_id: str, outcome: str, **evidence: str) -> ScanAttempt:
    return ScanAttempt(
        seed_id=seed_id,
        pattern_id=seed_id,
        outcome=outcome,  # type: ignore[arg-type]
        verdict_mechanism="predicate" if outcome in ("finding", "no_finding") else None,
        verdict_reason="r",
        error_detail=None,
        judge_evidence=dict(evidence),
    )


def _report(*attempts: ScanAttempt) -> ScanReport:
    return ScanReport(
        target_id="mcp:custom",
        attack_modules=["m"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=list(attempts),
        findings_count=sum(1 for a in attempts if a.outcome == "finding"),
        mylonite_version="0.10.5",
    )


def _by_class(verdicts: tuple[cv.ClassVerdict, ...]) -> dict[str, cv.ClassVerdict]:
    return {v.weakness: v for v in verdicts}


# --- the four statuses ---------------------------------------------------------


def test_a_finding_in_a_class_makes_the_class_a_finding() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W4, "finding", trace_outcome="dispatched-ok", proof_level="dispatched"),
                _attempt(_W4_B, "undecided", fallback_cause="MYL-INC-001"),
            )
        )
    )
    w4 = verdicts["W4"]
    assert w4.status == cv.STATUS_FINDING
    assert w4.proof_levels == ("dispatched",)
    assert (w4.findings, w4.not_tested) == (1, 1)


def test_proof_levels_are_listed_strongest_first() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W4, "finding", proof_level="dispatched-tool-linked"),
                _attempt(_W4_B, "finding", proof_level="effect-confirmed"),
            )
        )
    )
    assert verdicts["W4"].proof_levels == ("effect-confirmed", "dispatched-tool-linked")


def test_resisted_on_the_trace_is_plain_resisted() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(_attempt(_W4, "no_finding", trace_outcome="not-called", negative_basis="trace"))
        )
    )
    assert verdicts["W4"].status == cv.STATUS_RESISTED
    assert verdicts["W4"].codes == ()


def test_a_server_reported_negative_labels_the_class() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W4, "no_finding", negative_basis="trace"),
                _attempt(
                    _W4_B,
                    "no_finding",
                    trace_outcome="dispatched-error",
                    negative_basis="server-reported",
                    reason_code="MYL-SRV-001",
                ),
            )
        )
    )
    w4 = verdicts["W4"]
    assert w4.status == cv.STATUS_RESISTED_SERVER_REPORTED
    assert w4.codes == ("MYL-SRV-001",)
    assert w4.server_reported == 1


def test_any_untested_attempt_makes_an_unfound_class_not_tested() -> None:
    """A class is resisted only when every attempt in it was decided: one
    untested attempt means part of the class proved nothing."""
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W4, "no_finding", negative_basis="trace"),
                _attempt(_W4_B, "undecided", fallback_cause="MYL-INC-008"),
            )
        )
    )
    w4 = verdicts["W4"]
    assert w4.status == cv.STATUS_NOT_TESTED
    assert w4.codes == ("MYL-INC-008",)
    assert (w4.resisted, w4.not_tested) == (1, 1)


def test_not_tested_codes_come_from_the_cause_buckets() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(_attempt(_W2, "skipped_no_seed_arm"), _attempt(_W3, "not_applicable"))
        )
    )
    assert verdicts["W2"].codes == ("MYL-NT-005",)
    assert verdicts["W3"].codes == ("MYL-NT-004",)


def test_dry_run_attempts_make_no_class() -> None:
    assert cv.class_verdicts(_report(_attempt(_W4, "skipped_dry_run"))) == ()


def test_classes_are_ordered_by_name() -> None:
    verdicts = cv.class_verdicts(
        _report(_attempt(_W4, "finding"), _attempt(_W1, "no_finding"), _attempt(_W2, "finding"))
    )
    assert [v.weakness for v in verdicts] == ["W1", "W2", "W4"]


# --- resolving an attempt's class ------------------------------------------------


@pytest.mark.parametrize(
    ("seed_id", "weakness"),
    [
        (_W2, "W2"),
        ("synth-w4-unconfirmed-write_file", "W4"),
        ("synth-w1-rug-pull", "W1"),
        ("synth-w3-egress-fetch", "W3"),
        ("somebody-elses-seed", cv.UNKNOWN_CLASS),
    ],
)
def test_an_attempts_class_comes_from_its_seed_id(seed_id: str, weakness: str) -> None:
    assert cv.weakness_of(_attempt(seed_id, "no_finding")) == weakness


def test_an_unknown_seed_takes_its_class_from_the_exploit() -> None:
    assert cv.weakness_of(_attempt("x-seed", "finding"), {"x-seed": "W3"}) == "W3"


# --- calibration -------------------------------------------------------------------


def _calibration(**overrides: object) -> cv.CalibrationSummary:
    fields: dict[str, object] = {
        "status": "failed",
        "reason_code": "MYL-INC-005",
        "seed_status": "failed",
        "seed_reason_code": "MYL-INC-006",
        "certified_tools": (),
    }
    fields.update(overrides)
    return cv.CalibrationSummary(**fields)  # type: ignore[arg-type]


def test_a_failed_calibration_names_its_code_on_an_uncalibrated_trace_class() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(
                    _W4,
                    "undecided",
                    trace_outcome="dispatched-ok",
                    calibrated="false",
                    fallback_cause="MYL-INC-001",
                )
            ),
            calibration=_calibration(),
        )
    )
    assert verdicts["W4"].codes == ("MYL-INC-001", "MYL-INC-005")
    assert verdicts["W4"].status == cv.STATUS_NOT_TESTED


def test_the_seed_control_code_lands_on_w2_only() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W2, "no_finding", trace_outcome="not-called", calibrated="true"),
                _attempt(_W4, "no_finding", trace_outcome="not-called", calibrated="true"),
            ),
            calibration=_calibration(status="certified", reason_code=None),
        )
    )
    assert verdicts["W2"].codes == ("MYL-INC-006",)
    assert verdicts["W4"].codes == ()


def test_calibration_codes_never_change_a_status_or_touch_a_finding() -> None:
    verdicts = _by_class(
        cv.class_verdicts(
            _report(
                _attempt(_W4, "finding", trace_outcome="dispatched-ok", calibrated="false"),
                _attempt(_W2, "no_finding", trace_outcome="not-called", calibrated="false"),
            ),
            calibration=_calibration(),
        )
    )
    assert verdicts["W4"].status == cv.STATUS_FINDING
    assert verdicts["W4"].codes == ()
    assert verdicts["W2"].status == cv.STATUS_RESISTED
    assert verdicts["W2"].codes == ("MYL-INC-005", "MYL-INC-006")


def test_calibration_does_not_reach_attempts_without_a_trace() -> None:
    verdicts = _by_class(
        cv.class_verdicts(_report(_attempt(_W4, "no_finding")), calibration=_calibration())
    )
    assert verdicts["W4"].codes == ()


def test_calibration_summary_round_trips_through_json() -> None:
    summary = _calibration(certified_tools=("write_file",))
    assert cv.CalibrationSummary.from_dict(json.loads(json.dumps(summary.to_dict()))) == summary


def test_calibration_summary_from_a_malformed_dict_is_none() -> None:
    assert cv.CalibrationSummary.from_dict({"status": 3}) is None
    assert cv.CalibrationSummary.from_dict("nope") is None


def test_every_emitted_code_is_registered() -> None:
    from mylonite.reason_codes import REGISTRY

    verdicts = cv.class_verdicts(
        _report(
            _attempt(_W2, "skipped_no_seed_arm"),
            _attempt(_W4, "undecided", fallback_cause="MYL-INC-001"),
            _attempt(
                _W3, "no_finding", negative_basis="server-reported", reason_code="MYL-SRV-002"
            ),
        ),
        calibration=_calibration(),
    )
    for verdict in verdicts:
        for code in verdict.codes:
            assert code in REGISTRY


# --- saved artefacts ------------------------------------------------------------------


def test_a_0_10_4_scan_report_loads_unchanged_and_keeps_todays_rules() -> None:
    raw = json.loads(_FIXTURE_0_10_4.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(raw)
    # Loads unchanged: nothing is added, dropped or rewritten on the way in.
    assert report.model_dump(mode="json") == raw
    # The coverage outcome and its exit code are today's.
    outcome = ScanOutcome.from_report(report)
    assert outcome.coverage.name == "PARTIAL"
    assert outcome.exit_code == 0
    verdicts = _by_class(cv.class_verdicts(report))
    # No trace outcome anywhere, so nothing is server-reported and no proof level
    # appears: each class reads as it would have before.
    assert verdicts["W1"].status == cv.STATUS_RESISTED
    assert verdicts["W2"].status == cv.STATUS_FINDING
    assert verdicts["W2"].proof_levels == ()
    assert verdicts["W3"].status == cv.STATUS_NOT_TESTED
    assert verdicts["W3"].codes == ("MYL-NT-004",)
    # An errored effect probe reached no verdict, so the class is not tested.
    assert verdicts["W4"].status == cv.STATUS_NOT_TESTED
    assert verdicts["W4"].codes == ("MYL-NT-009",)


def test_the_summary_is_the_same_from_a_saved_report(tmp_path: Path) -> None:
    report = _report(
        _attempt(_W4, "finding", trace_outcome="dispatched-ok", proof_level="dispatched"),
        _attempt(_W2, "undecided", fallback_cause="MYL-INC-001", trace_outcome="dispatched-ok"),
        _attempt(_W3, "no_finding", negative_basis="server-reported", reason_code="MYL-SRV-002"),
    )
    path = tmp_path / "scan_report.json"
    path.write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")
    reloaded = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert cv.class_verdicts(reloaded) == cv.class_verdicts(report)


def test_class_verdict_to_dict_is_json_ready() -> None:
    (verdict,) = cv.class_verdicts(
        _report(_attempt(_W4, "finding", proof_level="dispatched", trace_outcome="dispatched-ok"))
    )
    assert json.loads(json.dumps(verdict.to_dict())) == {
        "weakness": "W4",
        "status": "FINDING",
        "codes": [],
        "proof_levels": ["dispatched"],
        "counts": {"finding": 1, "resisted": 0, "server_reported": 0, "not_tested": 0},
        "trace_decided": 1,
    }
