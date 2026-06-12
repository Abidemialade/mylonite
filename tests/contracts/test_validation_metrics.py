"""Validator contract 0.2.0: machine-readable validation-metric fields.

Covers the optional, defaulted ``metric`` (on ``ValidationOutcome``) and
``mutation_score`` (on ``ValidationReport``) added in the backward-compatible
``0.1.0 -> 0.2.0`` validator contract bump.
"""

from __future__ import annotations

from mylonite.contracts import ValidationOutcome, ValidationReport, validator


def test_validator_contract_version() -> None:
    # 0.3.0: ValidationOutcome.stage gained stability/effect/consensus legs.
    assert validator.CONTRACT_VERSION == "0.3.0"


def test_validation_outcome_metric_round_trips() -> None:
    outcome = ValidationOutcome(stage="flakiness", passed=True, detail="x", metric=0.8)
    assert outcome.metric == 0.8
    # Round-trips through JSON serialization.
    assert ValidationOutcome.model_validate_json(outcome.model_dump_json()) == outcome


def test_validation_outcome_metric_defaults_to_none() -> None:
    outcome = ValidationOutcome(stage="flakiness", passed=True, detail="x")
    assert outcome.metric is None


def test_validation_report_mutation_score_round_trips() -> None:
    report = ValidationReport(test_filename="test_x.py", kept=True, mutation_score=0.75)
    assert report.mutation_score == 0.75
    assert ValidationReport.model_validate_json(report.model_dump_json()) == report


def test_validation_report_mutation_score_defaults_to_none() -> None:
    report = ValidationReport(test_filename="test_x.py", kept=True)
    assert report.mutation_score is None
