"""Validator contract 0.2.0: machine-readable validation-metric fields.

Covers the optional, defaulted ``metric`` (on ``ValidationOutcome``) and
``mutation_score`` (on ``ValidationReport``) added in the backward-compatible
``0.1.0 -> 0.2.0`` validator contract bump.
"""

from __future__ import annotations

from mylonite.contracts import ValidationOutcome, ValidationReport, validator


def test_validator_contract_version() -> None:
    # 0.3.0: ValidationOutcome.stage gained stability/effect/consensus legs.
    # 0.4.0: ValidationReport gained structured evidence fields (gating_formula,
    # gating_legs, reproducibility, mutation_matrix).
    # 0.5.0: ReproducibilityEvidence gained guard_fired + rate_gap (statistical
    # success-rate differential).
    assert validator.CONTRACT_VERSION == "0.5.0"


def test_validation_report_structured_evidence_round_trips() -> None:
    """The 0.4.0 evidence fields round-trip and default to empty/None."""
    from mylonite.contracts import ReproducibilityEvidence, SeedKill

    report = ValidationReport(
        test_filename="test_x.py",
        outcomes=[ValidationOutcome(stage="differential", passed=True, detail="d", metric=1.0)],
        kept=True,
        gating_formula="kept = build AND differential AND flakiness",
        gating_legs=["build", "differential", "flakiness"],
        reproducibility=ReproducibilityEvidence(iterations=5, vuln_fired=5, guard_resisted=5),
        mutation_matrix=[SeedKill(pattern_id="p1", weakness="W2", killed=True)],
    )
    assert ValidationReport.model_validate_json(report.model_dump_json()) == report
    # Back-compatible default: omitting the new fields is still valid.
    bare = ValidationReport(test_filename="t.py", outcomes=[], kept=False)
    assert bare.gating_formula is None
    assert bare.gating_legs == []
    assert bare.reproducibility is None
    assert bare.mutation_matrix == []


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
