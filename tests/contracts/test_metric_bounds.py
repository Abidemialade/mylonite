"""Validator contract 0.2.0: defensive [0,1] bounds on validation metrics.

``ValidationOutcome.metric`` and ``ValidationReport.mutation_score`` are
documented as ``[0,1]`` fractions. These tests assert the Pydantic ``ge/le``
bounds reject out-of-range values at construction while accepting in-range
values and ``None`` (the default).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mylonite.contracts import ValidationOutcome, ValidationReport


@pytest.mark.parametrize("bad", [1.5, -0.1])
def test_validation_outcome_metric_rejects_out_of_range(bad: float) -> None:
    with pytest.raises(ValidationError):
        ValidationOutcome(stage="flakiness", passed=True, detail="x", metric=bad)


@pytest.mark.parametrize("good", [0.5, None])
def test_validation_outcome_metric_accepts_in_range(good: float | None) -> None:
    outcome = ValidationOutcome(stage="flakiness", passed=True, detail="x", metric=good)
    assert outcome.metric == good


@pytest.mark.parametrize("bad", [1.5, -0.1])
def test_validation_report_mutation_score_rejects_out_of_range(bad: float) -> None:
    with pytest.raises(ValidationError):
        ValidationReport(test_filename="t", kept=True, mutation_score=bad)


@pytest.mark.parametrize("good", [0.75, None])
def test_validation_report_mutation_score_accepts_in_range(good: float | None) -> None:
    report = ValidationReport(test_filename="t", kept=True, mutation_score=good)
    assert report.mutation_score == good
