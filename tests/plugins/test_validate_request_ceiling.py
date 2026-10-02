"""Validation under the hard LLM request ceiling: it stops sending at the
limit and never comes back with a kept verdict. Offline, scripted LLM."""

from __future__ import annotations

import functools

import pytest
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _emit_test,
    _ScriptedCompletion,
)

from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)
from mylonite.scan._llm import (
    REQUEST_CEILING_ENV,
    BudgetExceededError,
    request_ceiling_hit,
    requests_sent,
    reset_request_ceiling,
)


def _validate() -> object:
    validator = DifferentialValidator(iterations=3, completion_fn=_ScriptedCompletion())
    return validator.validate(
        _emit_test(_build_exploit()),
        ReferenceVulnerableOracle().adapter(),
        ReferenceVulnerableOracle(),
    )


@functools.cache
def _uncapped_requests() -> int:
    report = _validate()
    assert report.kept is True, report.notes  # type: ignore[attr-defined]
    total = requests_sent()
    reset_request_ceiling()
    return total


@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9])
def test_validation_stops_at_the_ceiling_and_is_never_kept(
    monkeypatch: pytest.MonkeyPatch, fraction: float
) -> None:
    total = _uncapped_requests()
    limit = max(1, int(total * fraction))
    monkeypatch.setenv(REQUEST_CEILING_ENV, str(limit))
    try:
        report = _validate()
    except BudgetExceededError:
        pass
    else:
        assert report.kept is not True, "a run that hit the ceiling must not be kept"  # type: ignore[attr-defined]
    assert requests_sent() <= limit
    assert request_ceiling_hit() == limit
