"""Reference differential iterations: how long each twin scan may run.

Offline: a scripted completion function stands in for every LLM call.

* ``--iteration-timeout`` bounds each twin's scan on the reference path too.
* An exploit whose seed the bank does not know still fails closed.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _emit_test,
    _outcome,
    _ScriptedCompletion,
    _SleepyScriptedCompletion,
)

from mylonite.contracts import ValidationOutcome
from mylonite.plugins._reference import reference_validator as rv
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)


def _skip_metamorphic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate the differential loop: the metamorphic stage has its own tests."""

    def _passing(self: Any, exploit: Any) -> ValidationOutcome:
        return ValidationOutcome(stage="metamorphic", passed=True, detail="skipped", metric=1.0)

    monkeypatch.setattr(DifferentialValidator, "_metamorphic_outcome", _passing)


def _validate(validator: DifferentialValidator, exploit: Any) -> Any:
    return validator.validate(
        _emit_test(exploit), ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )


def test_iteration_timeout_reaches_the_reference_twin_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skip_metamorphic(monkeypatch)
    timeouts: list[float | None] = []
    real_build_scan = rv.build_scan

    def _spy_build_scan(variant: str, **kwargs: Any) -> Any:
        timeouts.append(kwargs.get("wall_clock_timeout_s"))
        return real_build_scan(variant, **kwargs)

    monkeypatch.setattr(rv, "build_scan", _spy_build_scan)
    validator = DifferentialValidator(
        iterations=1,
        completion_fn=_ScriptedCompletion(),
        run_build=False,
        iteration_timeout_s=42.0,
    )

    _validate(validator, _build_exploit())

    assert timeouts == [42.0, 42.0]


def test_a_slow_reference_run_is_cut_off_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skip_metamorphic(monkeypatch)
    validator = DifferentialValidator(
        iterations=1,
        completion_fn=_SleepyScriptedCompletion(delay=0.5),
        run_build=False,
        iteration_timeout_s=0.05,
    )

    started = time.monotonic()
    report = _validate(validator, _build_exploit())

    assert time.monotonic() - started < 2.0
    assert report.kept is False
    assert _outcome(report, "differential").passed is False


def test_an_exploit_for_an_unknown_seed_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _skip_metamorphic(monkeypatch)
    validator = DifferentialValidator(
        iterations=1, completion_fn=_ScriptedCompletion(), run_build=False
    )

    report = _validate(validator, _build_exploit("no-such-seed-in-the-bank"))

    assert report.kept is False
    assert _outcome(report, "differential").passed is False
