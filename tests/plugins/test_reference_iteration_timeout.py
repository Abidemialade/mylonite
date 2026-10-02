"""Reference differential iterations: how long each twin scan may run.

Offline: a scripted completion function stands in for every LLM call.

* ``--iteration-timeout`` bounds each twin's scan on the reference path too.
* An exploit whose seed the bank does not know still fails closed.
"""

from __future__ import annotations

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
    unguarded_no_verdict,
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

    report = _validate(validator, _build_exploit())

    assert report.kept is False
    differential = _outcome(report, "differential")
    assert differential.passed is False
    # The cut-off unguarded run is counted as reaching no verdict, not as an
    # attack that never landed.
    assert "reached no verdict 1/1" in differential.detail
    assert unguarded_no_verdict(report.notes) == 1


def test_an_exploit_for_an_unknown_seed_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _skip_metamorphic(monkeypatch)
    validator = DifferentialValidator(
        iterations=1, completion_fn=_ScriptedCompletion(), run_build=False
    )

    report = _validate(validator, _build_exploit("no-such-seed-in-the-bank"))

    assert report.kept is False
    assert _outcome(report, "differential").passed is False


def test_a_custom_target_that_never_comes_up_raises_target_launch_error() -> None:
    """A run whose target cannot even be described is not evidence either way:
    stop with a named error rather than report the attack "did not reproduce"."""
    from tests.plugins.test_differential_validator import (
        _cust_completion,
        _custom_exploit,
        _FakeCustomAdapter,
    )

    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import TargetLaunchError

    class _DeadAdapter(_FakeCustomAdapter):
        async def describe(self) -> Any:
            raise OSError("server command not found")

    validator = DifferentialValidator(
        iterations=2, vuln_threshold=2, completion_fn=_cust_completion, run_build=False
    )
    test = ReferencePytestGenerator().emit(_custom_exploit())

    with pytest.raises(TargetLaunchError):
        validator.validate(test, _DeadAdapter("true"), ReferenceVulnerableOracle())


def test_a_custom_adapter_factory_that_raises_is_a_target_launch_error() -> None:
    from tests.plugins.test_differential_validator import _cust_completion, _custom_exploit

    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import TargetLaunchError

    def _factory() -> Any:
        raise FileNotFoundError("no such server binary")

    validator = DifferentialValidator(
        iterations=1,
        completion_fn=_cust_completion,
        run_build=False,
        target_adapter_factory=_factory,
    )
    test = ReferencePytestGenerator().emit(_custom_exploit())

    with pytest.raises(TargetLaunchError):
        validator.validate(test, object(), ReferenceVulnerableOracle())  # type: ignore[arg-type]


def test_the_custom_differential_stamps_the_stand_in_guard_mode() -> None:
    from tests.plugins.test_differential_validator import (
        _cust_completion,
        _custom_exploit,
        _FakeCustomAdapter,
    )

    from mylonite._twin_fidelity import guard_mode_in
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator

    validator = DifferentialValidator(
        iterations=2,
        vuln_threshold=2,
        completion_fn=_cust_completion,
        run_build=False,
        target_adapter_factory=lambda: _FakeCustomAdapter("true"),
        guarded_adapter_factory=lambda: _FakeCustomAdapter("false"),
        control_weakness="W4",
        guard_mode="approve-policy",
    )
    report = validator.validate(
        ReferencePytestGenerator().emit(_custom_exploit()),
        _FakeCustomAdapter("true"),
        ReferenceVulnerableOracle(),
    )

    assert guard_mode_in(report.notes) == "approve-policy"


def test_a_target_that_goes_down_mid_loop_names_the_runs_it_discarded() -> None:
    from tests.plugins.test_differential_validator import (
        _cust_completion,
        _custom_exploit,
        _FakeCustomAdapter,
    )

    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import TargetLaunchError

    class _DiesOnThirdRun(_FakeCustomAdapter):
        calls = 0

        async def describe(self) -> Any:
            type(self).calls += 1
            if type(self).calls >= 3:
                raise OSError("server exited")
            return await super().describe()

    validator = DifferentialValidator(
        iterations=3, vuln_threshold=2, completion_fn=_cust_completion, run_build=False
    )
    test = ReferencePytestGenerator().emit(_custom_exploit())

    with pytest.raises(TargetLaunchError) as caught:
        validator.validate(test, _DiesOnThirdRun("true"), ReferenceVulnerableOracle())

    assert caught.value.completed_runs == 2
    assert "after 2 of 3 runs finished, 2 of them fired" in str(caught.value)
