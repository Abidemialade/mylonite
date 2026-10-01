"""``validate`` never keeps a test when every firing run is judge-only.

A judge-only run is one only the LLM judge said landed: nothing in the target's
state or the recorded trace confirmed it. Judge-only runs still count as
support when at least one run is confirmed.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite._verdict import (
    JUDGE_ONLY_MARKER,
    REJECTED,
    STABLE_NOT_PROVEN,
    next_step_after_keep,
    verdict_label,
    verdict_reason,
)
from mylonite.contracts import ScanAttempt, ScanReport
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
    _CustomRun,
    _IterationTally,
)
from mylonite.scan.engine import ScanResult

from .test_differential_validator import _cust_completion, _custom_exploit, _FakeCustomAdapter


def _validate_custom(
    tiers: list[str | None], *, effect: str = "unprobed", black_box: bool = False
) -> Any:
    """Validate a custom target whose runs all fire, at the given tiers."""
    test = ReferencePytestGenerator().emit(_custom_exploit())
    queue = list(tiers)

    def _run(self: Any, target: Any, pattern_id: str, *, factory: Any = None) -> _CustomRun:
        tier = queue.pop(0)
        return _CustomRun(
            finding=True,
            effect_confirmed=effect,
            response=None,
            verdict_mechanism="llm" if tier == "judge-only" else "predicate",
            evidence_tier=tier,
            black_box=black_box,
        )

    validator = DifferentialValidator(
        iterations=len(tiers),
        vuln_threshold=len(tiers),
        completion_fn=_cust_completion,
        run_build=False,
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(DifferentialValidator, "_run_custom_iteration", _run, raising=True)
        # The judges agree, so only the evidence rule decides the keep.
        mp.setattr(DifferentialValidator, "_multi_judge_consensus", lambda self, runs, payload: 1.0)
        return validator.validate(test, _FakeCustomAdapter("true"), ReferenceVulnerableOracle())


def _stability(report: Any) -> Any:
    return next(o for o in report.outcomes if o.stage == "stability")


def test_custom_target_rejects_a_keep_resting_on_the_judge_alone() -> None:
    report = _validate_custom(["judge-only", "judge-only"])
    assert report.kept is False
    assert verdict_label(report) == REJECTED
    stability = _stability(report)
    assert stability.passed is False
    assert "LLM judge alone" in stability.detail
    assert "2 judge-only" in stability.detail
    assert JUDGE_ONLY_MARKER in report.notes
    assert "LLM judge alone" in verdict_reason(report)


def test_a_black_box_target_keeps_a_judge_only_test_capped_at_stable_not_proven() -> None:
    """A transport: rest target records no tool calls and runs no effect probe,
    so the judge is all it can offer: the test is kept, never as KEPT."""
    report = _validate_custom(["judge-only", "judge-only"], black_box=True)
    assert report.kept is True
    assert _stability(report).passed is True
    assert verdict_label(report) == STABLE_NOT_PROVEN
    assert "black-box target: the LLM judge is the only evidence" in verdict_reason(report)
    assert JUDGE_ONLY_MARKER not in report.notes
    assert "effect_probe" not in next_step_after_keep(report)


@pytest.mark.parametrize("tier", [None, "state", "trace"])
def test_every_keep_on_a_black_box_target_is_capped(tier: str | None) -> None:
    """No exceptions: a rest run whose tier is missing or reads state still caps."""
    report = _validate_custom([tier, tier], black_box=True)
    assert report.kept is True
    assert verdict_label(report) == STABLE_NOT_PROVEN
    assert "black-box target" in verdict_reason(report)


def test_a_black_box_keep_with_a_passing_differential_is_capped_in_its_notes() -> None:
    """The real path, with a guarded twin that resists: the differential passes,
    and both the label and the label written into the notes read STABLE, NOT PROVEN."""
    test = ReferencePytestGenerator().emit(_custom_exploit())

    def _run(self: Any, target: Any, pattern_id: str, *, factory: Any = None) -> _CustomRun:
        if factory is not None:  # the guarded side resists
            return _CustomRun(
                finding=False, effect_confirmed="unprobed", response=None, resisted=True
            )
        return _CustomRun(
            finding=True,
            effect_confirmed="unprobed",
            response=None,
            verdict_mechanism="llm",
            evidence_tier="judge-only",
            black_box=True,
        )

    validator = DifferentialValidator(
        iterations=2,
        vuln_threshold=2,
        completion_fn=_cust_completion,
        guarded_adapter_factory=lambda: _FakeCustomAdapter("true"),
        control_weakness="W2",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(DifferentialValidator, "_run_custom_iteration", _run, raising=True)
        mp.setattr(DifferentialValidator, "_multi_judge_consensus", lambda self, runs, payload: 1.0)
        report = validator.validate(test, _FakeCustomAdapter("true"), ReferenceVulnerableOracle())

    assert next(o for o in report.outcomes if o.stage == "differential").passed is True
    assert report.kept is True
    assert verdict_label(report) == STABLE_NOT_PROVEN
    assert "STABLE, NOT PROVEN (kept" in report.notes
    assert "KEPT (kept" not in report.notes


def test_a_black_box_cap_holds_even_when_every_other_leg_proves() -> None:
    """A passing differential (e.g. the input-framing one) never lifts the cap."""
    from mylonite.contracts import ValidationOutcome

    report = _validate_custom(["judge-only", "judge-only"], black_box=True)
    proven = report.model_copy(
        update={
            "outcomes": [
                ValidationOutcome(stage="build", passed=True, detail="ok"),
                ValidationOutcome(stage="differential", passed=True, detail="ok"),
            ]
        }
    )
    assert verdict_label(proven) == STABLE_NOT_PROVEN


def test_judge_only_runs_still_support_a_confirmed_run() -> None:
    report = _validate_custom(["trace", "judge-only"])
    stability = _stability(report)
    assert stability.passed is True
    assert "LLM judge alone" not in stability.detail
    assert JUDGE_ONLY_MARKER not in report.notes
    assert "1 trace, 1 judge-only" in stability.detail


def test_a_run_with_no_recorded_tier_is_not_judge_only() -> None:
    """Older stand-ins and runs with no judged attempt record no tier."""
    stability = _stability(_validate_custom([None, None]))
    assert stability.passed is True
    assert "2 unknown" in stability.detail


def test_a_real_custom_run_records_its_evidence_tier() -> None:
    """The effect probe confirmed the effect, so the run rests on state."""
    validator = DifferentialValidator(
        iterations=1, vuln_threshold=1, completion_fn=_cust_completion, run_build=False
    )
    run = validator._run_custom_iteration(_FakeCustomAdapter("true"), _custom_exploit().pattern_id)
    assert run.finding is True
    assert run.evidence_tier == "state"


# --- reference twins ---------------------------------------------------------


def _scan_result(pattern_id: str, outcome: str, mechanism: str | None) -> ScanResult:
    attempt = ScanAttempt(
        seed_id=pattern_id,
        pattern_id=pattern_id,
        outcome=outcome,  # type: ignore[arg-type]
        verdict_mechanism=mechanism,  # type: ignore[arg-type]
    )
    report = ScanReport(
        target_id="reference:vulnerable",
        provider="anthropic",
        model="stub",
        elapsed_seconds=0.1,
        attempts=[attempt],
        findings_count=1 if outcome == "finding" else 0,
        mylonite_version="0.10.5",
    )
    return ScanResult(report=report, exploits=[])


def _validate_reference(vuln_mechanism: str) -> Any:
    exploit = _custom_exploit().model_copy(update={"target_id": "reference:vulnerable"})
    pid = exploit.pattern_id
    test = ReferencePytestGenerator().emit(exploit)

    def _iteration(self: Any, pattern_id: str) -> _IterationTally:
        return _IterationTally(
            vuln_fired=True,
            guard_resisted=True,
            vuln_result=_scan_result(pid, "finding", vuln_mechanism),
            guard_result=_scan_result(pid, "no_finding", "predicate"),
            guard_fired=False,
        )

    from mylonite.contracts import ValidationOutcome

    passing = {"passed": True, "detail": "stub", "metric": 1.0}
    validator = DifferentialValidator(iterations=2, completion_fn=_cust_completion)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(DifferentialValidator, "_run_iteration", _iteration)
        mp.setattr(
            DifferentialValidator,
            "_metamorphic_outcome",
            lambda self, e: ValidationOutcome(stage="metamorphic", **passing),
        )
        mp.setattr(
            DifferentialValidator,
            "_build_outcome",
            lambda self, t, tallies: ValidationOutcome(stage="build", **passing),
        )
        return validator._validate_reference(test)


def test_reference_twins_reject_a_differential_resting_on_the_judge_alone() -> None:
    report = _validate_reference("llm")
    differential = next(o for o in report.outcomes if o.stage == "differential")
    assert differential.passed is False
    assert "LLM judge alone" in differential.detail
    assert JUDGE_ONLY_MARKER in report.notes
    assert report.kept is False
    assert "LLM judge alone" in verdict_reason(report)


def test_reference_twins_keep_a_differential_the_trace_confirmed() -> None:
    report = _validate_reference("predicate")
    differential = next(o for o in report.outcomes if o.stage == "differential")
    assert differential.passed is True
    assert "2 trace" in differential.detail


def test_the_rendered_verdict_names_the_judge_only_cause() -> None:
    import io

    from rich.console import Console

    from mylonite.report.render import _render_validation_report

    buffer = io.StringIO()
    _render_validation_report(
        _validate_custom(["judge-only", "judge-only"]),
        console=Console(file=buffer, width=200, force_terminal=False),
    )
    assert "verdict: REJECTED" in buffer.getvalue()
    assert "LLM judge alone" in buffer.getvalue()


def test_a_real_run_against_an_http_agent_is_marked_black_box() -> None:
    class _HttpAgent(_FakeCustomAdapter):
        async def describe(self) -> Any:
            from mylonite.contracts import TargetDescriptor

            return TargetDescriptor(target_id="rest:agent", kind="http-agent")

    validator = DifferentialValidator(
        iterations=1, vuln_threshold=1, completion_fn=_cust_completion, run_build=False
    )
    pid = _custom_exploit().pattern_id
    assert validator._run_custom_iteration(_HttpAgent("unprobed"), pid).black_box is True
    assert validator._run_custom_iteration(_FakeCustomAdapter("true"), pid).black_box is False
