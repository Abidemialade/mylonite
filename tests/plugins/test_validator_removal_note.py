"""Validate's effect-leg detail surfaces removal-confirmation outcomes.

A target that declares ``effect_probe.removal`` stamps ``removal_confirmed``/
``removal_note`` on every custom-target run (see ``removal_probe.py`` and
``_session_adapter.py``'s ``invoke``). This gains those per-run outcome
counts, plus the first note of each kind, in the effect leg's own detail
text — report-only: it changes no verdict, gating or proof level. A target
that declares no removal probe carries neither field, so the clause stays
absent.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
    _CustomRun,
)

from .test_differential_validator import _cust_completion, _custom_exploit, _FakeCustomAdapter


def _effect(report: Any) -> Any:
    return next(o for o in report.outcomes if o.stage == "effect")


def _validate_with_runs(runs: list[_CustomRun]) -> Any:
    test = ReferencePytestGenerator().emit(_custom_exploit())
    queue = list(runs)

    def _run(self: Any, target: Any, pattern_id: str, *, factory: Any = None) -> _CustomRun:
        return queue.pop(0)

    validator = DifferentialValidator(
        model="stub",
        iterations=len(runs),
        vuln_threshold=len(runs),
        completion_fn=_cust_completion,
        run_build=False,
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(DifferentialValidator, "_run_custom_iteration", _run, raising=True)
        mp.setattr(DifferentialValidator, "_multi_judge_consensus", lambda self, rs, payload: 1.0)
        return validator.validate(test, _FakeCustomAdapter("true"), ReferenceVulnerableOracle())


def test_removal_counts_and_notes_appear_for_a_removal_declaring_fake() -> None:
    runs = [
        _CustomRun(
            finding=True,
            effect_confirmed="true",
            response=None,
            verdict_mechanism="predicate",
            evidence_tier="state",
            removal_confirmed="true",
            removal_note=(
                "the planted record read present before the attempt and absent "
                "after, the sentinel survived, and this attempt's call to the "
                "seed tool named it exactly"
            ),
        ),
        _CustomRun(
            finding=True,
            effect_confirmed="true",
            response=None,
            verdict_mechanism="predicate",
            evidence_tier="state",
            removal_confirmed="unavailable",
            removal_note="the record may already exist, so it was not touched",
        ),
    ]

    report = _validate_with_runs(runs)
    detail = _effect(report).detail

    assert "removal: 1 confirmed, 1 unavailable" in detail
    assert "confirmed (the planted record read present" in detail
    assert "unavailable (the record may already exist, so it was not touched)" in detail


def test_removal_clause_is_absent_when_the_target_declares_no_removal_probe() -> None:
    runs = [
        _CustomRun(
            finding=True,
            effect_confirmed="true",
            response=None,
            verdict_mechanism="predicate",
            evidence_tier="state",
        ),
        _CustomRun(
            finding=True,
            effect_confirmed="true",
            response=None,
            verdict_mechanism="predicate",
            evidence_tier="state",
        ),
    ]

    report = _validate_with_runs(runs)

    assert "removal" not in _effect(report).detail


def test_removal_counts_every_kind_of_outcome_once_each() -> None:
    runs = [
        _CustomRun(
            finding=True,
            effect_confirmed="true",
            response=None,
            verdict_mechanism="predicate",
            evidence_tier="state",
            removal_confirmed=status,
            removal_note=f"note for {status}",
        )
        for status in ("true", "false", "unavailable", "errored")
    ]

    report = _validate_with_runs(runs)
    detail = _effect(report).detail

    assert "removal: 1 confirmed, 1 not confirmed, 1 unavailable, 1 errored" in detail
    for label in ("confirmed (note for true)", "not confirmed (note for false)"):
        assert label in detail
