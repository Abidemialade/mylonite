"""A repeat-run leg that rests on one run per build reads "not measured", never a pass.

With one run per build the success rate is 0% or 100% by construction, so the
flakiness leg cannot measure anything. A kept report with that evidence must not
say "stable" or show a pass mark for the leg. A report with enough runs renders
exactly as before.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from mylonite._verdict import MIN_STABILITY_RUNS, stability_measured, verdict_reason
from mylonite.contracts import ReproducibilityEvidence, ValidationOutcome, ValidationReport
from mylonite.report.render import _render_validation_report


def _kept(iterations: int) -> ValidationReport:
    return ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="ran", metric=None),
            ValidationOutcome(stage="differential", passed=True, detail="fires", metric=1.0),
            ValidationOutcome(stage="flakiness", passed=True, detail="gap +100%", metric=1.0),
            ValidationOutcome(stage="metamorphic", passed=True, detail="held", metric=1.0),
        ],
        kept=True,
        gating_formula="kept = build AND differential AND flakiness AND metamorphic",
        gating_legs=["build", "differential", "flakiness", "metamorphic"],
        reproducibility=ReproducibilityEvidence(
            iterations=iterations, vuln_fired=iterations, guard_resisted=iterations
        ),
    )


def _rendered(report: ValidationReport) -> str:
    console = Console(file=io.StringIO(), record=True, width=200)
    _render_validation_report(report, console=console)
    return console.export_text()


def test_one_run_per_build_is_not_measured() -> None:
    report = _kept(1)

    assert not stability_measured(report)
    reason = verdict_reason(report)
    assert "stable." not in reason
    assert "not measured (1 run per build)" in reason

    out = _rendered(report)
    assert "· not measured" in out
    assert "flakiness (not measured)" in out
    assert "flakiness ✓" not in out and "flakiness +" not in out
    assert "discriminates and is stable" not in out


@pytest.mark.parametrize("iterations", [MIN_STABILITY_RUNS, 5])
def test_enough_runs_render_unchanged(iterations: int) -> None:
    report = _kept(iterations)

    assert stability_measured(report)
    assert verdict_reason(report) == "the test discriminates and is stable."

    out = _rendered(report)
    assert "not measured" not in out
    assert "flakiness ✓" in out or "flakiness +" in out


def test_a_report_without_run_counts_renders_unchanged() -> None:
    report = _kept(5).model_copy(update={"reproducibility": None})

    assert stability_measured(report)
    assert verdict_reason(report) == "the test discriminates and is stable."
