"""`validate` can't KEEP on a skipped or failed build test, and a keep with no
proof never reads as KEPT.

* The build leg passes only when the committed test actually ran and passed.
  A failing or all-skipped test fails the leg, so the report is rejected.
* A skipped build leg (``run_build=False``) is report-only, and the verdict
  label is ``STABLE, NOT PROVEN``, never ``KEPT``.
* A custom-target keep with no differential and no effect proof is labelled
  ``STABLE, NOT PROVEN`` in the label, the notes and the rendered verdict.

All offline: the differential loop and the record leg use the scripted
completions from the sibling tests.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _cust_completion,
    _custom_exploit,
    _emit_test,
    _FakeCustomAdapter,
    _outcome,
    _ScriptedCompletion,
)
from tests.plugins.test_record_during_validate import _install_fake_acompletion

from mylonite._verdict import (
    KEPT,
    REJECTED,
    STABLE_NOT_PROVEN,
    verdict_label,
    verdict_reason,
)
from mylonite.contracts import AdapterResponse, ValidationOutcome, ValidationReport
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)
from mylonite.report.render import _render_validation_report

_FAILING_SOURCE = "def test_guard_holds():\n    assert False\n"
_SKIPPING_SOURCE = (
    "import pytest\n\n\n@pytest.mark.skip(reason='no target')\ndef test_guard_holds():\n    pass\n"
)


def _rendered(report: ValidationReport) -> str:
    buf = io.StringIO()
    _render_validation_report(report, console=Console(file=buf, width=200))
    return buf.getvalue()


# --- the build leg needs a real pass -----------------------------------------


@pytest.mark.parametrize("source", [_FAILING_SOURCE, _SKIPPING_SOURCE], ids=["failed", "skipped"])
def test_build_test_that_fails_or_skips_is_never_kept(
    source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The differential discriminates, but the committed test does not pass:
    the build leg fails and the report is rejected."""
    _install_fake_acompletion(monkeypatch)
    exploit = _build_exploit()
    test = _emit_test(exploit).model_copy(update={"source": source})
    validator = DifferentialValidator(
        model="stub",
        iterations=2,
        completion_fn=_ScriptedCompletion(),
        record_fixtures_dir=tmp_path / "gen" / "fixtures",
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    assert _outcome(report, "differential").passed is True
    build = _outcome(report, "build")
    assert build.passed is False, build.detail
    assert build.report_only is False
    assert "did NOT pass" in build.detail
    assert report.kept is False
    assert verdict_label(report) == REJECTED
    out = _rendered(report)
    assert "build fail" in out
    assert "verdict: KEPT" not in out


def test_skipped_build_is_not_a_plain_keep() -> None:
    exploit = _build_exploit()
    test = _emit_test(exploit)
    validator = DifferentialValidator(
        model="stub", iterations=2, completion_fn=_ScriptedCompletion(), run_build=False
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    build = _outcome(report, "build")
    assert build.passed is False
    assert build.report_only is True
    assert "build" not in report.gating_legs
    assert report.kept is True
    assert verdict_label(report) == STABLE_NOT_PROVEN
    assert STABLE_NOT_PROVEN in (report.notes or "")
    assert "build leg was skipped" in verdict_reason(report)
    out = _rendered(report)
    assert "verdict: STABLE, NOT PROVEN" in out
    assert "verdict: KEPT" not in out


# --- a keep with no differential and no effect proof -------------------------


class _FiringNoProbeAdapter:
    """A custom target whose trace shows the attack landing, with no effect probe."""

    async def describe(self) -> Any:
        from mylonite.contracts import TargetDescriptor, ToolSpec

        return TargetDescriptor(
            target_id="mcp:custom",
            kind="mcp",
            weakness_classes=["W4"],
            tools=[ToolSpec(name="send_email", description="send", json_schema={})],
        )

    async def invoke(self, payload: Any) -> AdapterResponse:
        return AdapterResponse(
            payload_pattern_id=payload.pattern_id,
            raw_response="sent",
            tool_calls=["send_email"],
            metadata={
                "effect_confirmed": "unprobed",
                "effect_trace": '[{"tool": "send_email", "is_error": false}]',
            },
        )

    async def close(self) -> None:
        return None


def test_custom_keep_without_differential_or_effect_is_stable_not_proven(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reproduction plus judge agreement is all this keep rests on: no guarded
    twin, no control, no effect probe. The judges are stubbed to agree."""
    test = ReferencePytestGenerator().emit(_custom_exploit())
    validator = DifferentialValidator(
        model="stub", iterations=2, vuln_threshold=2, completion_fn=_cust_completion
    )
    monkeypatch.setattr(validator, "_multi_judge_consensus", lambda runs, payload: 1.0)
    report = validator.validate(test, _FiringNoProbeAdapter(), ReferenceVulnerableOracle())

    assert report.kept is True, report.notes
    assert all(o.stage != "differential" for o in report.outcomes)
    assert _outcome(report, "effect").report_only is True
    assert _outcome(report, "build").passed is True
    assert verdict_label(report) == STABLE_NOT_PROVEN
    assert STABLE_NOT_PROVEN in (report.notes or "")
    assert "KEPT" not in (report.notes or "")
    out = _rendered(report)
    assert "verdict: STABLE, NOT PROVEN" in out
    assert "no guarded twin or control" in out
    assert "verdict: KEPT" not in out


def test_custom_keep_with_effect_proof_is_kept() -> None:
    """The custom build leg only collects the test (it needs a live target), and
    an effect probe that confirms the damage is the proof, so the label is KEPT."""
    test = ReferencePytestGenerator().emit(_custom_exploit())
    validator = DifferentialValidator(
        model="stub", iterations=2, vuln_threshold=2, completion_fn=_cust_completion
    )
    report = validator.validate(test, _FakeCustomAdapter("true"), ReferenceVulnerableOracle())

    build = _outcome(report, "build")
    assert build.passed is True
    assert "collected (not run)" in build.detail
    assert report.kept is True
    assert verdict_label(report) == KEPT
    assert "verdict: KEPT" in _rendered(report)


# --- the label rule on its own ----------------------------------------------


def _report(kept: bool, *outcomes: ValidationOutcome) -> ValidationReport:
    return ValidationReport(test_filename="t.py", outcomes=list(outcomes), kept=kept)


def _leg(stage: Any, passed: bool = True, report_only: bool = False) -> ValidationOutcome:
    return ValidationOutcome(stage=stage, passed=passed, detail="", report_only=report_only)


def test_label_needs_a_passed_build_and_a_proof_leg() -> None:
    assert verdict_label(_report(True, _leg("build"), _leg("differential"))) == KEPT
    assert verdict_label(_report(True, _leg("build"), _leg("effect"))) == KEPT
    assert verdict_label(_report(True, _leg("build"), _leg("stability"))) == STABLE_NOT_PROVEN
    assert (
        verdict_label(_report(True, _leg("build", False, True), _leg("differential")))
        == STABLE_NOT_PROVEN
    )
    assert (
        verdict_label(_report(True, _leg("build"), _leg("effect", False, True)))
        == STABLE_NOT_PROVEN
    )
    assert verdict_label(_report(False, _leg("build"), _leg("differential"))) == REJECTED
