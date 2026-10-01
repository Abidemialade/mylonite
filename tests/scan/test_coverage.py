"""Tests for ``mylonite.scan.coverage`` — the single typed authority for

"did this scan actually work". See ``scan/coverage.py`` module docstring for
the root-cause motivation (six consumers each re-deriving "clean" from a
different lossy projection of ``ScanReport``).
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from mylonite.contracts._types import ScanAttempt, ScanAttemptOutcome, ScanReport
from mylonite.scan.coverage import (
    _OPERATOR_MESSAGE_BY_ABORT,
    ATTEMPT_CLASS,
    AbortReason,
    AttemptClass,
    Coverage,
    ScanOutcome,
    provider_abort_message,
)

EXIT_SUCCESS = 0
EXIT_CONFIG = 2
EXIT_BUDGET = 3
EXIT_PROVIDER = 4


def _attempt(
    outcome: ScanAttemptOutcome,
    *,
    seed_id: str = "s1",
    judge_evidence: dict[str, str] | None = None,
    error_detail: str | None = None,
) -> ScanAttempt:
    return ScanAttempt(
        seed_id=seed_id,
        pattern_id=seed_id,
        outcome=outcome,
        verdict_mechanism=None,
        verdict_reason=None,
        judge_evidence=judge_evidence or {},
        error_detail=error_detail,
    )


def _report(
    *,
    attempts: list[ScanAttempt] | None = None,
    findings_count: int = 0,
    aborted: str | None = None,
    fallback_breakdown: dict[str, int] | None = None,
) -> ScanReport:
    return ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=attempts or [],
        findings_count=findings_count,
        aborted=aborted,
        fallback_breakdown=fallback_breakdown or {},
        mylonite_version="0.0.0",
    )


class TestExhaustiveness:
    def test_every_attempt_outcome_is_classified(self) -> None:
        # Mirrors the import-time guard in coverage.py — asserted again here as
        # an ordinary test so a future ScanAttemptOutcome addition fails a
        # normal pytest run, not just "import broke somewhere".
        assert set(ATTEMPT_CLASS) == set(get_args(ScanAttemptOutcome))

    def test_attempt_class_values_are_valid(self) -> None:
        assert set(ATTEMPT_CLASS.values()) <= set(AttemptClass)


class TestFromReportExitCodes:
    @pytest.mark.parametrize(
        ("aborted", "expected_exit"),
        [
            ("budget_exceeded", EXIT_BUDGET),
            ("provider_unreachable", EXIT_PROVIDER),
            ("describe_failed", EXIT_CONFIG),
            ("no_payloads", EXIT_CONFIG),
            ("wall_clock_timeout", EXIT_CONFIG),
        ],
    )
    def test_abort_exit_codes(self, aborted: str, expected_exit: int) -> None:
        report = _report(aborted=aborted)
        outcome = ScanOutcome.from_report(report)
        assert outcome.exit_code == expected_exit
        assert outcome.abort == AbortReason(aborted)

    def test_clean_no_findings_exit_success(self) -> None:
        report = _report(attempts=[_attempt("no_finding")], findings_count=0)
        outcome = ScanOutcome.from_report(report)
        assert outcome.exit_code == EXIT_SUCCESS
        assert outcome.abort is None

    def test_incomplete_coverage_is_reported_even_when_something_was_found(self) -> None:
        """Finding something does not make the coverage gap go away.

        `operator_message` was gated on `findings_count == 0`, so the run that
        most needs the caveat -- one finding plus a heavy not-tested share --
        was the one that reported nothing. The console line in artefacts.py
        already fires regardless of findings; the structured outcome did not, so
        `gate` and every JSON consumer saw silence.

        The exit code deliberately stays EXIT_SUCCESS here: "ran and found
        something" is scan's documented convention (see the sibling test), and
        changing it is a separate decision.
        """
        report = _report(
            attempts=[_attempt("finding"), _attempt("skipped_no_seed_arm")],
            findings_count=1,
        )
        outcome = ScanOutcome.from_report(report)

        assert outcome.not_tested == 1
        assert outcome.coverage is not Coverage.EXERCISED
        assert outcome.operator_message is not None
        assert "coverage" in outcome.operator_message.lower()
        assert outcome.exit_code == EXIT_SUCCESS  # convention unchanged

    def test_findings_still_exit_success_at_this_layer(self) -> None:
        # EXIT_NOT_KEPT (gate's verdict) is a downstream concern (T2) — scan's
        # own exit-code convention treats "ran and found something" as success,
        # matching cli.py's `scan` command today (only `aborted` drives non-zero).
        report = _report(attempts=[_attempt("finding")], findings_count=1)
        outcome = ScanOutcome.from_report(report)
        assert outcome.exit_code == EXIT_SUCCESS
        assert outcome.findings == 1

    def test_all_errored_no_formal_abort_exits_nonzero(self) -> None:
        # The gate-review regression: PROVIDER_UNREACHABLE only fires once the
        # engine sees consecutive_failures >= DEFAULT_PROVIDER_FAILURE_THRESHOLD
        # (3, in scan/engine.py). A target with fewer than 3 applicable attempts
        # (a narrow --weakness-class filter, or just few seeds) can run with
        # every attempt erroring (e.g. missing/invalid provider credentials)
        # without ever tripping that threshold — `aborted` stays None. Before
        # this fix, exit_code fell through to the `abort is None` branch and
        # returned EXIT_SUCCESS despite `trustworthy_clean` correctly being
        # False — silently indistinguishable from a genuine clean pass to any
        # exit_code-driven consumer (this is what made `gate` exit 0 here).
        report = _report(
            attempts=[_attempt("error"), _attempt("error", seed_id="s2")],
            findings_count=0,
            aborted=None,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.trustworthy_clean is False
        assert outcome.abort is None
        assert outcome.exit_code != EXIT_SUCCESS
        assert outcome.exit_code == EXIT_CONFIG
        assert outcome.operator_message is not None
        assert "never formally aborted" in outcome.operator_message

    def test_partial_not_tested_without_abort_and_no_findings_exits_nonzero(self) -> None:
        # Same failure shape as above but PARTIAL rather than fully
        # NOT_EXERCISED: some attempts genuinely ran clean, others were
        # structurally skipped, no formal abort, and nothing was found. Still
        # not a trustworthy clean pass, so still must not be EXIT_SUCCESS.
        report = _report(
            attempts=[
                _attempt("no_finding"),
                _attempt("skipped_no_seed_arm", seed_id="s2"),
            ],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.PARTIAL
        assert outcome.trustworthy_clean is False
        assert outcome.exit_code != EXIT_SUCCESS
        assert outcome.exit_code == EXIT_CONFIG

    def test_all_no_engagement_is_not_a_trustworthy_clean(self) -> None:
        """A scan where the agent never called a tool proved nothing.

        Previously these attempts were recorded as ``no_finding`` and therefore
        classified EXERCISED_RESISTED, so a scan in which the agent did nothing
        at all reported full coverage and exited 0 — the single largest source of
        inflated coverage measured on a third-party corpus (15 of 22 clean
        verdicts). They are NOT_TESTED, exactly like ``not_applicable``.
        """
        report = _report(
            attempts=[
                _attempt("skipped_planner_no_engagement"),
                _attempt("skipped_planner_no_engagement", seed_id="s2"),
            ],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.NOT_EXERCISED
        assert outcome.trustworthy_clean is False
        assert outcome.exit_code != EXIT_SUCCESS

    def test_no_engagement_mixed_with_a_real_clean_is_partial(self) -> None:
        """One genuine negative alongside an unexercised attempt is PARTIAL, not clean."""
        report = _report(
            attempts=[
                _attempt("no_finding"),
                _attempt("skipped_planner_no_engagement", seed_id="s2"),
            ],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.PARTIAL
        assert outcome.trustworthy_clean is False
        assert outcome.exit_code != EXIT_SUCCESS

    def test_partial_coverage_with_a_real_finding_still_exits_success(self) -> None:
        # The exclusion that keeps the fix from over-firing: a real finding
        # (findings_count > 0) is still worth EXIT_SUCCESS at this layer even
        # under incomplete coverage — mirrors `scan`'s own convention (only
        # `aborted` drives non-zero; finding something is not itself failure).
        report = _report(
            attempts=[
                _attempt("finding"),
                _attempt("skipped_no_seed_arm", seed_id="s2"),
            ],
            findings_count=1,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.PARTIAL
        assert outcome.trustworthy_clean is False
        assert outcome.exit_code == EXIT_SUCCESS


class TestOperatorMessage:
    def test_no_payloads_message_matches_cli_wording(self) -> None:
        outcome = ScanOutcome.from_report(_report(aborted="no_payloads"))
        assert outcome.operator_message is not None
        assert "no seeds were applicable" in outcome.operator_message

    def test_describe_failed_message_matches_cli_wording(self) -> None:
        outcome = ScanOutcome.from_report(_report(aborted="describe_failed"))
        assert outcome.operator_message is not None
        assert "could not describe the target" in outcome.operator_message

    def test_wall_clock_timeout_message_matches_cli_wording(self) -> None:
        outcome = ScanOutcome.from_report(_report(aborted="wall_clock_timeout"))
        assert outcome.operator_message is not None
        assert "wall-clock budget" in outcome.operator_message

    def test_clean_report_has_no_operator_message(self) -> None:
        # A genuinely clean report needs at least one exercised attempt (a
        # bare `_report()` with zero attempts at all is itself an untested,
        # not-trustworthy-clean report post-fix — see
        # test_all_errored_no_formal_abort_exits_nonzero and
        # TestCoverageComputation for that shape).
        report = _report(attempts=[_attempt("no_finding")], findings_count=0)
        outcome = ScanOutcome.from_report(report)
        assert outcome.trustworthy_clean is True
        assert outcome.operator_message is None

    def test_all_errored_no_formal_abort_has_a_diagnostic_message(self) -> None:
        report = _report(
            attempts=[_attempt("error"), _attempt("error", seed_id="s2")],
            findings_count=0,
            aborted=None,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.operator_message is not None
        assert "verdict_reason" in outcome.operator_message


class TestTrustworthyClean:
    @pytest.mark.parametrize(
        "aborted",
        [
            "budget_exceeded",
            "provider_unreachable",
            "describe_failed",
            "no_payloads",
            "wall_clock_timeout",
        ],
    )
    def test_aborted_reports_are_never_trustworthy_clean(self, aborted: str) -> None:
        report = _report(attempts=[_attempt("no_finding")], aborted=aborted)
        outcome = ScanOutcome.from_report(report)
        assert outcome.trustworthy_clean is False

    def test_all_errored_attempts_are_not_trustworthy_clean(self) -> None:
        # The exact false-clean bug this task fixes: every attempt errored,
        # findings_count is 0, and the engine never set `aborted` — the old
        # NOT_TESTED_OUTCOMES allowlist didn't cover "error", so this used to
        # render "N attempts * 0 findings" and exit 0.
        report = _report(
            attempts=[_attempt("error"), _attempt("error", seed_id="s2")],
            findings_count=0,
            aborted=None,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.not_tested == 2
        assert outcome.exercised == 0
        assert outcome.coverage is Coverage.NOT_EXERCISED
        assert outcome.trustworthy_clean is False

    def test_genuinely_clean_report_is_trustworthy(self) -> None:
        report = _report(
            attempts=[_attempt("no_finding"), _attempt("no_finding", seed_id="s2")],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.EXERCISED
        assert outcome.trustworthy_clean is True

    def test_findings_are_never_trustworthy_clean(self) -> None:
        report = _report(attempts=[_attempt("finding")], findings_count=1)
        outcome = ScanOutcome.from_report(report)
        assert outcome.trustworthy_clean is False

    def test_partial_not_tested_without_abort_is_not_trustworthy_clean(self) -> None:
        # Some attempts ran clean, but others were structurally skipped — the
        # scan wasn't aborted, yet coverage is incomplete, so it must not read
        # as a genuine clean pass either.
        report = _report(
            attempts=[
                _attempt("no_finding"),
                _attempt("skipped_no_seed_arm", seed_id="s2"),
            ],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.PARTIAL
        assert outcome.trustworthy_clean is False


class TestCoverageComputation:
    def test_intentional_skip_dry_run_does_not_count_as_not_tested(self) -> None:
        report = _report(attempts=[_attempt("skipped_dry_run")], findings_count=0)
        outcome = ScanOutcome.from_report(report)
        assert outcome.not_tested == 0
        assert outcome.exercised == 0
        assert outcome.coverage is Coverage.NOT_EXERCISED
        # A `--dry-run` report collapses to `coverage is NOT_EXERCISED` just
        # like a genuine "nothing ran" gap does, but it's deliberate BY
        # DESIGN (no customisation/invocation is attempted in dry-run mode) —
        # it must NOT trip the untrustworthy-without-abort exit code, or
        # `mylonite scan --dry-run` would start exiting non-zero on every run.
        assert outcome.exit_code == EXIT_SUCCESS
        assert outcome.operator_message is None

    def test_mixed_dry_run_and_real_gap_still_exits_nonzero(self) -> None:
        # Not every attempt is skipped_dry_run here — one is a genuine
        # structural gap — so this must NOT be excused as "dry-run shaped".
        report = _report(
            attempts=[
                _attempt("skipped_dry_run"),
                _attempt("error", seed_id="s2"),
            ],
            findings_count=0,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.coverage is Coverage.NOT_EXERCISED
        assert outcome.exit_code == EXIT_CONFIG

    def test_mixed_fired_and_resisted_count_as_exercised(self) -> None:
        report = _report(
            attempts=[_attempt("finding"), _attempt("no_finding", seed_id="s2")],
            findings_count=1,
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.exercised == 2
        assert outcome.not_tested == 0
        assert outcome.coverage is Coverage.EXERCISED

    def test_default_fallbacks_field_is_zero(self) -> None:
        outcome = ScanOutcome.from_report(_report())
        assert outcome.fallbacks == 0

    def test_fallbacks_sums_the_report_breakdown(self) -> None:
        # T4: `fallbacks` is derived from `report.fallback_breakdown` (populated
        # by the engine from judge/customiser fallback events) rather than the
        # hardcoded 0 placeholder T1 shipped with — the sum across every cause.
        report = _report(
            fallback_breakdown={
                "judge_call_raised": 2,
                "judge_unparseable_output": 1,
                "customiser_fallback": 3,
            }
        )
        outcome = ScanOutcome.from_report(report)
        assert outcome.fallbacks == 6


class TestUnknownAbortReason:
    def test_scan_report_construction_rejects_unknown_abort_value(self) -> None:
        """0.7.10: ``ScanReport.aborted`` is now ``AbortReason | None`` (a real
        JSON Schema ``enum``, not a bare unconstrained string) — Pydantic
        itself rejects an unrecognised value at CONSTRUCTION time. A
        hand-edited replay fixture, a legacy artefact from an incompatible
        version, or a future typo can no longer even build a ``ScanReport``
        carrying a bogus ``aborted`` string; this used to be silently
        accepted (see the sibling test below for the ``from_report``-level
        defence this replaces as the primary guard).
        """
        with pytest.raises(ValidationError, match="some_future_reason_nobody_declared") as excinfo:
            _report(aborted="some_future_reason_nobody_declared")
        assert "budget_exceeded" in str(excinfo.value)

    def test_from_report_defensively_re_validates_a_validation_bypassed_report(self) -> None:
        """Belt-and-suspenders: a ``ScanReport`` built via ``model_construct()``
        (which skips field validation entirely — e.g. a lower-level
        deserialisation path, or a hand-rolled test double) can still carry a
        raw, unrecognised ``aborted`` string despite the field's declared
        type. ``ScanOutcome.from_report`` must not blow up with the bare
        ``ValueError`` a ``StrEnum`` raises by default; it re-validates and
        raises an actionable error naming the offending value and the
        known-good ones — the same property the pre-0.7.10 test proved
        against a normally-constructed report.
        """
        report = ScanReport.model_construct(
            target_id="t",
            provider="p",
            model="m",
            elapsed_seconds=1.0,
            attempts=[],
            findings_count=0,
            aborted="some_future_reason_nobody_declared",
            fallback_breakdown={},
            mylonite_version="0.0.0",
        )
        with pytest.raises(ValueError, match="some_future_reason_nobody_declared") as excinfo:
            ScanOutcome.from_report(report)
        assert "AbortReason" in str(excinfo.value)
        assert "budget_exceeded" in str(excinfo.value)


# --- #212: the NOT TESTED hint names the DOMINANT cause, not always credentials --


def test_dominant_cause_no_seed_arm_does_not_blame_credentials() -> None:
    """3 of 3 attempts had no seed_arm — the hint must name THAT, and must not
    suggest checking provider credentials (nothing called a provider here)."""
    report = _report(
        attempts=[
            _attempt("skipped_no_seed_arm"),
            _attempt("skipped_no_seed_arm", seed_id="s2"),
            _attempt("skipped_no_seed_arm", seed_id="s3"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "seed_arm" in outcome.operator_message
    assert "credentials" not in outcome.operator_message
    assert "This is NOT a clean result" in outcome.operator_message


def test_dominant_cause_not_applicable_names_the_seed_mismatch() -> None:
    report = _report(
        attempts=[
            _attempt("not_applicable"),
            _attempt("not_applicable", seed_id="s2"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "doesn't fit" in outcome.operator_message or "doesn't expose" in outcome.operator_message
    assert "credentials" not in outcome.operator_message


def test_dominant_cause_launch_failure_names_the_command() -> None:
    report = _report(
        attempts=[_attempt("launch_failure"), _attempt("launch_failure", seed_id="s2")],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "command:" in outcome.operator_message
    assert "credentials" not in outcome.operator_message


def test_dominant_cause_payload_not_delivered_names_seed_arm_wiring() -> None:
    report = _report(
        attempts=[
            _attempt("skipped_payload_not_delivered"),
            _attempt("skipped_payload_not_delivered", seed_id="s2"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "seed_arm" in outcome.operator_message
    assert "credentials" not in outcome.operator_message


def test_dominant_cause_no_engagement_names_the_model() -> None:
    report = _report(
        attempts=[
            _attempt("skipped_planner_no_engagement"),
            _attempt("skipped_planner_no_engagement", seed_id="s2"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "tool calls" in outcome.operator_message
    assert "credentials" not in outcome.operator_message


def test_dominant_cause_undecided_from_effect_probe_error_names_the_probe() -> None:
    """An `undecided` attempt whose fallback_cause is the effect-probe-errored
    marker (not a provider call raising) must point at the effect_probe, not
    at credentials."""
    report = _report(
        attempts=[
            _attempt("undecided", judge_evidence={"fallback_cause": "effect_probe_errored"}),
            _attempt(
                "undecided",
                seed_id="s2",
                judge_evidence={"fallback_cause": "effect_probe_errored"},
            ),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "effect_probe" in outcome.operator_message
    assert "credentials" not in outcome.operator_message


def test_dominant_cause_undecided_from_call_raised_does_blame_credentials() -> None:
    """An `undecided` attempt whose fallback_cause is call_raised (the LLM call
    itself threw) IS a real provider-call failure — credentials is the right hint."""
    report = _report(
        attempts=[
            _attempt("undecided", judge_evidence={"fallback_cause": "call_raised"}),
            _attempt("undecided", seed_id="s2", judge_evidence={"fallback_cause": "call_raised"}),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "credentials" in outcome.operator_message


def test_dominant_cause_undecided_unparseable_judge_output_names_the_judge_model() -> None:
    """A judge call that SUCCEEDED but returned unusable output is not a
    credentials problem, and is a different fix from "check the
    effect_probe" -- it points at the judge model."""
    report = _report(
        attempts=[
            _attempt("undecided", judge_evidence={"fallback_cause": "unparseable_output"}),
            _attempt(
                "undecided", seed_id="s2", judge_evidence={"fallback_cause": "unparseable_output"}
            ),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "judge model" in outcome.operator_message or "judge-model" in outcome.operator_message
    assert "credentials" not in outcome.operator_message
    assert "effect_probe" not in outcome.operator_message


def test_dominant_cause_undecided_no_adjudicator_is_not_a_defect() -> None:
    """A predicate that was inconclusive with the LLM judge disabled (routine
    in the demo's own wiring) must not be worded like a provider failure or
    an effect_probe defect."""
    from mylonite.scan.coverage import NO_ADJUDICATOR

    report = _report(
        attempts=[
            _attempt("undecided", judge_evidence={"no_adjudicator": NO_ADJUDICATOR}),
            _attempt("undecided", seed_id="s2", judge_evidence={"no_adjudicator": NO_ADJUDICATOR}),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "credentials" not in outcome.operator_message
    assert "no LLM judge was configured" in outcome.operator_message


def test_dominant_cause_generic_error_does_not_blame_credentials() -> None:
    """outcome == 'error' with no provider-shaped error_detail (a target
    subprocess crash, not a provider call) must not suggest credentials."""
    report = _report(
        attempts=[
            _attempt("error", error_detail="BrokenPipeError"),
            _attempt("error", seed_id="s2", error_detail="RuntimeError"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "credentials" not in outcome.operator_message
    assert "error_detail" in outcome.operator_message


def test_dominant_cause_provider_error_via_error_detail_blames_credentials() -> None:
    """outcome == 'error' whose error_detail names a real provider/LiteLLM
    exception class IS a provider-call failure — credentials is the right hint."""
    report = _report(
        attempts=[
            _attempt("error", error_detail="AuthenticationError"),
            _attempt("error", seed_id="s2", error_detail="AuthenticationError"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "credentials" in outcome.operator_message


def test_no_dominant_cause_falls_back_to_generic_wording() -> None:
    """No single cause accounts for a majority — generic wording, not a
    misleadingly specific single-cause hint."""
    report = _report(
        attempts=[
            _attempt("not_applicable"),
            _attempt("skipped_no_seed_arm", seed_id="s2"),
            _attempt("launch_failure", seed_id="s3"),
        ],
        findings_count=0,
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    assert "This is NOT a clean result" in outcome.operator_message
    assert "credentials" in outcome.operator_message  # the generic fallback wording


def test_budget_exceeded_has_an_actionable_operator_message() -> None:
    """The most likely abort should not be the least explained.

    `budget_exceeded` used to map to `None`, so the whole explanation an
    operator got was the bare words "aborted: budget_exceeded" from the generic
    summary line — for the one abort with an obvious remedy, and the exact
    sibling of `wall_clock_timeout`, which had a real message all along.
    """
    message = _OPERATOR_MESSAGE_BY_ABORT[AbortReason.BUDGET_EXCEEDED]
    assert message is not None
    assert "--max-llm-calls" in message, "it must name the flag that fixes it"
    assert "incomplete" in message, "and be explicit that this is not a clean result"


def test_budget_exceeded_message_does_not_wrongly_tell_a_custom_target_to_use_the_flag() -> None:
    """#205: --weakness-class WIDENS a custom target's seed
    set (adds to weakness_classes) but FILTERS a reference/bundled target's
    -- this message has no target-kind context (a bare AbortReason lookup),
    so it must not name --weakness-class alone as the fix for every target,
    which used to read as "narrow with --weakness-class" regardless of kind
    (wrong advice for a custom target, where the flag widens)."""
    message = _OPERATOR_MESSAGE_BY_ABORT[AbortReason.BUDGET_EXCEEDED]
    assert message is not None
    # Either it names BOTH remedies (flag for reference/bundled, target-file
    # weakness_classes for custom) or it avoids naming --weakness-class as a
    # narrowing device on its own.
    if "--weakness-class" in message:
        assert "weakness_classes" in message, message


# --- no-verdict attempts ----------------------------------------------------
#
# `no_finding` carries two different facts: a mechanism decided the target
# resisted, or nothing decided anything. Only the first is coverage.


@pytest.mark.parametrize(
    ("evidence", "label"),
    [
        ({"fallback_cause": "call_raised"}, "judge call raised"),
        ({"fallback_cause": "unparseable_output"}, "judge output unparseable"),
        ({"no_adjudicator": "llm_judge_disabled"}, "judge disabled, predicate inconclusive"),
    ],
)
def test_no_verdict_no_finding_is_not_trustworthy_clean(
    evidence: dict[str, str], label: str
) -> None:
    """The false-clean this fix exists to close.

    A scan whose only attempt never reached a verdict used to report
    `coverage=EXERCISED`, `trustworthy_clean=True` and exit 0 — identical to a
    genuine clean pass, because a fallback verdict hard-codes `success=False`
    and the engine records that as `no_finding`.
    """
    outcome = ScanOutcome.from_report(
        _report(attempts=[_attempt("no_finding", judge_evidence=evidence)])
    )

    assert outcome.trustworthy_clean is False, label
    assert outcome.coverage is not Coverage.EXERCISED, label
    assert outcome.not_tested == 1, label
    assert outcome.exit_code != EXIT_SUCCESS, label


def test_genuine_no_finding_is_still_trustworthy_clean() -> None:
    """The negative control: a real judged negative must stay a clean pass.

    Without this, a fix that over-fires would quietly turn every honest clean
    scan into a non-zero exit — a worse failure than the one being fixed.
    """
    outcome = ScanOutcome.from_report(
        _report(attempts=[_attempt("no_finding", judge_evidence={"confidence": "0.9"})])
    )

    assert outcome.trustworthy_clean is True
    assert outcome.coverage is Coverage.EXERCISED
    assert outcome.exit_code == EXIT_SUCCESS


def test_a_finding_is_never_treated_as_a_no_verdict_attempt() -> None:
    """Only `no_finding` can be a non-verdict; a finding required a decision."""
    outcome = ScanOutcome.from_report(
        _report(
            attempts=[_attempt("finding", judge_evidence={"fallback_cause": "call_raised"})],
            findings_count=1,
        )
    )

    assert outcome.exercised == 1
    assert outcome.not_tested == 0


def test_an_unexercised_attempt_carrying_a_no_verdict_cause_is_counted_once() -> None:
    """The two non-result categories must stay disjoint, and really can collide.

    `engine` decides the zero-engagement override from the tool-call trace
    independently of the decisive verdict, then attaches that verdict's
    `judge_evidence` whichever branch won. So a `skipped_planner_no_engagement`
    attempt genuinely can carry a no-verdict cause — the shipped demo fixtures
    contain exactly that shape.

    It must be counted as NOT_TESTED and nothing else: the agent never engaged,
    which is a stronger and more specific reason than "nothing adjudicated it".
    `attempt_reached_no_verdict`'s `no_finding` guard is what enforces this, and
    the demo's coverage note adds the two categories together — so were they ever
    to overlap, it would report more non-results than there are attempts.
    """
    from mylonite.scan.coverage import NO_ADJUDICATOR, attempt_reached_no_verdict

    attempt = _attempt(
        "skipped_planner_no_engagement",
        judge_evidence={
            "predicate": "web_fetch_to_unauthorised_url",
            "no_adjudicator": NO_ADJUDICATOR,
        },
    )

    assert not attempt_reached_no_verdict(attempt)

    outcome = ScanOutcome.from_report(_report(attempts=[attempt]))
    assert outcome.not_tested == 1
    assert outcome.exercised == 0


# --- `undecided` and `launch_failure` as first-class outcomes (issue #144) ----


def test_undecided_is_not_tested_and_not_resistance() -> None:
    """The whole point of the contract bump: the literal alone now carries the
    fact. A consumer reading only `outcome` can no longer mistake "nothing
    decided this" for "the guard held"."""
    from mylonite.scan.coverage import attempt_reached_no_verdict

    attempt = _attempt("undecided")

    assert ATTEMPT_CLASS["undecided"] is AttemptClass.NOT_TESTED
    assert attempt_reached_no_verdict(attempt) is True

    outcome = ScanOutcome.from_report(_report(attempts=[attempt]))
    assert outcome.not_tested == 1
    assert outcome.exercised == 0
    assert outcome.trustworthy_clean is False


def test_a_legacy_no_verdict_attempt_is_still_recognised() -> None:
    """Back-compat, and it matters: `report`, `validate` and the testkit all read
    artefacts off DISK. A report written by an earlier version spells this
    `no_finding` plus a cause key, and dropping that path would silently start
    reading old no-verdict attempts as clean resistance."""
    from mylonite.scan.coverage import NO_ADJUDICATOR, attempt_reached_no_verdict

    legacy = _attempt("no_finding", judge_evidence={"no_adjudicator": NO_ADJUDICATOR})

    assert attempt_reached_no_verdict(legacy) is True


def test_launch_failure_is_not_tested() -> None:
    """A target whose command never started exercised nothing — and the remedy
    is to fix the command, not the planner."""
    attempt = _attempt("launch_failure")

    assert ATTEMPT_CLASS["launch_failure"] is AttemptClass.NOT_TESTED
    outcome = ScanOutcome.from_report(_report(attempts=[attempt]))
    assert outcome.not_tested == 1
    assert outcome.trustworthy_clean is False


# --- adjudication_counts: how verdicts were reached -------------------------


def _decided(outcome: ScanAttemptOutcome, mechanism: str | None, **kw: object) -> ScanAttempt:
    return ScanAttempt(
        seed_id="s",
        pattern_id="s",
        outcome=outcome,
        verdict_mechanism=mechanism,  # type: ignore[arg-type]
        verdict_reason=None,
        judge_evidence=kw.get("judge_evidence") or {},  # type: ignore[arg-type]
    )


def test_adjudication_counts_splits_decided_attempts_by_mechanism() -> None:
    from mylonite.scan.coverage import adjudication_counts

    report = _report(
        attempts=[
            _decided("finding", "predicate"),
            _decided("no_finding", "predicate"),
            _decided("no_finding", "llm"),
        ],
        findings_count=1,
    )
    counts = adjudication_counts(report)
    assert (counts.predicate, counts.llm, counts.no_verdict) == (2, 1, 0)
    assert counts.decided == 3
    assert counts.total_attempts == 3


def test_adjudication_counts_excludes_attempts_that_never_ran() -> None:
    """NOT_TESTED outcomes carry a mechanism in some cases (not_applicable,
    no-engagement) but settled nothing about the attack, so they are not decided."""
    from mylonite.scan.coverage import adjudication_counts

    report = _report(
        attempts=[
            _decided("not_applicable", "predicate"),
            _decided("skipped_planner_no_engagement", "predicate"),
            _decided("error", None),
            _decided("skipped_dry_run", None),
        ]
    )
    counts = adjudication_counts(report)
    assert counts.decided == 0
    assert counts.no_verdict == 0
    assert counts.total_attempts == 4


def test_adjudication_counts_reports_attempts_that_reached_no_verdict() -> None:
    """Both spellings of "no mechanism decided this": the current ``undecided``
    literal and an earlier version's ``no_finding`` plus a fallback cause."""
    from mylonite.scan.coverage import adjudication_counts

    report = _report(
        attempts=[
            _decided("undecided", "llm"),
            _decided("no_finding", "llm", judge_evidence={"fallback_cause": "unparseable"}),
            _decided("no_finding", "llm"),
        ]
    )
    counts = adjudication_counts(report)
    assert counts.no_verdict == 2
    assert counts.llm == 1
    assert counts.decided == 1


def test_findings_first_moves_finding_outcomes_to_the_front_stably() -> None:
    """#206: the console summary must not bury a finding under whatever
    attempts happened to run first when the scan aborted early."""
    from mylonite.scan.coverage import findings_first

    a1 = _attempt("no_finding", seed_id="a1")
    a2 = _attempt("finding", seed_id="a2")
    a3 = _attempt("not_applicable", seed_id="a3")
    a4 = _attempt("finding", seed_id="a4")

    reordered = findings_first([a1, a2, a3, a4])

    assert [a.seed_id for a in reordered] == ["a2", "a4", "a1", "a3"]


def test_findings_first_no_findings_is_a_no_op() -> None:
    from mylonite.scan.coverage import findings_first

    attempts = [_attempt("no_finding", seed_id="a1"), _attempt("not_applicable", seed_id="a2")]
    assert findings_first(attempts) == attempts


# --- #191: a rate-limit or unreachable-provider abort says what to do ----------


def test_a_rate_limit_abort_names_provider_model_and_remedies() -> None:
    message = provider_abort_message(
        "rate_limit", provider="anthropic", model="anthropic/claude-test"
    )
    assert message is not None
    assert message.startswith("error: [MYL-ABT-002] ")
    assert "rate-limited" in message
    assert "provider anthropic, model anthropic/claude-test" in message
    assert "--max-concurrent" in message
    assert "--max-llm-calls" in message
    assert "quota" in message


def test_a_network_abort_points_at_connectivity_not_credentials() -> None:
    message = provider_abort_message("network", provider="openai", model="openai/gpt-test")
    assert message is not None
    assert "could not reach the LLM provider" in message
    assert "provider openai, model openai/gpt-test" in message
    assert "enterprise-networking" in message


@pytest.mark.parametrize("category", [None, "auth", "unknown", "bad_request"])
def test_other_causes_keep_the_generic_message(category: str | None) -> None:
    assert provider_abort_message(category, provider="anthropic", model="m") is None


def test_the_message_never_carries_a_key_embedded_in_the_model_string() -> None:
    key = "sk-ant-api03-" + "z" * 40  # pragma: allowlist secret
    message = provider_abort_message(
        "rate_limit", provider="anthropic", model=f"anthropic/claude?api_key={key}"
    )
    assert message is not None
    assert key not in message


def test_the_engine_detail_replaces_the_generic_provider_text() -> None:
    detail = provider_abort_message("rate_limit", provider="anthropic", model="m")
    outcome = ScanOutcome.from_report(_report(aborted="provider_unreachable"), abort_detail=detail)
    assert outcome.exit_code == EXIT_PROVIDER
    assert outcome.operator_message == detail
