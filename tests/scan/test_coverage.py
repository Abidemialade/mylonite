"""Tests for ``mylonite.scan.coverage`` — the single typed authority for

"did this scan actually work". See ``scan/coverage.py`` module docstring for
the root-cause motivation (six consumers each re-deriving "clean" from a
different lossy projection of ``ScanReport``).
"""

from __future__ import annotations

from typing import get_args

import pytest

from mylonite.contracts._types import ScanAttempt, ScanAttemptOutcome, ScanReport
from mylonite.scan.coverage import (
    ATTEMPT_CLASS,
    AbortReason,
    AttemptClass,
    Coverage,
    ScanOutcome,
)

EXIT_SUCCESS = 0
EXIT_CONFIG = 2
EXIT_BUDGET = 3
EXIT_PROVIDER = 4


def _attempt(outcome: ScanAttemptOutcome, *, seed_id: str = "s1") -> ScanAttempt:
    return ScanAttempt(
        seed_id=seed_id,
        pattern_id=seed_id,
        outcome=outcome,
        verdict_mechanism=None,
        verdict_reason=None,
    )


def _report(
    *,
    attempts: list[ScanAttempt] | None = None,
    findings_count: int = 0,
    aborted: str | None = None,
) -> ScanReport:
    return ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=attempts or [],
        findings_count=findings_count,
        aborted=aborted,
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


class TestUnknownAbortReason:
    def test_unrecognised_aborted_value_raises_actionable_error(self) -> None:
        # A hand-edited replay fixture, a legacy artefact from an incompatible
        # version, or a future typo could set `aborted` to something outside
        # the 5 known AbortReason values. The bare `ValueError` StrEnum raises
        # by default ("'x' is not a valid AbortReason") is undiagnosable once
        # ScanReports are routinely loaded back off disk — this must name the
        # offending value and the known-good ones instead.
        report = _report(aborted="some_future_reason_nobody_declared")
        with pytest.raises(ValueError, match="some_future_reason_nobody_declared") as excinfo:
            ScanOutcome.from_report(report)
        assert "AbortReason" in str(excinfo.value)
        assert "budget_exceeded" in str(excinfo.value)
