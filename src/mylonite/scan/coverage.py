"""The single typed authority for "did this scan actually work".

Root cause (A1 in the 0.7.7 remediation plan): ``ScanReport.aborted`` (in
``contracts/_types.py``) is a nullable magic string with 5 values, and
``ScanAttempt.outcome`` is a 9-value ``Literal``. Six different consumers
(``cli.py``'s ``scan``/``gate``/``ablate`` commands, ``artefacts.py``'s
``render_summary``, and others) each re-derive "did this scan actually work"
from a different lossy projection of those two fields — most visibly,
``artefacts.NOT_TESTED_OUTCOMES`` used to be a hand-maintained ALLOWLIST
covering only 2 of the 9 ``ScanAttemptOutcome`` values, so an
``outcome="error"`` attempt (an exception during invocation/judging — not in
the allowlist) silently rendered as "tested and clean" rather than "not
exercised". A scan where every attempt errored could render "N attempts * 0
findings" and exit 0 — a false-clean. ``artefacts.NOT_TESTED_OUTCOMES`` is
now derived from :data:`ATTEMPT_CLASS` below instead of maintaining its own
parallel list.

This module fixes that by being the ONE place that turns a ``ScanReport``
into a verdict: :func:`ScanOutcome.from_report`. Every command that needs to
know "did this scan actually work" should go through it (wiring existing
call sites into ``ScanOutcome`` itself — e.g. ``gate``/``ablate``/``report``/
``demo`` — is later work; this task's own CLI-facing fix is limited to
``artefacts.NOT_TESTED_OUTCOMES``, described above).

Pure data/logic — no CLI concerns. Must not import ``typer`` or
``mylonite.cli``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum, auto
from typing import Final, get_args

from mylonite.contracts._types import ScanAttemptOutcome, ScanReport

# --- Abort reasons -------------------------------------------------------------


class AbortReason(StrEnum):
    """Why a scan terminated early or ran nothing.

    ``StrEnum`` (a str-backed enum, matching the ``_Framework`` convention
    already used in ``cli.py``) so ``AbortReason.X.value`` matches the
    existing wire format on ``ScanReport.aborted`` (a bare ``str | None`` —
    NOT a contract change) exactly, and so ``AbortReason.X == "x"``-style
    comparisons keep working during the transition while other call sites
    still compare raw strings.
    """

    BUDGET_EXCEEDED = "budget_exceeded"
    PROVIDER_UNREACHABLE = "provider_unreachable"
    DESCRIBE_FAILED = "describe_failed"
    NO_PAYLOADS = "no_payloads"
    WALL_CLOCK_TIMEOUT = "wall_clock_timeout"


# --- Attempt classification ----------------------------------------------------


class AttemptClass(Enum):
    """What a single ``ScanAttempt.outcome`` actually tells us about coverage."""

    #: The attack ran and the target failed to resist it.
    EXERCISED_FIRED = auto()
    #: The attack ran and the target resisted it — a genuine negative result.
    EXERCISED_RESISTED = auto()
    #: The attack did NOT run (bad metadata, unresolvable seed, planner
    #: failure, no seed_arm, payload never delivered, or an outright
    #: exception) — this attempt proved nothing about the target.
    NOT_TESTED = auto()
    #: The attack was deliberately not attempted by design (``--dry-run``),
    #: not because of a gap. Distinct from NOT_TESTED: a dry run reflects an
    #: operator choice, not a coverage hole.
    INTENTIONALLY_SKIPPED = auto()


# Total map from EVERY ScanAttemptOutcome literal value to an AttemptClass.
# Keep this exhaustive — the assertion below enforces it at import time.
ATTEMPT_CLASS: Final[dict[str, AttemptClass]] = {
    "finding": AttemptClass.EXERCISED_FIRED,
    "no_finding": AttemptClass.EXERCISED_RESISTED,
    # Structural skips: the seed's payload metadata was invalid, so the attack
    # was never customised or invoked for this seed.
    "skipped_invalid_metadata": AttemptClass.NOT_TESTED,
    # The seed needed customisation but couldn't be resolved from the
    # catalogue — the attack never ran.
    "skipped_unknown_seed": AttemptClass.NOT_TESTED,
    # adapter.invoke() raised AdapterInvocationSkipped (A3) — the planner
    # failed before the attack could be delivered.
    "skipped_planner_failure": AttemptClass.NOT_TESTED,
    # No seed_arm was available to plant the payload — nothing was exercised.
    "skipped_no_seed_arm": AttemptClass.NOT_TESTED,
    # The target confirmed the planted payload was never delivered.
    "skipped_payload_not_delivered": AttemptClass.NOT_TESTED,
    # Deliberate: --dry-run means no customisation or invocation was ever
    # attempted, by design — not a coverage gap.
    "skipped_dry_run": AttemptClass.INTENTIONALLY_SKIPPED,
    # An exception during invoke/judge (THE false-clean bug this task fixes:
    # previously absent from artefacts.NOT_TESTED_OUTCOMES, so an all-error
    # scan rendered as clean).
    "error": AttemptClass.NOT_TESTED,
}

# Import-time exhaustiveness guard — this is the whole point of the task.
# Raises (not `assert`, which `-O` can strip) so a future ScanAttemptOutcome
# addition that isn't classified here fails LOUDLY and immediately, rather
# than silently defaulting new outcomes to "clean".
if set(ATTEMPT_CLASS) != set(get_args(ScanAttemptOutcome)):
    missing = set(get_args(ScanAttemptOutcome)) - set(ATTEMPT_CLASS)
    extra = set(ATTEMPT_CLASS) - set(get_args(ScanAttemptOutcome))
    raise RuntimeError(
        "mylonite.scan.coverage.ATTEMPT_CLASS is out of sync with "
        f"ScanAttemptOutcome: missing={sorted(missing)} extra={sorted(extra)}. "
        "Every ScanAttemptOutcome literal must be classified here."
    )


# --- Coverage verdict ------------------------------------------------------------


class Coverage(Enum):
    """Did the scan actually exercise what it set out to?"""

    #: Every attempt was exercised (fired or resisted); nothing was aborted
    #: or structurally skipped as a gap.
    EXERCISED = auto()
    #: Some attempts were exercised, but the scan was aborted mid-run or some
    #: attempts were NOT_TESTED — coverage is incomplete, not absent.
    PARTIAL = auto()
    #: Nothing was exercised at all.
    NOT_EXERCISED = auto()


# --- Exit-code / message mapping ------------------------------------------------
#
# Mirrors cli.py's existing 5-way `scan` command mapping (search `EXIT_BUDGET`,
# `EXIT_PROVIDER`, `EXIT_CONFIG`, `EXIT_SUCCESS` there) exactly — extracted,
# not reinterpreted. Duplicated as plain ints here (rather than importing
# cli.py) because this module must stay free of CLI/typer concerns; if the
# cli.py constants ever change, keep this mapping in sync.
_EXIT_SUCCESS: Final = 0
_EXIT_CONFIG: Final = 2
_EXIT_BUDGET: Final = 3
_EXIT_PROVIDER: Final = 4

_EXIT_CODE_BY_ABORT: Final[dict[AbortReason, int]] = {
    AbortReason.BUDGET_EXCEEDED: _EXIT_BUDGET,
    AbortReason.PROVIDER_UNREACHABLE: _EXIT_PROVIDER,
    # These three all map to EXIT_CONFIG in cli.py today — distinct reasons,
    # same exit code (only budget/provider get their own).
    AbortReason.NO_PAYLOADS: _EXIT_CONFIG,
    AbortReason.DESCRIBE_FAILED: _EXIT_CONFIG,
    AbortReason.WALL_CLOCK_TIMEOUT: _EXIT_CONFIG,
}

# Verbatim (or near-verbatim) copies of the stderr lines cli.py's `scan`
# command prints via `echo_err` for each abort reason. budget_exceeded and
# provider_unreachable have no dedicated `echo_err` message in cli.py today —
# they rely on render_summary's generic "aborted: <reason>" line — so those
# map to `None` here to match current behaviour exactly.
_OPERATOR_MESSAGE_BY_ABORT: Final[dict[AbortReason, str | None]] = {
    AbortReason.BUDGET_EXCEEDED: None,
    AbortReason.PROVIDER_UNREACHABLE: None,
    AbortReason.NO_PAYLOADS: (
        "error: no seeds were applicable to this target, so nothing was scanned. "
        "If this is a custom MCP app, declare which weakness classes it exposes "
        "via --target-file (weakness_classes) or --weakness-class."
    ),
    AbortReason.DESCRIBE_FAILED: (
        "error: could not describe the target (adapter.describe() failed); "
        "nothing was scanned. Check the target command/scope and connectivity."
    ),
    AbortReason.WALL_CLOCK_TIMEOUT: (
        "error: scan exceeded its wall-clock budget and stopped early; coverage "
        "is incomplete. Raise the timeout or narrow the scan, then re-run."
    ),
}

# --- Untrustworthy-without-a-formal-abort ---------------------------------------
#
# `PROVIDER_UNREACHABLE` (the `aborted` field) only fires once the engine sees
# `consecutive_failures >= DEFAULT_PROVIDER_FAILURE_THRESHOLD` (3, in
# scan/engine.py). A target with fewer than 3 applicable attempts (a narrow
# --weakness-class filter, or just few seeds) can run start-to-finish with
# every single attempt erroring — e.g. missing/invalid provider credentials —
# without ever tripping that threshold. `report.aborted` then stays `None`,
# `findings_count` is 0, and nothing was genuinely exercised: exactly the
# shape a real clean pass has, EXCEPT `trustworthy_clean` is correctly False.
# Without this, `exit_code` fell through to the `abort is None` branch below
# and silently returned `_EXIT_SUCCESS` — indistinguishable from a real clean
# pass to every consumer (this is the exact fail-open bug `gate` hit).
#
# The rule: whenever nothing trustworthy came out of the scan (coverage never
# reached EXERCISED) AND nothing was found, `exit_code` must not be 0 — no
# matter whether a formal `AbortReason` was ever recorded. A genuine finding
# (`findings_count > 0`) is excluded: that's still real evidence worth an
# EXIT_SUCCESS at this layer, mirroring `scan`'s own convention (only
# `aborted` drives a non-zero exit there; finding something is not, by
# itself, treated as failure — see cli.py's `scan` command and
# `test_findings_still_exit_success_at_this_layer`).
_EXIT_INCOMPLETE_NO_ABORT: Final = _EXIT_CONFIG

_INCOMPLETE_COVERAGE_NO_ABORT_MESSAGE: Final = (
    "error: coverage was incomplete or absent and nothing was found, but the scan "
    "was never formally aborted (e.g. too few applicable attempts to trip the "
    "provider-failure-threshold abort). This is NOT a clean result — check each "
    "attempt's verdict_reason/error_detail (a common cause is missing or invalid "
    "provider credentials), then re-run."
)


@dataclass(frozen=True)
class ScanOutcome:
    """The verdict for one scan: coverage, exit code, and operator messaging.

    The ONE place that turns a ``ScanReport`` into "did this actually work".
    Build via :meth:`from_report`; every command that needs that judgment
    should go through this rather than re-deriving it from ``report.aborted``
    or ``report.attempts`` directly.
    """

    coverage: Coverage
    abort: AbortReason | None
    exercised: int
    not_tested: int
    findings: int
    #: Total fallback events across every cause in ``report.fallback_breakdown``
    #: (e.g. ``judge_call_raised``, ``judge_unparseable_output``,
    #: ``customiser_fallback``) — every judge/customiser LLM call that degraded
    #: to a fallback verdict rather than a genuine parse, summed. T4 (root-cause
    #: remediation) is what makes this field meaningful: before T4, EVERY LLM-call
    #: exception (including non-recoverable ones — auth/tls/context_window) fed
    #: this same breakdown, so a wrong API key and a one-off network blip were
    #: indistinguishable here. T4 re-raises the non-recoverable categories
    #: instead (see ``scan/_llm.py``), so what lands in ``fallback_breakdown`` —
    #: and therefore this count — is now only genuinely transient degradations.
    fallbacks: int
    exit_code: int
    operator_message: str | None

    @property
    def trustworthy_clean(self) -> bool:
        """True only if this is a genuine, meaningful clean result.

        i.e. the scan actually ran to completion (wasn't aborted), every
        attempt was exercised (none were silently NOT_TESTED), and it found
        nothing. This is the specific check that closes the false-clean bug:
        a report full of ``outcome="error"`` attempts and no ``aborted`` used
        to look identical to a real clean pass — it no longer does, because
        those attempts drag ``coverage`` down to ``PARTIAL``/``NOT_EXERCISED``.
        """
        return self.abort is None and self.coverage is Coverage.EXERCISED and self.findings == 0

    @classmethod
    def from_report(cls, report: ScanReport) -> ScanOutcome:
        """The ONE place that turns a ``ScanReport`` into a verdict.

        Raises :class:`ValueError` with an actionable message if
        ``report.aborted`` is set to something other than one of the 5 known
        :class:`AbortReason` values — e.g. a hand-edited replay fixture, a
        legacy artefact from a version that used a different string, or a
        future typo. A bare ``ValueError: 'x' is not a valid AbortReason``
        would be undiagnosable once ``ScanReport``s are routinely loaded back
        off disk; naming the field and the known-good values here is not.
        """
        if report.aborted:
            try:
                abort: AbortReason | None = AbortReason(report.aborted)
            except ValueError as exc:
                known = sorted(r.value for r in AbortReason)
                raise ValueError(
                    f"ScanReport.aborted={report.aborted!r} is not a recognised "
                    f"AbortReason (known values: {known}). This report may be from "
                    "an incompatible mylonite version, or hand-edited/corrupted."
                ) from exc
        else:
            abort = None

        exercised = 0
        not_tested = 0
        intentionally_skipped = 0
        for attempt in report.attempts:
            attempt_class = ATTEMPT_CLASS[attempt.outcome]
            if attempt_class in (
                AttemptClass.EXERCISED_FIRED,
                AttemptClass.EXERCISED_RESISTED,
            ):
                exercised += 1
            elif attempt_class is AttemptClass.NOT_TESTED:
                not_tested += 1
            elif attempt_class is AttemptClass.INTENTIONALLY_SKIPPED:
                intentionally_skipped += 1

        if exercised == 0:
            coverage = Coverage.NOT_EXERCISED
        elif abort is not None or not_tested > 0:
            coverage = Coverage.PARTIAL
        else:
            coverage = Coverage.EXERCISED

        # A ``--dry-run`` report is EVERY attempt coming back
        # `skipped_dry_run` (INTENTIONALLY_SKIPPED) — deliberately not
        # exercised BY DESIGN, not a coverage gap (see AttemptClass's
        # docstring). It collapses to `coverage is NOT_EXERCISED` just like a
        # genuine "nothing ran" gap does, so it must be excluded from the
        # untrustworthy-without-abort branch below or `--dry-run` would start
        # exiting non-zero for every scan.
        is_dry_run_shaped = (
            bool(report.attempts)
            and intentionally_skipped == len(report.attempts)
            and exercised == 0
            and not_tested == 0
        )

        if abort is not None:
            exit_code = _EXIT_CODE_BY_ABORT[abort]
            operator_message = _OPERATOR_MESSAGE_BY_ABORT[abort]
        elif (
            coverage is not Coverage.EXERCISED
            and report.findings_count == 0
            and not is_dry_run_shaped
        ):
            # No formal AbortReason was recorded, yet coverage never reached
            # EXERCISED (PARTIAL or NOT_EXERCISED) and nothing was found. Must
            # not be indistinguishable from a genuine clean pass — see the
            # "Untrustworthy-without-a-formal-abort" note above.
            exit_code = _EXIT_INCOMPLETE_NO_ABORT
            operator_message = _INCOMPLETE_COVERAGE_NO_ABORT_MESSAGE
        else:
            exit_code = _EXIT_SUCCESS
            operator_message = None

        return cls(
            coverage=coverage,
            abort=abort,
            exercised=exercised,
            not_tested=not_tested,
            findings=report.findings_count,
            fallbacks=sum(report.fallback_breakdown.values()),
            exit_code=exit_code,
            operator_message=operator_message,
        )
