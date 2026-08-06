"""The single typed authority for "did this scan actually work".

Root cause (A1 in the 0.7.7 remediation plan): ``ScanReport.aborted`` (in
``contracts/_types.py``) is a nullable magic string with 5 values, and
``ScanAttempt.outcome`` is a 9-value ``Literal``. Six different consumers
(``cli.py``'s ``scan``/``gate``/``ablate`` commands, ``artefacts.py``'s
``render_summary``, and others) each re-derive "did this scan actually work"
from a different lossy projection of those two fields — most visibly,
``artefacts.NOT_TESTED_OUTCOMES`` is an ALLOWLIST covering only 2 of the 9
``ScanAttemptOutcome`` values, so an ``outcome="error"`` attempt (an
exception during invocation/judging — not in the allowlist) silently renders
as "tested and clean" rather than "not exercised". A scan where every
attempt errored can render "N attempts * 0 findings" and exit 0 — a
false-clean.

This module fixes that by being the ONE place that turns a ``ScanReport``
into a verdict: :func:`ScanOutcome.from_report`. Every command that needs to
know "did this scan actually work" should go through it (wiring existing
call sites is later work — this task only introduces the type).

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
    #: Populated by a later task (T4's fallback-classification work); a scan
    #: built here always reports 0 until that wiring lands.
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
        """The ONE place that turns a ``ScanReport`` into a verdict."""
        abort = AbortReason(report.aborted) if report.aborted else None

        exercised = 0
        not_tested = 0
        for attempt in report.attempts:
            attempt_class = ATTEMPT_CLASS[attempt.outcome]
            if attempt_class in (
                AttemptClass.EXERCISED_FIRED,
                AttemptClass.EXERCISED_RESISTED,
            ):
                exercised += 1
            elif attempt_class is AttemptClass.NOT_TESTED:
                not_tested += 1
            # INTENTIONALLY_SKIPPED counts toward neither — it's not a gap.

        if exercised == 0:
            coverage = Coverage.NOT_EXERCISED
        elif abort is not None or not_tested > 0:
            coverage = Coverage.PARTIAL
        else:
            coverage = Coverage.EXERCISED

        if abort is not None:
            exit_code = _EXIT_CODE_BY_ABORT[abort]
            operator_message = _OPERATOR_MESSAGE_BY_ABORT[abort]
        else:
            exit_code = _EXIT_SUCCESS
            operator_message = None

        return cls(
            coverage=coverage,
            abort=abort,
            exercised=exercised,
            not_tested=not_tested,
            findings=report.findings_count,
            fallbacks=0,
            exit_code=exit_code,
            operator_message=operator_message,
        )
