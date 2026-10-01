"""One summary line per weakness class: what the scan showed about that class.

Each class reads as one of four statuses:

* ``FINDING``: at least one attempt in the class fired. Its proof levels
  (``effect-confirmed``, ``dispatched``, ``dispatched-tool-linked``) say how
  strongly.
* ``NOT TESTED``: nothing fired, and at least one attempt in the class proved
  nothing (no verdict, never ran, never engaged). Part of the class is
  unproven, so the class is never read as resisted. The reason codes say why.
* ``RESISTED (server-reported)``: every attempt was decided and resisted, and
  at least one negative rests only on the server's own reply (an error, or a
  reply that held the action). The ``MYL-SRV-*`` codes say which.
* ``RESISTED``: every attempt was decided and resisted, on the trace or on a
  calibrated observer.

The summary is computed from the report's attempts alone (plus, when the
caller has one, the target's calibration summary), so ``mylonite report`` on a
saved scan directory gives the same answer the scan printed. Attempts with no
``trace_outcome`` (reference and REST targets, reports written by earlier
versions) carry no proof level and no server-reported label, so their classes
read exactly as their outcomes always did.

Exit codes do not read this summary.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from mylonite.contracts import ScanAttempt, ScanReport
from mylonite.scan.coverage import (
    ATTEMPT_CLASS,
    MODULE_LOAD_FAILURE_KEY,
    NO_ATTACK_EMITTED_KEY,
    AttemptClass,
    attempt_reached_no_verdict,
    reason_code_for_attempt,
)
from mylonite.scan.evidence_tier import EVIDENCE_TIERS, tier_counts
from mylonite.scan.seeds import SEED_CATALOGUE

STATUS_FINDING: Final = "FINDING"
STATUS_RESISTED: Final = "RESISTED"
STATUS_RESISTED_SERVER_REPORTED: Final = "RESISTED (server-reported)"
STATUS_NOT_TESTED: Final = "NOT TESTED"

#: The class of an attempt whose seed id resolves to no known class.
UNKNOWN_CLASS: Final = "unknown"

#: Proof levels, strongest first.
PROOF_LEVEL_ORDER: Final[tuple[str, ...]] = (
    "effect-confirmed",
    "dispatched",
    "dispatched-tool-linked",
)

#: The class whose seed control (plant, then recall) calibration runs.
_SEED_CONTROL_CLASS: Final = "W2"

_SEED_WEAKNESS: Final[dict[str, str]] = {s.pattern_id: s.weakness for s in SEED_CATALOGUE}
#: Descriptor-synthesised seeds name their class: ``synth-w4-unconfirmed-<tool>``.
_SYNTH_SEED_RE: Final = re.compile(r"^synth-(w\d)-")


@dataclass(frozen=True)
class CalibrationSummary:
    """What calibration proved about a target's effect probe, as plain data.

    Built from the plugin's ``CalibrationResult`` by the caller, and written to
    and read back from ``verdicts.json``, so this module never imports the
    plugin layer.
    """

    #: ``certified`` | ``failed`` | ``no_probe`` | ``not_authorized``.
    status: str
    #: The probe's own code (``MYL-INC-002`` to ``MYL-INC-005``), if any.
    reason_code: str | None
    #: The seed control's status: ``passed`` | ``failed`` | ``not_run`` | ``not_declared``.
    seed_status: str
    #: ``MYL-INC-006`` or ``MYL-INC-007``, if any.
    seed_reason_code: str | None
    #: The tools the probe was shown to see a write through.
    certified_tools: tuple[str, ...] = ()

    @property
    def calibrated(self) -> bool:
        return self.status == "certified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "seed_control": {"status": self.seed_status, "reason_code": self.seed_reason_code},
            "certified_tools": list(self.certified_tools),
        }

    @classmethod
    def from_dict(cls, data: object) -> CalibrationSummary | None:
        """Read :meth:`to_dict`'s shape back; ``None`` for anything malformed."""
        if not isinstance(data, Mapping):
            return None
        seed = data.get("seed_control")
        tools = data.get("certified_tools", [])
        status = data.get("status")
        reason = data.get("reason_code")
        if not isinstance(seed, Mapping) or not isinstance(status, str):
            return None
        seed_status = seed.get("status")
        seed_reason = seed.get("reason_code")
        if not isinstance(seed_status, str):
            return None
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            return None
        if not all(c is None or isinstance(c, str) for c in (reason, seed_reason)):
            return None
        return cls(
            status=status,
            reason_code=reason,
            seed_status=seed_status,
            seed_reason_code=seed_reason,
            certified_tools=tuple(tools),
        )


@dataclass(frozen=True)
class ClassVerdict:
    """The summary for one weakness class."""

    weakness: str
    status: str
    #: Every reason code behind the status, sorted. Empty for a clean
    #: ``RESISTED`` or a ``FINDING``.
    codes: tuple[str, ...]
    #: The proof levels of the class's findings, strongest first.
    proof_levels: tuple[str, ...]
    findings: int
    resisted: int
    #: Resisted attempts whose negative rests only on the server's reply.
    server_reported: int
    not_tested: int
    #: Attempts decided by the trace rule (they carry a ``trace_outcome``).
    trace_decided: int = field(default=0)
    #: The class's findings counted by evidence tier, every tier present,
    #: strongest first (see ``scan/evidence_tier.py``).
    evidence_tiers: tuple[tuple[str, int], ...] = field(
        default=tuple((tier, 0) for tier in EVIDENCE_TIERS)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "weakness": self.weakness,
            "status": self.status,
            "codes": list(self.codes),
            "proof_levels": list(self.proof_levels),
            "counts": {
                "finding": self.findings,
                "resisted": self.resisted,
                "server_reported": self.server_reported,
                "not_tested": self.not_tested,
            },
            "evidence_tiers": dict(self.evidence_tiers),
            "trace_decided": self.trace_decided,
        }


def weakness_of(attempt: ScanAttempt, exploit_weakness: Mapping[str, str] | None = None) -> str:
    """The weakness class an attempt belongs to.

    From the bundled seed catalogue, then a synthesised seed's own id, then
    ``exploit_weakness`` (pattern id -> class, from the exploit files a finding
    wrote), and :data:`UNKNOWN_CLASS` otherwise. An attempt the engine recorded
    for an attack module that failed to load, or for a class no module emitted
    an attack for (#221), names its class in its evidence
    (:data:`UNKNOWN_CLASS` when the module's classes could not be known).
    """
    if attempt.judge_evidence.get(MODULE_LOAD_FAILURE_KEY) or attempt.judge_evidence.get(
        NO_ATTACK_EMITTED_KEY
    ):
        return attempt.judge_evidence.get("weakness") or UNKNOWN_CLASS
    for key in (attempt.seed_id, attempt.pattern_id):
        if key in _SEED_WEAKNESS:
            return _SEED_WEAKNESS[key]
        match = _SYNTH_SEED_RE.match(key)
        if match:
            return match.group(1).upper()
    if exploit_weakness:
        for key in (attempt.pattern_id, attempt.seed_id):
            if key in exploit_weakness:
                return exploit_weakness[key]
    return UNKNOWN_CLASS


def _ordered_proof_levels(levels: set[str]) -> tuple[str, ...]:
    known = [level for level in PROOF_LEVEL_ORDER if level in levels]
    return (*known, *sorted(levels - set(PROOF_LEVEL_ORDER)))


def _calibration_codes(
    weakness: str, attempts: Sequence[ScanAttempt], calibration: CalibrationSummary | None
) -> set[str]:
    """Calibration's codes that explain this class: the probe's own code when a
    trace-decided attempt in it ran uncalibrated, and the seed control's code
    on the class the seed control serves. They never change the status: an
    uncalibrated probe only fails to clear a dispatch."""
    if calibration is None:
        return set()
    codes: set[str] = set()
    uncalibrated = any(
        a.judge_evidence.get("trace_outcome") and a.judge_evidence.get("calibrated") != "true"
        for a in attempts
    )
    if uncalibrated and calibration.reason_code:
        codes.add(calibration.reason_code)
    if weakness == _SEED_CONTROL_CLASS and calibration.seed_reason_code:
        codes.add(calibration.seed_reason_code)
    return codes


def _one_class(
    weakness: str, attempts: Sequence[ScanAttempt], calibration: CalibrationSummary | None
) -> ClassVerdict:
    findings = resisted = server_reported = not_tested = 0
    codes: set[str] = set()
    proof_levels: set[str] = set()
    for attempt in attempts:
        evidence = attempt.judge_evidence
        cls = ATTEMPT_CLASS.get(attempt.outcome)
        if cls is AttemptClass.EXERCISED_FIRED:
            findings += 1
            if evidence.get("proof_level"):
                proof_levels.add(evidence["proof_level"])
        elif cls is AttemptClass.EXERCISED_RESISTED and not attempt_reached_no_verdict(attempt):
            resisted += 1
            if evidence.get("negative_basis") == "server-reported":
                server_reported += 1
                if evidence.get("reason_code"):
                    codes.add(evidence["reason_code"])
        else:
            # NOT_TESTED, or a pre-`undecided` report's no-verdict no_finding.
            not_tested += 1
            code = reason_code_for_attempt(attempt)
            if code is None and attempt_reached_no_verdict(attempt):
                code = reason_code_for_attempt(attempt.model_copy(update={"outcome": "undecided"}))
            if code is not None:
                codes.add(code)

    if findings:
        status = STATUS_FINDING
        codes = set()
    else:
        if not_tested:
            status = STATUS_NOT_TESTED
        elif server_reported:
            status = STATUS_RESISTED_SERVER_REPORTED
        else:
            status = STATUS_RESISTED
        codes |= _calibration_codes(weakness, attempts, calibration)

    return ClassVerdict(
        weakness=weakness,
        status=status,
        codes=tuple(sorted(codes)),
        proof_levels=_ordered_proof_levels(proof_levels),
        findings=findings,
        resisted=resisted,
        server_reported=server_reported,
        not_tested=not_tested,
        trace_decided=sum(1 for a in attempts if a.judge_evidence.get("trace_outcome")),
        evidence_tiers=tuple(tier_counts(a for a in attempts if a.outcome == "finding").items()),
    )


def class_verdicts(
    report: ScanReport,
    *,
    exploit_weakness: Mapping[str, str] | None = None,
    calibration: CalibrationSummary | None = None,
) -> tuple[ClassVerdict, ...]:
    """The per-class summary for ``report``, ordered by class name.

    Dry-run attempts belong to no class: a dry run tests nothing by design.
    """
    by_class: dict[str, list[ScanAttempt]] = {}
    for attempt in report.attempts:
        if ATTEMPT_CLASS.get(attempt.outcome) is AttemptClass.INTENTIONALLY_SKIPPED:
            continue
        by_class.setdefault(weakness_of(attempt, exploit_weakness), []).append(attempt)
    return tuple(
        _one_class(weakness, attempts, calibration)
        for weakness, attempts in sorted(by_class.items())
    )


def has_trace_outcome(report: ScanReport) -> bool:
    """True when any attempt was decided by the trace rule."""
    return any(a.judge_evidence.get("trace_outcome") for a in report.attempts)
