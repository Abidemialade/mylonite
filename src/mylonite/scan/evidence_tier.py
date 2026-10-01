"""What a verdict rests on: the target's state, the recorded trace, or the judge alone.

Every decided attempt gets one evidence tier:

* ``state``: a probe read the target's own state and saw the effect.
* ``trace``: a deterministic check decided from what the session recorded
  (the trace rule, or the seed's predicate).
* ``judge-only``: only the LLM judge said so. Nothing structural confirmed it,
  including a judge success whose rationale disagreed with the trace and was
  kept anyway.

:func:`evidence_tier` is the one rule. It reads fields every verdict already
carries (``verdict_mechanism``, ``proof_level``, ``effect_confirmed``), so a
``scan_report.json`` written before tiers existed is reclassified offline, the
same way as a fresh one.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final, Literal

from mylonite.contracts import ScanAttempt
from mylonite.scan.coverage import attempt_reached_no_verdict

EvidenceTier = Literal["state", "trace", "judge-only"]

#: Strongest first.
EVIDENCE_TIERS: Final[tuple[EvidenceTier, ...]] = ("state", "trace", "judge-only")

#: The key the tier is stamped under in ``judge_evidence`` and in an exploit's
#: ``payload.metadata``. Readers derive it again rather than trusting the stamp.
EVIDENCE_TIER_KEY: Final = "evidence_tier"

#: The tiers that confirm an attack without the judge's word.
CONFIRMED_TIERS: Final[frozenset[str]] = frozenset({"state", "trace"})

_TRACE_PROOF_LEVELS: Final = frozenset({"dispatched", "dispatched-tool-linked"})

#: Outcomes a mechanism decided. Every other outcome has no tier.
_DECIDED_OUTCOMES: Final = frozenset({"finding", "no_finding"})


def evidence_tier(mechanism: str | None, evidence: Mapping[str, object]) -> EvidenceTier | None:
    """The evidence tier of one verdict; ``None`` when no mechanism decided it.

    In order: the trace rule's proof level (``effect-confirmed`` is state, the
    dispatch levels are trace); then, on an attempt with no ``trace_outcome``,
    an effect probe that saw the effect (state); then the mechanism (a predicate is trace, the LLM judge is
    judge-only).
    """
    if mechanism is None:
        return None
    proof_level = evidence.get("proof_level")
    if proof_level == "effect-confirmed":
        return "state"
    if proof_level in _TRACE_PROOF_LEVELS:
        return "trace"
    # Only where the trace rule did not decide. On a traced attempt the rule
    # already weighed the probe: a finding carries a proof level, and a
    # resisted attempt's "true" (a stale or uncalibrated probe) is not state.
    if "trace_outcome" not in evidence and str(evidence.get("effect_confirmed", "")) == "true":
        return "state"
    if mechanism == "predicate":
        return "trace"
    return "judge-only"


def attempt_evidence_tier(attempt: ScanAttempt) -> EvidenceTier | None:
    """The tier of a recorded attempt, or ``None`` when nothing decided it."""
    if attempt.outcome not in _DECIDED_OUTCOMES or attempt_reached_no_verdict(attempt):
        return None
    return evidence_tier(attempt.verdict_mechanism, attempt.judge_evidence)


def tier_counts(attempts: Iterable[ScanAttempt]) -> dict[str, int]:
    """How many of ``attempts`` sit at each tier, every tier present, strongest first."""
    counts: dict[str, int] = dict.fromkeys(EVIDENCE_TIERS, 0)
    for attempt in attempts:
        tier = attempt_evidence_tier(attempt)
        if tier is not None:
            counts[tier] += 1
    return counts


def rests_on_judge_only(tiers: Iterable[str | None]) -> bool:
    """True when there is at least one firing run and every one is judge-only.

    A run with no recorded tier (``None``) is not judge-only: nothing says the
    judge alone decided it. Judge-only runs still count as support when at
    least one run is ``state`` or ``trace``.
    """
    recorded = list(tiers)
    return bool(recorded) and all(tier == "judge-only" for tier in recorded)
