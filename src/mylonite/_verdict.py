"""The verdict label a validation report earns.

``ValidationReport.kept`` says whether a test passed every gating leg. It does
not say what those legs proved. A custom target validated with no guarded twin,
no control and no effect probe can pass on reproduction and judge agreement
alone; a run with the build leg skipped never ran the emitted test. Both are
kept, but neither shows that a safeguard stops the attack or that the committed
test passes, so neither may read as a plain KEPT.

:func:`verdict_label` derives the label from fields every report already
carries, so no new field is needed.

A collect-only build (a custom target, whose test needs the live target to run)
doesn't run the committed test: it proves the file collects. There a KEPT rests
on the differential or effect leg, which proved the attack on live runs; that
leg is the evidence, not the build.
"""

from __future__ import annotations

from typing import Final, Literal

from mylonite.contracts import ValidationReport

VerdictLabel = Literal["KEPT", "STABLE, NOT PROVEN", "REJECTED"]

KEPT: Final = "KEPT"
STABLE_NOT_PROVEN: Final = "STABLE, NOT PROVEN"
REJECTED: Final = "REJECTED"

#: The legs that show a safeguard stops the attack (``differential``) or that
#: the damage really happened on the target (``effect``).
_PROOF_STAGES: Final = frozenset({"differential", "effect"})


def _build_passed(report: ValidationReport) -> bool:
    """True when the build leg ran (was not skipped) and passed."""
    return any(o.stage == "build" and o.passed and not o.report_only for o in report.outcomes)


def has_proof(report: ValidationReport) -> bool:
    """True when a gating differential or effect leg passed."""
    return any(o.stage in _PROOF_STAGES and o.passed and not o.report_only for o in report.outcomes)


def verdict_label(report: ValidationReport) -> VerdictLabel:
    """``KEPT``, ``STABLE, NOT PROVEN`` or ``REJECTED`` for one report.

    KEPT needs all three: ``kept``, a build leg that passed (not skipped), and
    a passing differential or effect leg. A kept report missing either of the
    last two is ``STABLE, NOT PROVEN``.
    """
    if not report.kept:
        return REJECTED
    if _build_passed(report) and has_proof(report):
        return KEPT
    return STABLE_NOT_PROVEN


def verdict_reason(report: ValidationReport) -> str:
    """One plain sentence on why the report earned its label."""
    label = verdict_label(report)
    if label == REJECTED:
        return "the test was not kept."
    if label == KEPT:
        return "the test discriminates and is stable."
    gaps = []
    if not has_proof(report):
        gaps.append(
            "nothing showed a safeguard stops the attack or that the damage happened "
            "(no guarded twin or control, and no effect probe confirmed it)"
        )
    if not _build_passed(report):
        gaps.append("the build leg was skipped, so the emitted test was not checked")
    return "the attack reproduced, but " + "; and ".join(gaps) + "."
