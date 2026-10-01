"""The verdict label a validation report earns.

``ValidationReport.kept`` says whether a test passed every gating leg. It does
not say what those legs proved. A custom target validated with no guarded twin,
no control and no effect probe can pass on reproduction and judge agreement
alone; a run with the build leg skipped never ran the emitted test. Both are
kept, but neither shows that a safeguard stops the attack or that the committed
test passes, so neither may read as a plain KEPT.

:func:`verdict_label` derives the label from fields every report already
carries, so no new field is needed.

A finding whose every firing run is judge-only (only the LLM judge said the
attack landed) is REJECTED, not STABLE, NOT PROVEN: the validator fails the
leg that claims the attack reproduced, because nothing but the judge showed
that it did. The report's ``notes`` then carry :data:`JUDGE_ONLY_MARKER`
(the same bracketed-marker convention as ``_twin_fidelity.format_marker``),
which lets :func:`verdict_reason` say so.

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

#: Stamped into ``ValidationReport.notes`` when a judge-only finding failed a
#: leg, so the verdict reason can name the cause from the report alone (no new
#: field). Same convention as the ``[guarded-twin=...]`` marker.
JUDGE_ONLY_MARKER: Final = "[evidence=judge-only]"

#: The clause that leg's detail carries next to the marker.
JUDGE_ONLY_CLAUSE: Final = (
    "every firing run rests on the LLM judge alone: nothing in the target's state "
    "or the recorded trace confirmed the attack, so it cannot keep a test"
)

#: The legs that show a safeguard stops the attack (``differential``) or that
#: the damage really happened on the target (``effect``).
_PROOF_STAGES: Final = frozenset({"differential", "effect"})


def _build_passed(report: ValidationReport) -> bool:
    """True when the build leg ran (was not skipped) and passed."""
    return any(o.stage == "build" and o.passed and not o.report_only for o in report.outcomes)


def has_proof(report: ValidationReport) -> bool:
    """True when a gating differential or effect leg passed."""
    return any(o.stage in _PROOF_STAGES and o.passed and not o.report_only for o in report.outcomes)


def judge_only_marker(judge_only: bool) -> str:
    """`` [evidence=judge-only]`` for a report's notes, or empty."""
    return f" {JUDGE_ONLY_MARKER}" if judge_only else ""


def rests_on_judge_only(report: ValidationReport) -> bool:
    """True when the validator marked the report: every firing run was judge-only."""
    return JUDGE_ONLY_MARKER in (report.notes or "")


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
        if rests_on_judge_only(report):
            return (
                "the test was not kept: every firing run rested on the LLM judge alone, "
                "and nothing in the target's state or the recorded trace confirmed the attack."
            )
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


def next_step_after_keep(report: ValidationReport) -> str:
    """The next step ``validate`` prints for a kept report.

    The exit code is 0 either way, but an unproven keep is not presented as a
    finished gate: committing its test gates reproduction only."""
    if verdict_label(report) == STABLE_NOT_PROVEN:
        return (
            "Next: committing this test gates reproduction only; add a guarded side "
            "or an effect_probe and re-run `mylonite validate` to prove a safeguard."
        )
    return (
        "Next: commit the generated test + fixtures so CI can gate on it "
        "(see `mylonite gate --help`)."
    )
