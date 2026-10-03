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

from typing import Any, Final, Literal

from mylonite.contracts import ExploitRecord, ValidationReport

VerdictLabel = Literal["KEPT", "STABLE, NOT PROVEN", "REJECTED"]

KEPT: Final = "KEPT"
STABLE_NOT_PROVEN: Final = "STABLE, NOT PROVEN"
REJECTED: Final = "REJECTED"

#: Stamped into ``ValidationReport.notes`` when a judge-only finding failed a
#: leg, so the verdict reason can name the cause from the report alone (no new
#: field). Same convention as the ``[guarded-twin=...]`` marker.
JUDGE_ONLY_MARKER: Final = "[evidence=judge-only]"

#: Stamped into ``ValidationReport.notes`` when a black-box target (``transport:
#: rest``) kept a test on judge-only fires. Such a keep is capped at STABLE,
#: NOT PROVEN, whatever its other legs show.
BLACK_BOX_MARKER: Final = "[evidence=black-box-judge-only]"

#: The clause that leg's detail carries.
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


def black_box_marker(capped: bool) -> str:
    """`` [evidence=black-box-judge-only]`` for a report's notes, or empty."""
    return f" {BLACK_BOX_MARKER}" if capped else ""


def is_black_box_keep(report: ValidationReport) -> bool:
    """True when the report's keep rests on a black-box target's judge alone."""
    return BLACK_BOX_MARKER in (report.notes or "")


def rests_on_judge_only(report: ValidationReport) -> bool:
    """True when the validator marked the report: every firing run was judge-only."""
    return JUDGE_ONLY_MARKER in (report.notes or "")


def verdict_label(report: ValidationReport) -> VerdictLabel:
    """``KEPT``, ``STABLE, NOT PROVEN`` or ``REJECTED`` for one report.

    KEPT needs all three: ``kept``, a build leg that passed (not skipped), and
    a passing differential or effect leg. A kept report missing either of the
    last two is ``STABLE, NOT PROVEN``. So is a black-box target's keep that
    rests on the LLM judge alone (:func:`is_black_box_keep`), whatever else
    passed.
    """
    if not report.kept:
        return REJECTED
    if is_black_box_keep(report):
        return STABLE_NOT_PROVEN
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
    if is_black_box_keep(report):
        return (
            "black-box target: the LLM judge is the only evidence. The HTTP adapter "
            "records no tool calls and runs no effect probe, so nothing else can confirm "
            "the attack."
        )
    gaps = []
    if not has_proof(report):
        gaps.append(
            "nothing showed a safeguard stops the attack or that the damage happened "
            "(no guarded twin or control, and no effect probe confirmed it)"
        )
    if not _build_passed(report):
        gaps.append("the build leg was skipped, so the emitted test was not checked")
    return "the attack reproduced, but " + "; and ".join(gaps) + "."


def next_step_after_keep(
    report: ValidationReport,
    exploit: ExploitRecord | None = None,
    *,
    target: Any | None = None,
) -> str:
    """The next step ``validate`` prints for a kept report.

    The exit code is 0 either way, but an unproven keep is not presented as a
    finished gate: committing its test gates reproduction only.

    ``exploit`` (A3/SV1): when given and the verdict is a plain ``KEPT`` —
    never for a STABLE, NOT PROVEN or black-box keep, which already say
    nothing was proven — this is preceded by the same severity, impact and
    suggested-fix lines the gate PR body opens with
    (:func:`mylonite.gate.mitigation.finding_block`, reused here rather than
    re-derived), so the fix under a kept finding is never exclusive to the
    gate PR. Imported lazily: ``gate.mitigation`` imports this module at
    load time, so importing it back at module scope here would be circular.
    """
    if is_black_box_keep(report):
        return (
            "Next: committing this test gates reproduction only, on the LLM judge's word; "
            "a black-box target gives no state or trace evidence to prove more."
        )
    if verdict_label(report) == STABLE_NOT_PROVEN:
        return (
            "Next: committing this test gates reproduction only; add a guarded side "
            "or an effect_probe and re-run `mylonite validate` to prove a safeguard."
        )
    next_line = (
        "Next: commit the generated test + fixtures so CI can gate on it "
        "(see `mylonite gate --help`)."
    )
    if exploit is None:
        return next_line
    from mylonite.gate.mitigation import finding_block

    block = "\n".join(finding_block(exploit, report, target=target))
    return f"{block}\n\n{next_line}"
