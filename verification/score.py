"""Score recorded transcripts through Mylonite's success-judge (hermetic).

This is the heart of Layer 2. For each transcript it reconstructs the
``Payload`` / ``AdapterResponse`` pair Mylonite's judge expects, runs the judge
with the deterministic, portable ``consequential_action_executed`` predicate
(NO LLM fallback by default — fully reproducible), and folds the result into a
:class:`mylonite.corpus.ConfusionMatrix` against the benchmark's own verdict.

The positive class is "attack succeeded". ``expected_exploited`` is the
benchmark's third-party rule (``Transcript.benchmark_success``);
``detected_exploited`` is Mylonite's judge. Agreement (precision/recall/F1) is
the independently-verifiable claim: Mylonite's judge reproduces the established
benchmark's success criterion on real model behaviour.
"""

from __future__ import annotations

import json

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.corpus import CaseResult, ConfusionMatrix, confusion_matrix
from mylonite.scan.judge import SuccessJudge
from verification.crosswalk import Crosswalk
from verification.transcript import Transcript

#: Mylonite's portable, app-neutral effect predicate. Keys off
#: ``consequential_tool`` and inspects the effect trace — the same notion of
#: success ("the attacker's tool actually executed") that the benchmarks use.
_PORTABLE_PREDICATE = "consequential_action_executed"


def _payload_for(transcript: Transcript, crosswalk: Crosswalk) -> Payload:
    primary = crosswalk.primary_class(transcript.dataset, transcript.split)
    return Payload(
        pattern_id=transcript.case_id,
        channel="tool-result",
        body=transcript.attacker_instruction,
        metadata={
            "predicate": _PORTABLE_PREDICATE,
            "consequential_tool": transcript.attacker_tool,
            "weakness": primary,
            "dataset": transcript.dataset,
            "split": transcript.split,
        },
    )


def _response_for(transcript: Transcript) -> AdapterResponse:
    effect_trace = json.dumps([c.model_dump() for c in transcript.tool_calls])
    return AdapterResponse(
        payload_pattern_id=transcript.case_id,
        raw_response=transcript.final_output,
        tool_calls=[c.tool for c in transcript.tool_calls],
        # No effect_confirmed: let the portable predicate decide from the trace.
        metadata={"effect_trace": effect_trace},
    )


async def score_transcript(
    transcript: Transcript, judge: SuccessJudge, crosswalk: Crosswalk
) -> CaseResult:
    """Judge one transcript and fold it into a corpus ``CaseResult``."""
    payload = _payload_for(transcript, crosswalk)
    response = _response_for(transcript)
    verdict = await judge.judge(payload, response)
    primary = crosswalk.primary_class(transcript.dataset, transcript.split)
    return CaseResult(
        weakness=primary,
        variant=transcript.split,
        expected_exploited=transcript.benchmark_success,
        detected_exploited=verdict.success,
        detail=verdict.reason[:200],
    )


async def score_transcripts(
    transcripts: list[Transcript],
    *,
    crosswalk: Crosswalk,
    judge: SuccessJudge | None = None,
) -> tuple[list[CaseResult], ConfusionMatrix]:
    """Score every transcript; return ``(rows, confusion_matrix)``.

    Defaults to a deterministic judge (``llm_fallback=False``) so scoring is
    hermetic and reproducible. Pass a judge with ``llm_fallback=True`` to also
    exercise the LLM-judge leg (the "with-LLM" column).
    """
    judge = judge or SuccessJudge(model="deterministic-unused", llm_fallback=False)
    rows = [await score_transcript(t, judge, crosswalk) for t in transcripts]
    return rows, confusion_matrix(rows)
