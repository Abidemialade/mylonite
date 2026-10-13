"""A seed whose predicate is missing or not registered reaches no verdict.

Nothing checks a seed's predicate name before the scan runs, so a missing key
or a misspelt name reaches the judge. The judge cannot rule on it, and the
attempt must read undecided (NOT TESTED), never as the target resisting.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import (
    AdapterResponse,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.scan import coverage
from mylonite.scan.coverage import NO_ADJUDICATOR, ScanOutcome
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge


async def _never_called(**_: Any) -> SimpleNamespace:  # pragma: no cover
    raise AssertionError("an unjudgeable seed must not reach the LLM judge")


def _metadata(predicate: str | None) -> dict[str, str]:
    meta = {
        "seed_id": "t",
        "weakness": "W2",
        "setup": "seed_note",
        "drive": "read_note_for_summary",
    }
    if predicate is not None:
        meta["predicate"] = predicate
    return meta


def _payload(predicate: str | None) -> Payload:
    return Payload(
        pattern_id="t", channel="tool-result", body="ATTACK", metadata=_metadata(predicate)
    )


def _response() -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="t", raw_response="done", tool_calls=["read_note"], metadata={}
    )


# --- the judge ---------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "predicate", [None, "", "a_predicate_nobody_registered"], ids=["missing", "empty", "unknown"]
)
@pytest.mark.parametrize("llm_fallback", [True, False])
async def test_an_unjudgeable_seed_is_no_verdict(predicate: str | None, llm_fallback: bool) -> None:
    judge = SuccessJudge(model="stub", completion_fn=_never_called, llm_fallback=llm_fallback)
    v = await judge.judge(_payload(predicate), _response())
    assert v.success is False
    assert v.mechanism == "predicate"
    assert v.evidence["no_adjudicator"] == NO_ADJUDICATOR
    # Nothing degraded and no call was made, so this is not a failed LLM call.
    assert v.fallback_cause is None


# --- the engine --------------------------------------------------------------


class _Module:
    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="stub-pattern",
            name="stub",
            summary="test",
            target_kinds=["mcp"],
            compliance=ComplianceTags(owasp_llm=["LLM01"]),
        )

    def generate_payloads(self, target: TargetDescriptor) -> list[Payload]:
        del target
        return [_payload("a_predicate_nobody_registered")]


class _Adapter:
    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
        del payload
        return _response()

    async def close(self) -> None:
        return None


class _NoCustomiser:
    async def customise(self, seed: Any, target: Any) -> Payload:  # pragma: no cover
        raise AssertionError("these payloads run direct")


@pytest.mark.asyncio
async def test_an_unknown_predicate_is_recorded_undecided_not_resisted() -> None:
    engine = ScanEngine(
        config=ScanConfig(
            target_id="custom:stub",
            provider="anthropic",
            model="stub-model",
            max_llm_calls=50,
            max_concurrent=1,
            output_dir=Path(".mylonite/scans"),
        ),
        adapter=_Adapter(),
        attack_modules=[_Module()],
        customiser=_NoCustomiser(),
        judge=SuccessJudge(model="stub", completion_fn=_never_called),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert coverage.attempt_reached_no_verdict(attempt)
    assert coverage.no_verdict_causes(attempt) == [NO_ADJUDICATOR]
    outcome = ScanOutcome.from_report(result.report)
    assert outcome.operator_message is not None
    assert "This is NOT a clean result" in outcome.operator_message


@pytest.mark.asyncio
async def test_an_unknown_predicate_on_a_recorded_trace_is_decided_by_the_trace() -> None:
    """With a recorded trace outcome, the trace rule decides: the unknown name
    counts as a predicate that could not rule, and a not-called trace still
    reads as resisted. Only the no-trace path stamps ``no_adjudicator``."""
    response = AdapterResponse(
        payload_pattern_id="t",
        raw_response="done",
        tool_calls=["read_note"],
        metadata={
            "trace_outcome": "not-called",
            "link": "unlinked",
            "marker_kind": "exfil",
            "marker_linked": "false",
            "calibrated": "false",
            "seed_control": "not_run",
            "effect_confirmed": "unprobed",
        },
    )
    judge = SuccessJudge(model="stub", completion_fn=_never_called)
    v = await judge.judge(_payload("a_predicate_nobody_registered"), response)
    assert v.success is False
    assert v.fallback_cause is None
    assert "no_adjudicator" not in v.evidence
    assert v.evidence.get("negative_basis") == "trace"
