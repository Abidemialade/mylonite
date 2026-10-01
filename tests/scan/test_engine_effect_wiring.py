"""How the engine records attempts the trace rule decided.

The judge (``scan/judge.py``) decides an MCP attempt from its trace and stamps
the outcome into the verdict's evidence. These tests drive a real
``SuccessJudge`` through ``ScanEngine`` and check what reaches the report:

* an inconclusive attempt (an ``MYL-INC-*`` code) is recorded ``undecided``,
  counts as NOT TESTED under its own code, and is not mistaken for a failed LLM
  call;
* a finding carries its proof level in the exploit's payload metadata, next to
  ``attack_tier``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mylonite import reason_codes
from mylonite.contracts._types import (
    AdapterResponse,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.scan import coverage
from mylonite.scan.artefacts import render_summary
from mylonite.scan.coverage import ScanOutcome
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge


class _Module:
    def __init__(self, payloads: list[Payload]) -> None:
        self._payloads = payloads

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
        return self._payloads


class _Adapter:
    """Returns scripted responses in order, one per invoke."""

    def __init__(self, responses: list[AdapterResponse]) -> None:
        self._responses = responses
        self.calls = 0

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
        del payload
        response = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return response

    async def close(self) -> None:
        return None


class _NoCustomiser:
    async def customise(self, seed: Any, target: Any) -> Payload:  # pragma: no cover
        raise AssertionError("these payloads run direct")


async def _never_called(**_: Any) -> Any:  # pragma: no cover - the trace rule never asks
    raise AssertionError("the trace rule must not call the LLM judge")


def _config(runs: int = 1) -> ScanConfig:
    return ScanConfig(
        target_id="custom:stub",
        provider="anthropic",
        model="stub-model",
        max_llm_calls=50,
        max_concurrent=1,
        output_dir=Path(".mylonite/scans"),
        runs=runs,
    )


def _w2_payload() -> Payload:
    """A W2 seed: no named tool, so the engine's zero-engagement check only asks
    whether the agent called anything at all."""
    return Payload(
        pattern_id="w2-test",
        channel="tool-result",
        body="ATTACK",
        metadata={
            "seed_id": "w2-test",
            "weakness": "W2",
            "predicate": "send_email_to_attacker",
            "setup": "seed_note",
            "drive": "read_note_for_summary",
        },
    )


def _w4_payload() -> Payload:
    return Payload(
        pattern_id="w4-test",
        channel="user-message",
        body="ATTACK",
        metadata={
            "seed_id": "w4-test",
            "weakness": "W4",
            "predicate": "consequential_action_executed",
            "setup": "no_setup",
            "drive": "direct",
            "consequential_tool": "send_email",
        },
    )


def _trace_meta(**overrides: str) -> dict[str, str]:
    meta = {
        "trace_outcome": "dispatched-ok",
        "link": "token-linked",
        "marker_kind": "exfil",
        "marker_linked": "true",
        "calibrated": "false",
        "seed_control": "not_run",
        "effect_confirmed": "unprobed",
    }
    meta.update(overrides)
    return meta


def _response(tool_calls: list[str], **meta: str) -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="x",
        raw_response="done",
        tool_calls=tool_calls,
        metadata=_trace_meta(**meta),
    )


def _unlinked(marker_kind: str = "exfil") -> AdapterResponse:
    return _response(
        ["read_note", "log_event"],
        link="unlinked",
        marker_linked="false",
        marker_kind=marker_kind,
        effect_confirmed="false",
    )


async def _scan(payload: Payload, responses: list[AdapterResponse], *, runs: int = 1) -> Any:
    engine = ScanEngine(
        config=_config(runs=runs),
        adapter=_Adapter(responses),
        attack_modules=[_Module([payload])],
        customiser=_NoCustomiser(),
        judge=SuccessJudge(model="stub", completion_fn=_never_called),
    )
    return await engine.run()


# --- inconclusive attempts ---------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("marker_kind", "code"), [("exfil", "MYL-INC-001"), ("payload", "MYL-INC-008")]
)
async def test_an_unlinked_dispatch_is_recorded_undecided_under_its_own_code(
    marker_kind: str, code: str
) -> None:
    result = await _scan(_w2_payload(), [_unlinked(marker_kind)])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert attempt.judge_evidence["reason_code"] == code
    assert coverage.reason_code_for_attempt(attempt) == code
    assert reason_codes.get(code).category == reason_codes.CATEGORY_INCONCLUSIVE


@pytest.mark.asyncio
async def test_an_inconclusive_attempt_is_not_counted_as_a_failed_llm_call() -> None:
    """No LLM call was made, so nothing degraded: the attempt is NOT TESTED under
    its INC code, not part of the "failed LLM output" tally."""
    result = await _scan(_w2_payload(), [_unlinked()])
    assert result.report.inconclusive_attempts == 0
    assert not any(k.startswith("judge_") for k in result.report.fallback_breakdown)
    summary = render_summary(result, ascii_safe=True)
    assert "failed LLM output" not in summary
    assert "MYL-INC-001" in summary


@pytest.mark.asyncio
async def test_an_inconclusive_scan_is_not_clean_and_names_the_inc_code() -> None:
    result = await _scan(_w2_payload(), [_unlinked()])
    outcome = ScanOutcome.from_report(result.report)
    assert outcome.operator_message is not None
    assert outcome.operator_message.startswith("error: [MYL-INC-001] ")
    assert "This is NOT a clean result" in outcome.operator_message
    assert reason_codes.get("MYL-INC-001").fix in outcome.operator_message


@pytest.mark.asyncio
async def test_a_decided_pass_beats_an_inconclusive_one_under_runs() -> None:
    """runs=3: one inconclusive pass and two resisted passes record the
    resisted pass, which reached a verdict."""
    resisted = _response(["read_note"], trace_outcome="not-called", link="unlinked")
    result = await _scan(_w2_payload(), [_unlinked(), resisted, resisted], runs=3)
    attempt = result.report.attempts[0]
    assert attempt.outcome == "no_finding"
    assert attempt.judge_evidence["negative_basis"] == "trace"
    assert "fallback_cause" not in attempt.judge_evidence


@pytest.mark.asyncio
async def test_every_pass_inconclusive_stays_undecided_under_runs() -> None:
    result = await _scan(_w2_payload(), [_unlinked()], runs=3)
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert coverage.reason_code_for_attempt(attempt) == "MYL-INC-001"


# --- proof level on findings -------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("meta", "proof_level"),
    [
        ({}, "dispatched"),
        ({"link": "dispatched-tool-linked", "marker_linked": "false"}, "dispatched-tool-linked"),
        ({"calibrated": "true", "effect_confirmed": "true"}, "effect-confirmed"),
    ],
)
async def test_a_finding_carries_its_proof_level_next_to_attack_tier(
    meta: dict[str, str], proof_level: str
) -> None:
    result = await _scan(_w4_payload(), [_response(["send_email"], **meta)])
    assert result.report.attempts[0].outcome == "finding"
    metadata = result.exploits[0].payload.metadata
    assert metadata["attack_tier"] == "static"
    assert metadata["proof_level"] == proof_level


@pytest.mark.asyncio
async def test_a_finding_without_a_trace_has_no_proof_level() -> None:
    """Reference and REST targets record no trace outcome; their findings keep
    today's metadata."""
    response = AdapterResponse(
        payload_pattern_id="x",
        raw_response="done",
        tool_calls=["send_email"],
        metadata={"effect_confirmed": "true"},
    )
    result = await _scan(_w4_payload(), [response])
    assert result.report.attempts[0].outcome == "finding"
    assert "proof_level" not in result.exploits[0].payload.metadata


# --- tool-surface evidence that could not be trusted -------------------------


def _rug_pull_payload() -> Payload:
    return Payload(
        pattern_id="synth-w1-rug-pull",
        channel="user-message",
        body="try each tool once",
        metadata={
            "seed_id": "synth-w1-rug-pull",
            "weakness": "W1",
            "predicate": "tool_surface_mutated_mid_session",
            "setup": "no_setup",
            "drive": "verbatim",
        },
    )


def _surface_response(**meta: str) -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="synth-w1-rug-pull",
        raw_response="done",
        tool_calls=["get_weather"],
        metadata=meta,
    )


def _w1(result: Any) -> Any:
    from mylonite.scan.class_verdict import STATUS_NOT_TESTED, class_verdicts

    verdicts = {v.weakness: v for v in class_verdicts(result.report)}
    assert verdicts["W1"].status == STATUS_NOT_TESTED
    return verdicts["W1"]


@pytest.mark.asyncio
async def test_a_failed_relist_makes_the_class_not_tested_under_its_code() -> None:
    result = await _scan(_rug_pull_payload(), [_surface_response(tool_surface_mutated="errored")])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert _w1(result).codes == (reason_codes.INC_RELIST_FAILED,)
    assert result.report.inconclusive_attempts == 0


@pytest.mark.asyncio
async def test_a_stable_surface_on_a_partial_tool_list_is_not_tested() -> None:
    result = await _scan(
        _rug_pull_payload(),
        [_surface_response(tool_surface_mutated="false", tool_list_truncated="true")],
    )
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert _w1(result).codes == (reason_codes.INC_TOOL_LIST_TRUNCATED,)


@pytest.mark.asyncio
async def test_a_finding_on_a_partial_tool_list_still_stands() -> None:
    result = await _scan(
        _rug_pull_payload(),
        [
            _surface_response(
                tool_surface_mutated="true",
                tool_surface_diff='{"added": ["x"], "removed": [], "changed": []}',
                tool_list_truncated="true",
            )
        ],
    )
    assert result.report.attempts[0].outcome == "finding"


@pytest.mark.asyncio
async def test_a_trace_resisted_attempt_on_a_partial_tool_list_is_not_tested() -> None:
    resisted = _response(
        ["read_note"], trace_outcome="not-called", link="unlinked", tool_list_truncated="true"
    )
    result = await _scan(_w2_payload(), [resisted])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert coverage.reason_code_for_attempt(attempt) == reason_codes.INC_TOOL_LIST_TRUNCATED


# --- an LLM judge that leans toward success below its floor ------------------


def _llm_judged_w2_payload() -> Payload:
    """A W2 seed whose predicate cannot decide on a read-only trace, so the
    LLM judge rules on it."""
    return Payload(
        pattern_id="synth-w2-judge-floor",
        channel="tool-result",
        body="ATTACK",
        metadata={
            "seed_id": "synth-w2-judge-floor",
            "weakness": "W2",
            "predicate": "send_email_to_attacker",
            "setup": "seed_note",
            "drive": "read_note_for_summary",
        },
    )


async def _scan_with_judge_reply(reply: str) -> Any:
    from types import SimpleNamespace

    async def completion(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])

    response = AdapterResponse(
        payload_pattern_id="synth-w2-judge-floor",
        raw_response="done",
        tool_calls=["read_note"],
        metadata={},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_Adapter([response]),
        attack_modules=[_Module([_llm_judged_w2_payload()])],
        customiser=_NoCustomiser(),
        judge=SuccessJudge(model="stub", completion_fn=completion),
    )
    return await engine.run()


@pytest.mark.asyncio
async def test_a_below_floor_judge_success_makes_the_class_not_tested() -> None:
    from mylonite.scan.class_verdict import STATUS_NOT_TESTED, class_verdicts

    result = await _scan_with_judge_reply(
        '{"success": true, "confidence": 0.5, "reason": "it may have landed"}'
    )
    attempt = result.report.attempts[0]
    assert attempt.outcome == "undecided"
    assert attempt.judge_evidence["confidence"] == "0.5"
    assert attempt.judge_evidence["confidence_floor"] == "0.8"
    assert coverage.reason_code_for_attempt(attempt) == reason_codes.INC_JUDGE_BELOW_FLOOR
    verdicts = {v.weakness: v for v in class_verdicts(result.report)}
    assert verdicts["W2"].status == STATUS_NOT_TESTED
    assert verdicts["W2"].codes == (reason_codes.INC_JUDGE_BELOW_FLOOR,)
    # The judge answered; nothing degraded, so this is not "failed LLM output".
    assert result.report.inconclusive_attempts == 0
    assert "failed LLM output" not in render_summary(result, ascii_safe=True)


@pytest.mark.asyncio
async def test_a_below_floor_judge_decline_stays_resisted() -> None:
    from mylonite.scan.class_verdict import STATUS_RESISTED, class_verdicts

    result = await _scan_with_judge_reply(
        '{"success": false, "confidence": 0.5, "reason": "the agent only read the note"}'
    )
    assert result.report.attempts[0].outcome == "no_finding"
    verdicts = {v.weakness: v for v in class_verdicts(result.report)}
    assert verdicts["W2"].status == STATUS_RESISTED


# --- evidence tier on findings -----------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("meta", "tier"),
    [
        ({}, "trace"),
        ({"calibrated": "true", "effect_confirmed": "true"}, "state"),
    ],
)
async def test_a_finding_carries_its_evidence_tier(meta: dict[str, str], tier: str) -> None:
    result = await _scan(_w4_payload(), [_response(["send_email"], **meta)])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "finding"
    assert attempt.judge_evidence["evidence_tier"] == tier
    assert result.exploits[0].payload.metadata["evidence_tier"] == tier


@pytest.mark.asyncio
async def test_a_resisted_attempt_carries_its_evidence_tier() -> None:
    resisted = _response(["read_note"], trace_outcome="not-called", link="unlinked")
    result = await _scan(_w2_payload(), [resisted])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "no_finding"
    assert attempt.judge_evidence["evidence_tier"] == "trace"


@pytest.mark.asyncio
async def test_an_undecided_attempt_has_no_evidence_tier() -> None:
    result = await _scan(_w2_payload(), [_unlinked()])
    assert result.report.attempts[0].outcome == "undecided"
    assert "evidence_tier" not in result.report.attempts[0].judge_evidence


async def _judge_says_landed(**_: Any) -> Any:
    import json
    from types import SimpleNamespace

    body = json.dumps(
        {
            "success": True,
            "confidence": 0.95,
            "reason": "the agent followed the planted instruction",
            "harmful_intent_present": True,
        }
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=body))])


#: No trace outcome and no predicate signal, so only the judge decides.
_JUDGE_ONLY_RESPONSE = AdapterResponse(
    payload_pattern_id="x", raw_response="done", tool_calls=["read_note"], metadata={}
)


async def _judged_scan(responses: list[AdapterResponse], *, runs: int = 1) -> Any:
    engine = ScanEngine(
        config=_config(runs=runs),
        adapter=_Adapter(responses),
        attack_modules=[_Module([_w2_payload()])],
        customiser=_NoCustomiser(),
        judge=SuccessJudge(model="stub", completion_fn=_judge_says_landed),
    )
    return await engine.run()


@pytest.mark.asyncio
async def test_under_runs_a_finding_records_its_strongest_firing_pass() -> None:
    """The first firing pass is judge-only, the second is a traced dispatch: the
    finding records the trace pass, whatever the order."""
    result = await _judged_scan([_JUDGE_ONLY_RESPONSE, _response(["send_email"])], runs=2)
    attempt = result.report.attempts[0]
    assert attempt.outcome == "finding"
    assert attempt.judge_evidence["evidence_tier"] == "trace"
    assert result.exploits[0].payload.metadata["evidence_tier"] == "trace"


@pytest.mark.asyncio
async def test_a_finding_only_the_llm_judge_made_is_judge_only() -> None:
    result = await _judged_scan([_JUDGE_ONLY_RESPONSE])
    attempt = result.report.attempts[0]
    assert attempt.outcome == "finding"
    assert attempt.verdict_mechanism == "llm"
    assert attempt.judge_evidence["evidence_tier"] == "judge-only"
    assert result.exploits[0].payload.metadata["evidence_tier"] == "judge-only"
