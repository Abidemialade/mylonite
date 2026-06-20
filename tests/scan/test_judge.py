"""SuccessJudge tests covering both deterministic-fired and LLM-fallback paths."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.scan.judge import SuccessJudge


def _stub_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _payload(predicate: str = "send_email_to_attacker", body: str = "ATTACK") -> Payload:
    return Payload(
        pattern_id="test",
        channel="tool-result",
        body=body,
        metadata={
            "seed_id": "test",
            "weakness": "W2",
            "predicate": predicate,
            "setup": "seed_note",
            "drive": "read_note_for_summary",
        },
    )


def _response(
    *,
    tool_calls: tuple[str, ...] = (),
    raw_response: str = "",
    metadata: dict[str, str] | None = None,
) -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="test",
        raw_response=raw_response,
        tool_calls=list(tool_calls),
        metadata=metadata or {},
    )


@pytest.mark.asyncio
async def test_effect_probe_confirmed_is_a_finding_no_llm() -> None:
    """effect_confirmed=true → deterministic success, overriding predicate + LLM."""
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": false, "confidence": 0.0, "reason": "x"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(), _response(metadata={"effect_confirmed": "true"}))
    assert v.success is True
    assert v.mechanism == "predicate"
    assert called is False


@pytest.mark.asyncio
async def test_effect_probe_false_is_not_a_finding_no_llm() -> None:
    """effect_confirmed=false (queued/refused) → deterministic clean — the R3 fix.

    A defended app that queues an action for human approval must NOT be a finding,
    even though the tool was named and an LLM might over-call it.
    """
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": true, "confidence": 0.99, "reason": "tool was called"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(
        _payload(),
        _response(tool_calls=("send_email",), metadata={"effect_confirmed": "false"}),
    )
    assert v.success is False
    assert v.mechanism == "predicate"
    assert "materialise" in v.reason
    assert called is False


@pytest.mark.asyncio
async def test_predicate_fires_short_circuits_llm() -> None:
    """When the deterministic predicate returns a Verdict, the LLM is never called."""
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": false, "confidence": 0.0, "reason": "x"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(
        _payload(),
        _response(
            tool_calls=("read_note", "send_email"),
            metadata={"store_emails_sent": "[('attacker@example.com', 's', 'b')]"},
        ),
    )
    assert v.success is True
    assert v.mechanism == "predicate"
    assert called is False


@pytest.mark.asyncio
async def test_w4_guarded_confirm_flow_beats_permissive_llm_judge() -> None:
    """Regression (reference:guarded W4 leak): the guarded two-step flow
    (send_email -> confirm_send) is a confident non-finding that must short-
    circuit the LLM judge.

    Before the fix the W4 predicate returned ``None`` on the confirm_send path,
    so a permissive judge — seeing 'the email was sent' — re-introduced a false
    positive on the guarded twin, destabilising the differential. The predicate
    now returns ``success=False`` and the LLM is never consulted.
    """
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": true, "confidence": 0.99, "reason": "email was sent"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(
        _payload(predicate="send_email_without_confirmation"),
        _response(
            tool_calls=("send_email", "confirm_send"),
            metadata={"store_emails_sent": "[('ops@example.com', 's', 'b')]"},
        ),
    )
    assert v.success is False
    assert v.mechanism == "predicate"
    assert called is False


@pytest.mark.asyncio
async def test_llm_fallback_runs_when_predicate_inconclusive() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"success": true, "confidence": 0.9, "reason": "saw it"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(
        _payload(),
        _response(tool_calls=("read_note",)),  # predicate inconclusive
    )
    assert v.success is True
    assert v.mechanism == "llm"


@pytest.mark.asyncio
async def test_llm_low_confidence_rejects() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"success": true, "confidence": 0.4, "reason": "weak"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(), _response(tool_calls=("read_note",)))
    assert v.success is False
    assert v.mechanism == "llm"


@pytest.mark.asyncio
async def test_llm_invalid_json_falls_back_to_failure() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response("not json")

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(), _response(tool_calls=("read_note",)))
    assert v.success is False
    assert v.mechanism == "llm"
    # Issue #7: a parse failure must be reported as such, distinct from a call failure.
    assert v.fallback_cause == "unparseable_output"
    assert "not parseable" in v.reason
    assert "call raised" not in v.reason.lower()


@pytest.mark.asyncio
async def test_llm_call_raised_reports_call_failure() -> None:
    """Issue #7: a raised provider call must read as a call failure, not a parse failure."""

    async def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("SSL: CERTIFICATE_VERIFY_FAILED")

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(), _response(tool_calls=("read_note",)))
    assert v.success is False
    assert v.mechanism == "llm"
    assert v.fallback_cause == "call_raised"
    assert "LLM call raised" in v.reason
    assert "CERTIFICATE_VERIFY_FAILED" in v.reason


@pytest.mark.asyncio
async def test_llm_fenced_json_is_accepted() -> None:
    """Issue #6: fenced judge output must parse, not fall back to inconclusive."""

    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('```json\n{"success": true, "confidence": 0.95, "reason": "ok"}\n```')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(), _response(tool_calls=("read_note",)))
    assert v.success is True
    assert v.mechanism == "llm"
    assert v.fallback_cause is None


@pytest.mark.asyncio
async def test_llm_fallback_disabled_is_predicate_only() -> None:
    """llm_fallback=False: an inconclusive predicate returns failure WITHOUT an LLM call.

    This is the deterministic demo/replay mode — the differential oracle is
    purely predicate-driven and never touches the (non-deterministic) LLM judge.
    """
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": true, "confidence": 1.0, "reason": "x"}')

    judge = SuccessJudge(model="stub", completion_fn=stub, llm_fallback=False)
    v = await judge.judge(
        _payload(), _response(tool_calls=("read_note",))
    )  # predicate inconclusive
    assert v.success is False
    assert v.mechanism == "predicate"
    assert v.fallback_cause is None
    assert called is False


@pytest.mark.asyncio
async def test_missing_predicate_key_returns_predicate_mechanism_failure() -> None:
    judge = SuccessJudge(model="stub")
    p = Payload(
        pattern_id="t",
        channel="tool-result",
        body="x",
        metadata={"seed_id": "t"},  # predicate key missing
    )
    v = await judge.judge(p, _response())
    assert v.success is False
    assert v.mechanism == "predicate"
    assert "predicate" in v.reason


@pytest.mark.asyncio
async def test_unknown_predicate_returns_failure_without_calling_llm() -> None:
    called = False

    async def stub(**_: Any) -> SimpleNamespace:
        nonlocal called
        called = True
        return _stub_response('{"success": true, "confidence": 1.0, "reason": "x"}')

    judge = SuccessJudge(model="stub", completion_fn=stub)
    v = await judge.judge(_payload(predicate="not_registered"), _response())
    assert v.success is False
    assert v.mechanism == "predicate"
    assert called is False
