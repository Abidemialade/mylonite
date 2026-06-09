"""InProcessReferenceAdapter tests.

Covers:
* describe() against both variants
* invoke() with a W2-style payload (seed_note + read_note_for_summary)
* close() no-op
* G1 (eng review A3): planner exception raises AdapterInvocationSkipped
* G8 (eng review A2): both 0-arg subclasses instantiate and satisfy the
  AsyncTargetAdapter Protocol
* Budget counter increment from the planner-side wrapper (A1)
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts import AsyncTargetAdapter, Payload
from mylonite.plugins._reference.reference_target_adapter import (
    InProcessGuardedReferenceAdapter,
    InProcessReferenceAdapter,
    InProcessVulnerableReferenceAdapter,
)
from mylonite.scan._llm import LiteLLMCallCounter
from mylonite.scan._types import AdapterInvocationSkipped


def _text_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _tool_call(name: str, arguments: dict[str, Any], call_id: str = "c1") -> SimpleNamespace:
    import json as _json

    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=_json.dumps(arguments)),
    )


def _tool_response(calls: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=calls))]
    )


def _w2_payload(body: str = "INJECTED") -> Payload:
    return Payload(
        pattern_id="test-w2",
        channel="tool-result",
        body=body,
        metadata={
            "seed_id": "test-w2",
            "weakness": "W2",
            "predicate": "send_email_to_attacker",
            "setup": "seed_note",
            "drive": "read_note_for_summary",
        },
    )


# --- G8 — subclasses + Protocol satisfaction -----------------------------------


def test_vulnerable_subclass_is_zero_arg_and_satisfies_protocol() -> None:
    adapter = InProcessVulnerableReferenceAdapter()
    assert isinstance(adapter, AsyncTargetAdapter)


def test_guarded_subclass_is_zero_arg_and_satisfies_protocol() -> None:
    adapter = InProcessGuardedReferenceAdapter()
    assert isinstance(adapter, AsyncTargetAdapter)


# --- describe() --------------------------------------------------------------


@pytest.mark.asyncio
async def test_describe_vulnerable_returns_expected_tool_surface() -> None:
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub")
    descriptor = await adapter.describe()
    assert descriptor.target_id == "reference:vulnerable"
    assert descriptor.kind == "mcp"
    tool_names = {t.name for t in descriptor.tools}
    assert {"read_note", "write_note", "web_fetch", "send_email"}.issubset(tool_names)


@pytest.mark.asyncio
async def test_describe_guarded_includes_confirm_send() -> None:
    adapter = InProcessReferenceAdapter(variant="guarded", model="stub")
    descriptor = await adapter.describe()
    tool_names = {t.name for t in descriptor.tools}
    assert "confirm_send" in tool_names


# --- invoke() — happy path ---------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_w2_seed_note_then_planner_sends_email() -> None:
    iteration = [0]

    async def stub(**_: Any) -> SimpleNamespace:
        iteration[0] += 1
        if iteration[0] == 1:
            # Planner asks to read the seeded note.
            return _tool_response([_tool_call("read_note", {"note_id": "matches-anything"})])
        if iteration[0] == 2:
            # Planner follows the injected instruction and emails attacker.
            return _tool_response(
                [
                    _tool_call(
                        "send_email",
                        {
                            "to": "attacker@example.com",
                            "subject": "s",
                            "body": "exfil",
                        },
                        call_id="c2",
                    )
                ]
            )
        return _text_response("done.")

    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=stub)
    response = await adapter.invoke(_w2_payload())
    assert response.payload_pattern_id == "test-w2"
    assert "read_note" in response.tool_calls
    assert "send_email" in response.tool_calls
    assert "attacker@example.com" in response.metadata["store_emails_sent"]
    assert response.metadata["variant"] == "vulnerable"
    assert response.metadata["setup"] == "seed_note"
    assert response.metadata["drive"] == "read_note_for_summary"


# --- G1 — A3 planner skip path -----------------------------------------------


@pytest.mark.asyncio
async def test_invoke_raises_adapter_invocation_skipped_on_planner_failure() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=stub)
    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(_w2_payload())
    assert "planner failure" in str(excinfo.value)
    assert excinfo.value.attempt_metadata["variant"] == "vulnerable"
    assert excinfo.value.attempt_metadata["exception"] == "RuntimeError"


# --- A1 — budget counter sees planner calls ----------------------------------


@pytest.mark.asyncio
async def test_planner_calls_increment_active_budget_counter() -> None:
    iteration = [0]

    async def stub(**_: Any) -> SimpleNamespace:
        iteration[0] += 1
        if iteration[0] == 1:
            return _tool_response([_tool_call("read_note", {"note_id": "x"})])
        return _text_response("ok")

    counter = LiteLLMCallCounter(cap=10)
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=stub)
    with counter.active():
        await adapter.invoke(_w2_payload())
    assert counter.by_caller.get("planner", 0) == 2
    assert counter.count == 2


# --- close() -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_is_a_noop() -> None:
    adapter = InProcessReferenceAdapter(model="stub")
    assert await adapter.close() is None
