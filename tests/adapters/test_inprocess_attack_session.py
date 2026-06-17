"""Multi-step AttackSession against the in-process reference target.

The session holds ONE NoteStore/server for its lifetime, so state planted via
a raw call_tool persists into a later planner drive — the capability invoke()
cannot provide (it builds a fresh store every call).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts.target_adapter import (
    AttackSession,
    SupportsAttackSession,
    ToolCallOutcome,
)
from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter


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


def _text_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


@pytest.mark.asyncio
async def test_open_session_satisfies_capability_protocols() -> None:
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub")
    assert isinstance(adapter, SupportsAttackSession)
    session = await adapter.open_session()
    assert isinstance(session, AttackSession)
    await session.close()


@pytest.mark.asyncio
async def test_call_tool_returns_outcome() -> None:
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub")
    session = await adapter.open_session()
    outcome = await session.call_tool("write_note", {"note_id": "n1", "body": "CANARY"})
    assert isinstance(outcome, ToolCallOutcome)
    assert outcome.tool
    assert outcome.is_error is False
    await session.close()


@pytest.mark.asyncio
async def test_state_persists_across_call_tool() -> None:
    """The headline capability: a note planted in step 1 is readable in step 2."""
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub")
    session = await adapter.open_session()
    await session.call_tool("write_note", {"note_id": "n1", "body": "CANARY-TOKEN"})
    readback = await session.call_tool("read_note", {"note_id": "n1"})
    assert "CANARY-TOKEN" in readback.result
    await session.close()


@pytest.mark.asyncio
async def test_drive_planner_isolates_planner_calls_from_attacker_calls() -> None:
    """A raw plant call must NOT pollute the planner trace of a later drive."""

    async def stub(**_: Any) -> SimpleNamespace:
        if not hasattr(stub, "_n"):
            stub._n = 0  # type: ignore[attr-defined]
        stub._n += 1  # type: ignore[attr-defined]
        if stub._n == 1:  # type: ignore[attr-defined]
            return _tool_response([_tool_call("read_note", {"note_id": "n1"})])
        return _text_response("done.")

    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=stub)
    session = await adapter.open_session()
    await session.call_tool("write_note", {"note_id": "n1", "body": "PLANTED"})
    response = await session.drive_planner("Read note n1 and summarise it.")
    assert "read_note" in response.tool_calls
    assert "write_note" not in response.tool_calls
    await session.close()


@pytest.mark.asyncio
async def test_drive_planner_stamps_pattern_id_when_supplied() -> None:
    """0.5.0: a driver-supplied pattern_id replaces the session-drive sentinel."""

    async def stub(**_: Any) -> SimpleNamespace:
        return _text_response("done.")

    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=stub)
    session = await adapter.open_session()
    default = await session.drive_planner("hello")
    stamped = await session.drive_planner("hello", pattern_id="my-seed-id")
    await session.close()
    assert default.payload_pattern_id == "session-drive"
    assert stamped.payload_pattern_id == "my-seed-id"
