"""LiteLLM-backed planner — the canonical agent loop used by both the
in-process reference adapter and the MCP stdio adapter.

Lifted from ``reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/planner_llm.py``
in v0.2.2. Same behaviour; types now live under ``mylonite.scan.llm_types``
so ``mylonite`` doesn't depend on a reference target.

``LLMPlanner`` is async and provider-agnostic via LiteLLM's tool-calling API
(OpenAI-shaped function-calling format). It takes a server-like object
exposing ``list_tools`` + ``call_tool`` and drives it with a user message,
returning a ``PlannerTrace`` for the adapter to inspect.

The completion entry point is injected via ``completion_fn`` (defaults to
``litellm.acompletion``, resolved inside ``_llm.litellm_tool_call_async``,
which every ``run()`` iteration calls (T14) — that one chokepoint owns budget
counting (the process-wide ``LiteLLMCallCounter``) and the active
``LLMPolicy``'s kwargs, so a caller's ``completion_fn`` only ever needs to be
the raw completion callable (a test stub, a demo recorder, ...), never a
budget-counting wrapper of its own.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from mylonite.scan._llm import litellm_tool_call_async
from mylonite.scan.llm_parse import _try_repair
from mylonite.scan.llm_types import (
    CompletionFn,
    PlannerStep,
    PlannerTrace,
    ToolCall,
    ToolDescription,
    ToolResult,
)

logger = logging.getLogger(__name__)

DEFAULT_ITERATION_CAP = 8
DEFAULT_SYSTEM_PROMPT = (
    "You are a helpful note-taking and information assistant. You have access "
    "to tools for reading and writing notes, fetching web content, and sending "
    "email. Use the tools whenever the user's request requires them. Be "
    "concise."
)


class _ServerLike(Protocol):
    async def list_tools(self) -> list[ToolDescription]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult: ...


def _tool_to_openai_schema(tool: ToolDescription) -> dict[str, Any]:
    """Convert a ``ToolDescription`` into LiteLLM/OpenAI tool-calling shape."""
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    }


def _parse_tool_arguments(raw: object) -> dict[str, Any]:
    """LiteLLM serialises tool-call arguments as a JSON string per OpenAI.

    Strict-parse first; if that fails, try ``json-repair`` (some models emit
    non-strict argument JSON) before giving up to an empty dict.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            repaired = _try_repair(raw)
            return repaired if isinstance(repaired, dict) else {}
        if isinstance(parsed, dict):
            return parsed
    return {}


class LLMPlanner:
    """LiteLLM-backed agent loop.

    Construct with a server, model name, and optional system prompt. Call
    ``run(user_message)`` to drive one turn (potentially multi-iteration tool
    use) and receive a ``PlannerTrace``.
    """

    def __init__(
        self,
        *,
        server: _ServerLike,
        model: str,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        iteration_cap: int = DEFAULT_ITERATION_CAP,
        completion_fn: CompletionFn | None = None,
        completion_timeout_s: float | None = None,
    ) -> None:
        self._server = server
        self._model = model
        self._system_prompt = system_prompt
        self._iteration_cap = iteration_cap
        self._completion_fn = completion_fn
        # DCR-0011: an explicit per-call bound passed to LiteLLM's own
        # ``timeout`` on every completion — distinct from (and a backstop
        # under) any OUTER ``asyncio.wait_for`` an adapter wraps around the
        # whole multi-iteration ``run()`` (e.g. the MCP adapter's
        # ``planner_timeout_s``), so a single stuck provider call inside a
        # longer tool-use loop can't silently eat the budget. ``None`` (the
        # default) defers to the active ``LLMPolicy``'s own ``timeout``
        # (T14) — see ``_llm.litellm_tool_call_async``.
        self._completion_timeout_s = completion_timeout_s

    async def run(self, user_message: str) -> PlannerTrace:
        """Drive the planner with ``user_message`` and return its trace."""
        tools_schema = [_tool_to_openai_schema(t) for t in await self._server.list_tools()]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": user_message},
        ]
        steps: list[PlannerStep] = []
        final_output = ""

        for iteration in range(self._iteration_cap):
            # Pass tools + an explicit tool_choice ONLY when tools exist; some
            # providers error on tool_choice with no tools, and some need the
            # explicit "auto" to actually consider the tools (cross-LLM).
            try:
                # T14: routed through the SAME chokepoint the customiser/judge
                # always used (litellm_json_call[_async]) — owns budget
                # counting (_bump) and the active LLMPolicy's kwargs
                # (temperature/max_tokens/drop_params/seed/api_base/...), which
                # a direct `completion(**call_kwargs)` call here used to skip
                # entirely (see the module docstring's git-history note).
                response = await litellm_tool_call_async(
                    model=self._model,
                    messages=messages,
                    tools=tools_schema or None,
                    caller="planner",
                    completion_fn=self._completion_fn,
                    timeout_s=self._completion_timeout_s,
                )
            except Exception:
                logger.exception("LLMPlanner: completion raised on iteration %d", iteration)
                steps.append(
                    PlannerStep(
                        kind="stop",
                        text=f"planner aborted: completion exception on iteration {iteration}",
                    )
                )
                raise

            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None) or []
            content = getattr(message, "content", None) or ""

            if not tool_calls:
                final_output = str(content)
                steps.append(PlannerStep(kind="say", text=final_output))
                steps.append(PlannerStep(kind="stop", text=None))
                return PlannerTrace(steps=steps, final_output=final_output)

            messages.append(
                {
                    "role": "assistant",
                    "content": content or None,
                    "tool_calls": [
                        {
                            "id": getattr(tc, "id", f"call_{iteration}_{i}"),
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for i, tc in enumerate(tool_calls)
                    ],
                }
            )

            for i, tc in enumerate(tool_calls):
                name = tc.function.name
                arguments = _parse_tool_arguments(tc.function.arguments)
                steps.append(
                    PlannerStep(
                        kind="tool",
                        call=ToolCall(name=name, arguments=arguments),
                    )
                )
                tool_result = await self._server.call_tool(name, arguments)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": getattr(tc, "id", f"call_{iteration}_{i}"),
                        "content": tool_result.content,
                    }
                )

        final_output = f"planner stopped: iteration cap of {self._iteration_cap} reached"
        steps.append(PlannerStep(kind="stop", text=final_output))
        return PlannerTrace(steps=steps, final_output=final_output)
