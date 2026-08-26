"""Shared Pydantic types for the LLM-backed planner and MCP adapters.

Lifted from ``mcp_kitchen_sink._types`` in v0.2.2 so ``mylonite.scan.llm_planner``
and the MCP stdio adapter (``mylonite.plugins._mcp``) can share a single
``_ServerLike`` Protocol without ``mylonite`` depending on a reference target.

The kitchen-sink ``_types`` module re-exports these classes for backwards
compatibility with the existing in-tree call sites.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: The LLM transport seam: a litellm-compatible completion callable injected in
#: place of a live model call (tests pass a stub; production passes
#: ``litellm.completion``/``acompletion``). Its arguments are untyped because that
#: mirrors litellm's own ``**kwargs`` interface -- the call sites forward a
#: ``dict[str, Any]`` of policy + request kwargs via ``fn(**call_kwargs)``. The
#: value of the alias is a single named, greppable type for a seam that was an
#: anonymous ``Callable[..., Any]`` in ~27 signatures across five subpackages.
CompletionFn = Callable[..., Any]

#: The async form of :data:`CompletionFn` (``litellm.acompletion``), for the
#: transport paths that ``await`` the result.
AsyncCompletionFn = Callable[..., Awaitable[Any]]


class ToolDescription(BaseModel):
    """Mirror of the MCP ``tools/list`` entry shape (subset)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    input_schema: dict[str, object]
    annotations: dict[str, object] | None = None
    """The tool's MCP ``ToolAnnotations``, verbatim, or None if it declared none.

    MCP standardises a risk vocabulary here — ``readOnlyHint``,
    ``destructiveHint``, ``idempotentHint``, ``openWorldHint`` — which is a far
    better classification signal than guessing from English words in the tool's
    name. Carried untyped (a plain dict) so a server may add fields the SDK does
    not model without this shim dropping them.

    Per the MCP spec these are HINTS from a possibly-untrusted server, so they
    inform classification but never override an operator's own declaration —
    see ``tool_classifier.classify``.
    """


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, object]


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    content: str
    isError: bool = False


class PlannerStep(BaseModel):
    """A single planner action: emit text or call a tool."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["say", "tool", "stop"]
    text: str | None = None
    call: ToolCall | None = None


class PlannerTrace(BaseModel):
    """The trace of a planner run, used by tests to inspect behaviour."""

    model_config = ConfigDict(extra="forbid")

    steps: list[PlannerStep]
    final_output: str

    def calls(self, name: str) -> list[ToolCall]:
        return [
            step.call
            for step in self.steps
            if step.kind == "tool" and step.call is not None and step.call.name == name
        ]
