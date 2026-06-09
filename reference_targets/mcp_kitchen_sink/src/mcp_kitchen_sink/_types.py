"""Shared Pydantic types for the kitchen-sink reference agent."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ToolDescription(BaseModel):
    """Mirror of the MCP `tools/list` entry shape (subset)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    input_schema: dict[str, object]


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
