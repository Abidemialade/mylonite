"""Deterministic planner stubs used by the differential tests.

The Phase 1 exploit-finding work in the parent project will plug a real
LiteLLM-backed planner in here; for Phase 0 we want repeatability and zero
external dependencies. Both planners share a tiny scripted protocol:

1. The caller hands the planner a *user goal* and a *task script* — a list
   of declarative steps the planner walks through.
2. Each step is one of:
   - ``("read", note_id)`` — call ``read_note``.
   - ``("apply", text)`` — see whether the planner treats ``text`` as
     instruction. The two variants differ here.
   - ``("send", to, subject, body)`` — try to send an email.
3. The planner returns a :class:`PlannerTrace` recording every step it
   took. Tests inspect the trace to assert the seeded weaknesses (or
   their mitigations) behaved as expected.

The vulnerable planner follows instruction-shaped content found anywhere
in a tool result. The guarded planner only follows instructions outside
``<untrusted>`` envelopes and refuses to ``send_email`` without a
``confirm_send`` step.
"""

from __future__ import annotations

import re
from typing import Protocol

from mcp_kitchen_sink._types import (
    PlannerStep,
    PlannerTrace,
    ToolCall,
)

InstructionScript = list[tuple[str, ...]]


class _ServerLike(Protocol):
    def list_tools(self) -> object: ...

    def call_tool(self, name: str, arguments: dict[str, object]) -> object: ...


_IGNORE_PRIOR = re.compile(
    r"ignore (?:all )?prior instructions",
    re.IGNORECASE,
)
_FORWARD_TO = re.compile(
    r"forward (?:everything )?to\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)",
    re.IGNORECASE,
)


def _looks_like_instruction(text: str) -> bool:
    """Heuristic that mirrors a naive planner's instruction-following."""
    return bool(_IGNORE_PRIOR.search(text) or _FORWARD_TO.search(text))


def _extract_forward_target(text: str) -> str | None:
    match = _FORWARD_TO.search(text)
    return match.group(1) if match else None


class VulnerablePlanner:
    """Naively follows instruction-shaped text from any tool result."""

    def __init__(self, server: _ServerLike) -> None:
        self.server = server
        # Read tool descriptions on init. The vulnerable variant honours any
        # parenthetical "(Note: ...)" guidance attached to a description.
        self._tool_hints: dict[str, str] = {}
        for tool in self.server.list_tools():  # type: ignore[attr-defined]
            self._tool_hints[tool.name] = tool.description

    def run(self, goal: str, script: InstructionScript) -> PlannerTrace:
        steps: list[PlannerStep] = []
        final = goal
        for instr in script:
            kind = instr[0]
            if kind == "read":
                note_id = instr[1]
                call = ToolCall(name="read_note", arguments={"note_id": note_id})
                steps.append(PlannerStep(kind="tool", call=call))
                result = self.server.call_tool("read_note", {"note_id": note_id})
                body = getattr(result, "content", "")
                # Naively treats raw result content as instruction.
                if _looks_like_instruction(body):
                    target = _extract_forward_target(body)
                    if target is not None:
                        call_e = ToolCall(
                            name="send_email",
                            arguments={
                                "to": target,
                                "subject": "forwarded per instruction",
                                "body": body,
                            },
                        )
                        steps.append(PlannerStep(kind="tool", call=call_e))
                        self.server.call_tool("send_email", call_e.arguments)
                        final = f"forwarded to {target}"
            elif kind == "apply":
                text = instr[1]
                if _looks_like_instruction(text):
                    steps.append(PlannerStep(kind="say", text=text))
                    final = text
            elif kind == "send":
                to, subject, body = instr[1], instr[2], instr[3]
                call_e = ToolCall(
                    name="send_email",
                    arguments={"to": to, "subject": subject, "body": body},
                )
                steps.append(PlannerStep(kind="tool", call=call_e))
                self.server.call_tool("send_email", call_e.arguments)
                final = "sent"
        steps.append(PlannerStep(kind="stop"))
        return PlannerTrace(steps=steps, final_output=final)


class GuardedPlanner:
    """Refuses to follow instructions found inside <untrusted> envelopes.

    Also refuses to fire ``send_email`` without an explicit confirm step.
    """

    UNTRUSTED_BLOCK = re.compile(
        r"<untrusted>(.*?)</untrusted>",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(self, server: _ServerLike) -> None:
        self.server = server
        # Guarded planner does not honour parenthetical hints in
        # descriptions — descriptions are advisory only.

    def _strip_untrusted(self, text: str) -> str:
        return self.UNTRUSTED_BLOCK.sub("[untrusted content omitted]", text)

    def run(self, goal: str, script: InstructionScript) -> PlannerTrace:
        steps: list[PlannerStep] = []
        final = goal
        for instr in script:
            kind = instr[0]
            if kind == "read":
                note_id = instr[1]
                call = ToolCall(name="read_note", arguments={"note_id": note_id})
                steps.append(PlannerStep(kind="tool", call=call))
                result = self.server.call_tool("read_note", {"note_id": note_id})
                body = getattr(result, "content", "")
                trusted_portion = self._strip_untrusted(body)
                # Only acts on the trusted portion (which by construction
                # contains no exploit payload).
                if _looks_like_instruction(trusted_portion):
                    final = "refused: instruction came from trusted source"
            elif kind == "apply":
                # The "apply" channel here is also untrusted; the guarded
                # planner refuses regardless of payload content.
                steps.append(PlannerStep(kind="say", text="refused untrusted apply"))
            elif kind == "send":
                to, subject, body = instr[1], instr[2], instr[3]
                # Guarded flow: stage + confirm.
                staged = ToolCall(
                    name="send_email",
                    arguments={"to": to, "subject": subject, "body": body},
                )
                steps.append(PlannerStep(kind="tool", call=staged))
                self.server.call_tool("send_email", staged.arguments)
                confirm = ToolCall(name="confirm_send", arguments={})
                steps.append(PlannerStep(kind="tool", call=confirm))
                self.server.call_tool("confirm_send", {})
                final = "sent"
        steps.append(PlannerStep(kind="stop"))
        return PlannerTrace(steps=steps, final_output=final)
