"""MCP ToolAnnotations as tier-1 classification evidence.

Mylonite previously ignored the protocol's own risk vocabulary entirely
(``grep readOnlyHint src/mylonite`` returned nothing but ``from __future__
import annotations``) and guessed from English words in tool names instead.
The MCP spec defines ``readOnlyHint`` / ``destructiveHint`` / ``idempotentHint``
/ ``openWorldHint`` for exactly the questions W2/W3/W4 ask.

The spec also says annotations are untrusted hints from the server, so they
inform classification but never outrank an operator declaration — and a tool
whose annotation contradicts its observed behaviour is a finding about the
target, not a classification bug to route around.
"""

from __future__ import annotations

import asyncio

from mylonite.scan.control_shim import (
    _CONSEQUENTIAL_HINTS,
    ConfirmGateControl,
    ControlServerShim,
    consequential_tool_names,
)
from mylonite.scan.llm_types import ToolDescription, ToolResult
from mylonite.scan.tool_classifier import (
    annotation_behaviour_mismatch,
    annotation_is_egress,
    annotation_is_read,
    annotation_is_sink,
    classify,
)


def _tool(name: str, annotations: dict | None = None) -> ToolDescription:
    return ToolDescription(
        name=name,
        description="d",
        input_schema={"type": "object", "properties": {}},
        annotations=annotations,
    )


class _Server:
    def __init__(self, tools: list[ToolDescription]) -> None:
        self._tools = tools
        self.calls: list[str] = []

    async def list_tools(self) -> list[ToolDescription]:
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict) -> ToolResult:
        self.calls.append(name)
        return ToolResult(name=name, content="ok", isError=False)


# --- the annotation -> control-question mapping ------------------------------


def test_read_only_tool_is_not_a_sink() -> None:
    assert annotation_is_sink({"readOnlyHint": True}) is False
    assert annotation_is_read({"readOnlyHint": True}) is True


def test_writing_tool_is_a_sink() -> None:
    assert annotation_is_sink({"readOnlyHint": False}) is True
    assert annotation_is_sink({"destructiveHint": True}) is True


def test_open_world_tool_is_egress() -> None:
    assert annotation_is_egress({"openWorldHint": True}) is True
    assert annotation_is_egress({"openWorldHint": False}) is False


def test_undeclared_annotations_are_tri_state_none() -> None:
    """'The server said nothing' must stay distinct from 'the server said
    false', or an absent annotation could clear a tool."""
    assert annotation_is_sink(None) is None
    assert annotation_is_sink({}) is None
    assert annotation_is_sink({"readOnlyHint": "yes"}) is None  # non-bool ignored


# --- tier ordering -----------------------------------------------------------


def test_operator_declaration_outranks_the_annotation() -> None:
    """MCP spec: never make decisions from a possibly-untrusted server's hints.
    A declared list is the operator speaking, and wins."""
    applies, reason = classify(
        "send_email",
        declared=frozenset({"send_email"}),
        hints=_CONSEQUENTIAL_HINTS,
        annotation_says=False,  # server claims it is read-only
    )
    assert (applies, reason) == (True, "declared")


def test_annotation_outranks_the_name_hint() -> None:
    applies, reason = classify(
        "send_email", declared=None, hints=_CONSEQUENTIAL_HINTS, annotation_says=False
    )
    assert (applies, reason) == (False, "mcp tool annotation")


def test_no_annotation_falls_back_to_previous_behaviour() -> None:
    applies, reason = classify(
        "send_email", declared=None, hints=_CONSEQUENTIAL_HINTS, annotation_says=None
    )
    assert (applies, reason) == (True, "name hint")


# --- end to end through the live shim ----------------------------------------


def test_control_uses_annotations_seen_via_list_tools() -> None:
    """A read-only-annotated tool is not gated by the W4 confirm gate."""
    server = _Server([_tool("archive_record", {"readOnlyHint": True})])
    shim = ControlServerShim(server, [ConfirmGateControl()])

    async def run() -> ToolResult:
        await shim.list_tools()  # populates the annotation store
        return await shim.call_tool("archive_record", {})

    result = asyncio.run(run())
    assert result.isError is False
    assert server.calls == ["archive_record"]


def test_without_list_tools_the_control_still_fails_closed() -> None:
    """An unpopulated annotation store must never clear a tool — absence of
    evidence is not evidence of safety."""
    server = _Server([_tool("archive_record", {"readOnlyHint": True})])
    shim = ControlServerShim(server, [ConfirmGateControl()])
    result = asyncio.run(shim.call_tool("archive_record", {}))
    assert result.isError is True
    assert server.calls == []


def test_annotations_are_read_before_any_description_transform() -> None:
    """A control that rewrites descriptions must not be able to change what
    another control learns about declared risk."""

    class Rewriter(ConfirmGateControl):
        def transform_description(self, tool: ToolDescription) -> ToolDescription:
            return tool.model_copy(update={"annotations": None})

    server = _Server([_tool("archive_record", {"readOnlyHint": True})])
    gate = ConfirmGateControl()
    shim = ControlServerShim(server, [Rewriter(), gate])

    async def run() -> ToolResult:
        await shim.list_tools()
        return await shim.call_tool("archive_record", {})

    assert asyncio.run(run()).isError is False


def test_static_check_report_reads_annotations_off_the_tool_spec() -> None:
    from mylonite.contracts._types import ToolSpec

    tools = [
        ToolSpec(name="send_email", description="d", annotations={"readOnlyHint": True}),
        ToolSpec(name="delete_file", description="d", annotations={"destructiveHint": True}),
    ]
    reported = dict(consequential_tool_names(tools))
    assert "send_email" not in reported  # server says read-only
    assert reported["delete_file"] == "mcp tool annotation"


# --- annotations are hints, and a lying hint is itself a finding -------------


def test_annotation_behaviour_mismatch_is_detectable() -> None:
    assert annotation_behaviour_mismatch({"readOnlyHint": True}, observed_write=True) is not None
    assert annotation_behaviour_mismatch({"readOnlyHint": True}, observed_write=False) is None
    assert annotation_behaviour_mismatch({"readOnlyHint": False}, observed_write=True) is None
    assert annotation_behaviour_mismatch(None, observed_write=True) is None
