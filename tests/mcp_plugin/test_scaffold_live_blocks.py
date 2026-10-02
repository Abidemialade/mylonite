"""The scaffold writes what it detected as live YAML, so the file runs as written.

A detected seed_arm is the one the scan's own auto-wire would infer, and is
written live. A readback tool that needs no arguments becomes a live
effect_probe when the file suggests W3 or W4. A server with no readback tool
gets W3/W4 marked "effect unconfirmable", naming the reason code the scan then
reports. What the scaffold writes and what the scan does come from the same
detectors.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from tests.mcp_plugin.fakes.neutral_servers import filesystem_tools, memory_tools

from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp.scaffold import _render_target_scaffold, _suggest_weakness_classes
from mylonite.plugins._mcp.target_file import (
    TargetFile,
    infer_seed_arm,
    needs_seed_arm_autowire,
    validate_for_scan,
)
from mylonite.reason_codes import NT_EFFECT_UNCONFIRMABLE
from mylonite.scan.control_shim import coverable_weakness_classes
from mylonite.scan.tool_roles import _classify_tools, readback_tool


def _spec(name: str, props: dict[str, Any], required: list[str], desc: str = "") -> ToolSpec:
    return ToolSpec(
        name=name,
        description=desc,
        json_schema={"type": "object", "properties": props, "required": required},
    )


def _kitchen_sink_tools() -> list[ToolSpec]:
    s = {"type": "string"}
    return [
        _spec("read_note", {"note_id": s}, ["note_id"], "Read a note by id."),
        _spec("write_note", {"note_id": s, "body": s}, ["note_id", "body"], "Write a note."),
        _spec("web_fetch", {"url": s}, ["url"], "Fetch the given URL and return the body."),
        _spec("send_email", {"to": s, "subject": s, "body": s}, ["to", "subject", "body"]),
    ]


def _send_only_tools() -> list[ToolSpec]:
    s = {"type": "string"}
    return [_spec("send_email", {"to": s, "body": s}, ["to", "body"], "Send an email.")]


def _render(tools: list[Any], suggested: list[str] | None = None) -> str:
    return _render_target_scaffold(
        tf=SimpleNamespace(family="custom", command="npx", args=[], env={}, scope=None),
        tool_names=[t.name for t in tools],
        suggested_weaknesses=(_suggest_weakness_classes(tools) if suggested is None else suggested),
        system_prompt_file=None,
        roles=_classify_tools(tools),
        tools=tools,
    )


def _load(rendered: str) -> TargetFile:
    return TargetFile.model_validate(yaml.safe_load(rendered))


def test_detected_seed_arm_and_readback_probe_are_written_live() -> None:
    tools = memory_tools()
    rendered = _render(tools, ["W2", "W4"])
    loaded = _load(rendered)

    expected, _note = infer_seed_arm(tools)
    assert expected is not None
    assert loaded.seed_arm == expected
    assert not needs_seed_arm_autowire(loaded)
    assert validate_for_scan(loaded) == []

    assert loaded.effect_probe is not None
    assert loaded.effect_probe.verify_tool == readback_tool(tools) == "read_graph"
    assert loaded.effect_probe.verify_args_template == {}
    # No deferral words of its own: a "queued" reply stays inconclusive.
    assert loaded.effect_probe.deferred_markers == ()
    assert loaded.effect_probe.deferred_reply_words == ()
    assert "# auto-detected:" in rendered


def test_a_readback_that_needs_arguments_stays_commented_with_its_stub() -> None:
    tools = filesystem_tools()
    rendered = _render(tools, ["W4"])
    loaded = _load(rendered)
    assert loaded.effect_probe is None
    assert "#   verify_tool: list_directory" in rendered
    assert "fill in" in rendered


def test_no_readback_marks_w3_w4_effect_unconfirmable() -> None:
    rendered = _render(_send_only_tools(), ["W1", "W4"])
    loaded = _load(rendered)
    assert loaded.effect_probe is None
    assert "W4" in loaded.weakness_classes
    assert "effect unconfirmable" in rendered
    assert NT_EFFECT_UNCONFIRMABLE in rendered


def test_no_effect_probe_without_an_effectful_class() -> None:
    rendered = _render(memory_tools(), ["W2"])
    assert _load(rendered).effect_probe is None


@pytest.mark.parametrize(
    "tools",
    [memory_tools(), filesystem_tools(), _kitchen_sink_tools(), _send_only_tools()],
    ids=["server-memory", "server-filesystem", "kitchen-sink", "send-only"],
)
def test_scaffold_and_scan_agree(tools: list[Any]) -> None:
    """The written seed_arm is the auto-wire's, the written classes are the
    coverable ones, and the written file passes the scan's own pre-flight."""
    loaded = _load(_render(tools))
    expected, _note = infer_seed_arm(tools)
    assert loaded.seed_arm == expected
    assert loaded.weakness_classes == coverable_weakness_classes(loaded.weakness_classes, tools)
    assert validate_for_scan(loaded) == []


def test_kitchen_sink_names_why_w2_is_left_out() -> None:
    """Its only readback needs a note id the agent never learns, so neither the
    scaffold nor the scan's auto-wire can plant W2 there."""
    tools = _kitchen_sink_tools()
    rendered = _render(tools)
    assert "W2" not in _load(rendered).weakness_classes
    assert infer_seed_arm(tools)[0] is None
    assert "no id-free retrieval tool" in rendered
