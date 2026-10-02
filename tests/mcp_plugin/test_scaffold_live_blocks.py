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
from mylonite.scan.tool_roles import _classify_tools, effect_readback


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
    assert loaded.effect_probe.verify_tool == "read_graph"
    choice = effect_readback(tools)
    assert choice is not None and choice.tool == "read_graph" and choice.tied
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
    assert "#   verify_tool: read_file" in rendered
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


def _t(name: str, required: tuple[str, ...] = (), **annotations: Any) -> ToolSpec:
    props = {r: {"type": "string"} for r in required}
    return ToolSpec(
        name=name,
        description="",
        json_schema={"type": "object", "properties": props, "required": list(required)},
        annotations=annotations,
    )


_SEND = _t("send_email", ("to", "body"))


@pytest.mark.parametrize(
    "unsafe",
    [_t("logout"), _t("clear_log", destructiveHint=True), _t("deploy_target")],
    ids=["logout", "clear_log-destructive", "deploy_target"],
)
def test_an_unsafe_tool_is_never_written_as_a_live_probe(unsafe: ToolSpec) -> None:
    """The scan calls verify_tool before and after every attempt, so a tool
    that logs out, clears a log or deploys must never be written live. With
    no probe written, the class reads NOT TESTED, never resisted."""
    tools = [_SEND, unsafe]
    assert effect_readback(tools) is None
    rendered = _render(tools, ["W4"])
    assert _load(rendered).effect_probe is None
    assert f"verify_tool: {unsafe.name}" not in rendered
    assert NT_EFFECT_UNCONFIRMABLE in rendered


def test_a_write_annotated_or_destructive_reader_is_never_live() -> None:
    tools = [_SEND, _t("list_jobs", readOnlyHint=False), _t("get_status", destructiveHint=True)]
    assert effect_readback(tools) is None
    assert _load(_render(tools, ["W4"])).effect_probe is None


def test_a_tied_readback_beats_an_unrelated_one_listed_first() -> None:
    tools = [_t("save_note", ("body",)), _t("list_notes"), _SEND, _t("sent_log")]
    choice = effect_readback(tools)
    assert choice is not None and choice.tool == "sent_log" and choice.tied
    probe = _load(_render(tools, ["W4"])).effect_probe
    assert probe is not None and probe.verify_tool == "sent_log"


def test_an_untied_readback_stays_a_commented_hint() -> None:
    tools = [_SEND, _t("list_notes")]
    choice = effect_readback(tools)
    assert choice is not None and choice.tool == "list_notes" and not choice.tied
    rendered = _render(tools, ["W4"])
    assert _load(rendered).effect_probe is None
    assert "#   verify_tool: list_notes" in rendered
    assert NT_EFFECT_UNCONFIRMABLE in rendered


def test_the_live_probe_says_calibration_makes_real_calls() -> None:
    rendered = _render(memory_tools(), ["W4"])
    assert "calls up to five of this server's" in rendered
    assert "calibration: {controls: skip}" in rendered
    assert "docs/target-file.md" in rendered
