"""Tool-role primitives + AttackPlan auto-discovery (Driver 1 / Slice 3)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from mylonite.scan.attack_loop import discover_attack_plan
from mylonite.scan.tool_roles import (
    _genuine_content_param,
    _id_param,
    _read_by_id_tool,
)


def _tool(name: str, props: dict[str, dict], required: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        description="",
        json_schema={"type": "object", "properties": props, "required": required},
    )


def _str(*names: str) -> dict[str, dict]:
    return {n: {"type": "string"} for n in names}


def test_id_param_prefers_required_id_shaped() -> None:
    tool = _tool("write_note", _str("note_id", "body"), ["note_id", "body"])
    assert _id_param(tool) == "note_id"


def test_genuine_content_param_rejects_id_only_tool() -> None:
    # read_note has only an id-shaped string param — not a real content slot.
    assert _genuine_content_param(_tool("read_note", _str("note_id"), ["note_id"])) is None
    # write_note has a free-text body — that IS the content slot.
    assert (
        _genuine_content_param(_tool("write_note", _str("note_id", "body"), ["note_id"])) == "body"
    )


def test_read_by_id_tool_found_even_when_id_required() -> None:
    tools = [
        _tool("read_note", _str("note_id"), ["note_id"]),
        _tool("write_note", _str("note_id", "body"), ["note_id", "body"]),
    ]
    assert _read_by_id_tool(tools) == "read_note"


def test_discover_attack_plan_on_reference_surface() -> None:
    """The store/read-by-id surface (write_note + read_note) yields a usable plan
    even though read_note REQUIRES the id — the loop mints the id itself."""
    from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter

    descriptor = asyncio.run(InProcessReferenceAdapter(variant="vulnerable").describe())
    plan = discover_attack_plan(descriptor)
    assert plan is not None
    assert plan.plant_tool == "write_note"
    assert plan.plant_args["body"] == "{payload}"
    assert plan.plant_args["note_id"] == "{id}"
    assert "{id}" in plan.drive_message


def test_discover_returns_none_without_a_store() -> None:
    descriptor = SimpleNamespace(
        tools=[
            _tool("web_fetch", _str("url"), ["url"]),
            _tool("send_email", _str("to", "subject", "body"), ["to", "subject", "body"]),
        ]
    )
    # send_email has a body, but its name carries no store hint, and there is no
    # retrieval path — so no indirect-injection plan is discoverable here.
    assert discover_attack_plan(descriptor) is None
