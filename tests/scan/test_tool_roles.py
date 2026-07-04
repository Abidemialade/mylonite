"""Tool-role primitives (schema heuristics shared by scan --scaffold)."""

from __future__ import annotations

from types import SimpleNamespace

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
