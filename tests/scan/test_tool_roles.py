"""Tool-role primitives (schema heuristics shared by scan --scaffold)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from mylonite.scan.tool_roles import (
    _content_param,
    _content_slot_template,
    _genuine_content_param,
    _id_param,
    _read_by_id_tool,
    _requires_id,
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


# --- DCR-0015: token-boundary matching, not substring -------------------------


def test_id_param_does_not_false_positive_on_a_word_containing_id_as_substring() -> None:
    """A plain substring test would wrongly treat "guidance" as id-shaped
    (it contains "id"). Token-boundary matching must not."""
    tool = _tool("summarize", _str("guidance", "body"), ["body"])
    assert _id_param(tool) is None


def test_genuine_content_param_does_not_false_positive_on_keyword() -> None:
    """ "keyword" contains the "key" id-hint as a substring but is not an id
    param — must still be picked as the content slot."""
    tool = _tool("search", _str("keyword"), [])
    assert _genuine_content_param(tool) == "keyword"


def test_content_param_still_rejects_a_genuine_id_shaped_param() -> None:
    """The token-boundary rewrite must not lose the original id-rejection
    fallback: when NEITHER param matches a content hint, the first NON-id
    string param wins over a genuinely id-shaped one ("ref" is a literal
    ID_PARAM_HINTS token)."""
    tool = _tool("process", _str("ref", "raw_input"), ["ref"])
    assert _content_param(tool) == "raw_input"


def test_requires_id_still_true_for_a_genuine_id_shaped_required_param() -> None:
    tool = _tool("read_note", _str("note_id"), ["note_id"])
    assert _requires_id(tool) is True


def test_requires_id_false_for_a_required_param_merely_containing_id_substring() -> None:
    """A required param named "valid" contains "id" as a substring but is not
    an id-shaped handle — must not be treated as one."""
    tool = _tool("check", _str("valid"), ["valid"])
    assert _requires_id(tool) is False


# --- #324: type-union blindness ------------------------------------------------
#
# Reproduces the exact schema shapes the issue #324 investigation captured from
# two third-party MCP servers' own advertised ``inputSchema`` (no local paths,
# no live calls): go-memory's nullable-array fields, and mcp-redis's Pydantic
# ``Union`` field with no inline ``"type"`` key at all.


def _schema_tool(name: str, schema: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(name=name, description="", json_schema=schema)


def test_content_slot_template_sees_a_go_sdk_nullable_array_field() -> None:
    """go-memory's ``add_observations``/``create_relations`` type their arrays
    as ``"type": ["null", "array"]`` (the Go JSON-Schema generator's own idiom
    for an optional field) rather than the bare ``"array"`` the TS server
    uses. A plain ``spec.get("type") == "array"`` equality check against a
    list never matched, so the whole tool was invisible as a content slot."""
    tool = _schema_tool(
        "add_observations",
        {
            "type": "object",
            "properties": {
                "observations": {
                    "type": ["null", "array"],
                    "items": {
                        "type": "object",
                        "properties": {
                            "entityName": {"type": "string"},
                            "contents": {"type": ["null", "array"], "items": {"type": "string"}},
                        },
                        "required": ["entityName", "contents"],
                    },
                }
            },
            "required": ["observations"],
        },
    )
    assert _content_slot_template(tool) == (
        "observations",
        {"observations": [{"contents": ["{payload}"], "entityName": "mylonite-probe"}]},
    )


def test_content_slot_template_unwraps_a_pydantic_anyof_union_to_its_string_branch() -> None:
    """mcp-redis's ``set`` types its ``value`` argument as a Pydantic
    ``Union[str, bytes, int, float, dict]`` -- an ``anyOf`` list with NO
    inline ``"type"`` key on the wrapper at all. ``spec.get("type")`` read
    ``None`` for it, so ``set`` (the obviously-correct write for a KV store)
    was never offered as a candidate; the walker fell through to a
    two-argument tool (``expire``) it could not fully construct a call for."""
    tool = _schema_tool(
        "set",
        {
            "type": "object",
            "properties": {
                "key": {"type": "string", "title": "Key"},
                "value": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "string", "format": "binary"},
                        {"type": "integer"},
                        {"type": "number"},
                        {"type": "object", "additionalProperties": True},
                    ],
                    "title": "Value",
                },
                "expiration": {
                    "anyOf": [{"type": "integer"}, {"type": "null"}],
                    "default": None,
                    "title": "Expiration",
                },
            },
            "required": ["key", "value"],
        },
    )
    assert _content_slot_template(tool) == ("value", {"value": "{payload}"})


def test_content_slot_template_skips_a_nested_field_whose_required_sibling_is_unfillable() -> None:
    """Inside a nested batched-record shape, a required sibling with no
    generic schema-valid literal (an object this walker has no shape for)
    must not be silently left missing — that field is skipped in favour of
    the next-ranked one, never an invalid call (#324)."""
    tool = _schema_tool(
        "create_entries",
        {
            "type": "object",
            "properties": {
                "entries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "body": {"type": "string"},
                            "metadata": {"type": "object", "properties": {}},
                        },
                        "required": ["body", "metadata"],
                    },
                }
            },
            "required": ["entries"],
        },
    )
    # "body" is the obvious content slot, but its REQUIRED sibling "metadata"
    # (an object with no further shape) has no safe literal — so no field at
    # this level may be used, and the walker has nothing else to fall back to.
    assert _content_slot_template(tool) is None


def test_content_slot_template_fills_a_required_integer_sibling() -> None:
    """A required sibling typed integer/number/boolean gets a neutral,
    schema-valid literal instead of being silently left missing (#324)."""
    tool = _schema_tool(
        "create_entry",
        {
            "type": "object",
            "properties": {
                "entry": {
                    "type": "object",
                    "properties": {
                        "body": {"type": "string"},
                        "priority": {"type": "integer"},
                    },
                    "required": ["body", "priority"],
                }
            },
            "required": ["entry"],
        },
    )
    assert _content_slot_template(tool) == (
        "entry",
        {"entry": {"body": "{payload}", "priority": 0}},
    )


def test_content_slot_template_skips_a_nested_id_shaped_integer_sibling() -> None:
    """#324 review I3: an id-shaped required sibling (``chat_id``) must never
    be auto-filled with ``0``, whatever its type -- a bare ``0`` can BE a
    real (often root/default) resource, unlike the per-run token a string
    fill uses. The field is skipped, and since it is the only candidate here,
    the whole tool has no content slot."""
    tool = _schema_tool(
        "create_entry",
        {
            "type": "object",
            "properties": {
                "entry": {
                    "type": "object",
                    "properties": {
                        "body": {"type": "string"},
                        "chat_id": {"type": "integer"},
                    },
                    "required": ["body", "chat_id"],
                }
            },
            "required": ["entry"],
        },
    )
    assert _content_slot_template(tool) is None
