"""Tool-role primitives (schema heuristics shared by scan --scaffold)."""

from __future__ import annotations

from types import SimpleNamespace

from mylonite.scan.tool_roles import (
    _content_param,
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
