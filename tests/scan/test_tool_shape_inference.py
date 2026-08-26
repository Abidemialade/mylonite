"""Regression tests for tool-shape assumptions hardcoded across the scanner.

Pins two tool-shape findings:

* the batched array-of-records blind spot — auto-wire was structurally blind to
  the batched array-of-records write, a common MCP idiom, because
  ``_schema_props`` only ever read TOP-LEVEL ``properties``.
* the ``classify()`` substring bug — ``get_postal_code`` was reported as a
  confirmed consequential tool because ``"post"`` is a substring of
  ``"postal"``.
"""

from __future__ import annotations

from mylonite.contracts._types import ToolSpec
from mylonite.plugins._mcp.target_file import infer_seed_arm
from mylonite.scan.control_shim import _CONSEQUENTIAL_HINTS, _READ_HINTS
from mylonite.scan.tool_classifier import classify, hint_matches, name_tokens

# The real @modelcontextprotocol/server-memory schemas, verbatim in shape.
_CREATE_ENTITIES = ToolSpec(
    name="create_entities",
    description="Create multiple new entities in the knowledge graph",
    json_schema={
        "type": "object",
        "properties": {
            "entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "entityType": {"type": "string"},
                        "observations": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["name", "entityType", "observations"],
                },
            }
        },
        "required": ["entities"],
    },
)
_READ_GRAPH = ToolSpec(
    name="read_graph",
    description="Read the graph",
    json_schema={"type": "object", "properties": {}},
)


def _template(tools: list[ToolSpec]) -> dict | None:
    spec, _note = infer_seed_arm(tools)
    return None if spec is None else dict(spec.args_template)


# --- the batched-array blind spot --------------------------------------------


def test_batched_array_write_tool_now_yields_a_seed_arm() -> None:
    """Pre-fix this reported 'no content-storing tool found' and left seed_arm
    commented out, so W2 was untestable against the whole class of servers whose
    write tools batch records behind one array property."""
    assert _template([_CREATE_ENTITIES, _READ_GRAPH]) is not None


def test_payload_lands_in_the_free_text_slot_not_the_label() -> None:
    """`observations` is free text an injection can ride in; `name` is a label.
    Schema order would have picked `name` — the ranking must not depend on it."""
    template = _template([_CREATE_ENTITIES, _READ_GRAPH])
    assert template is not None
    record = template["entities"][0]
    assert record["observations"] == ["{payload}"]
    assert "{payload}" not in str(record["name"])


def test_sibling_required_fields_are_filled_so_the_call_validates() -> None:
    record = _template([_CREATE_ENTITIES, _READ_GRAPH])["entities"][0]  # type: ignore[index]
    assert set(record) >= {"name", "entityType", "observations"}


def test_flat_string_param_is_unchanged() -> None:
    """The higher-fidelity flat shape must keep winning — every existing target
    file and fixture depends on it."""
    flat = ToolSpec(
        name="save_note",
        description="Save a note",
        json_schema={
            "type": "object",
            "properties": {"body": {"type": "string"}},
            "required": ["body"],
        },
    )
    assert _template([flat, _READ_GRAPH]) == {"body": "{payload}"}


def test_id_only_tool_still_finds_nothing() -> None:
    """An id is a handle, not a content slot. Recursing must not weaken the
    guard that keeps a payload out of an id param."""
    id_only = ToolSpec(
        name="create_link",
        description="Link two records",
        json_schema={
            "type": "object",
            "properties": {"target_id": {"type": "string"}},
            "required": ["target_id"],
        },
    )
    assert _template([id_only, _READ_GRAPH]) is None


def test_pathological_nesting_terminates() -> None:
    deep: dict = {"type": "string"}
    for _ in range(12):
        deep = {"type": "array", "items": deep}
    tool = ToolSpec(
        name="create_tree",
        description="d",
        json_schema={"type": "object", "properties": {"n": deep}},
    )
    assert _template([tool, _READ_GRAPH]) is None  # depth-capped, no hang


# --- the substring classification bug ----------------------------------------


def test_hints_match_on_tokens_not_substrings() -> None:
    assert name_tokens("get_postal_code") == {"get", "postal", "code"}
    assert name_tokens("sendEmail") == {"send", "email"}
    assert hint_matches("send_email", _CONSEQUENTIAL_HINTS) is True
    # "post" must not match inside "postal"; "create" must not match "increatement".
    assert hint_matches("get_postal_code", _CONSEQUENTIAL_HINTS) is False
    assert hint_matches("increatement_counter", _CONSEQUENTIAL_HINTS) is False


def test_substring_false_positive_no_longer_reported_as_a_name_hint() -> None:
    """`reason` drives what `mylonite check` reports as a confirmed
    consequential tool, so a bogus 'name hint' was user-visible."""
    _applies, reason = classify("get_postal_code", declared=None, hints=_CONSEQUENTIAL_HINTS)
    assert reason == "fail-closed default"


def test_genuine_name_hints_still_match() -> None:
    for name in ("send_email", "delete_file", "create_issue", "transfer_funds"):
        applies, reason = classify(name, declared=None, hints=_CONSEQUENTIAL_HINTS)
        assert (applies, reason) == (True, "name hint"), name
    for name in ("read_note", "list_files", "search_nodes"):
        applies, reason = classify(name, declared=None, hints=_READ_HINTS)
        assert (applies, reason) == (True, "name hint"), name
