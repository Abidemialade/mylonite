"""Tests for T15 (H4) — dialect-aware tool-schema normalisation.

Covers: :mod:`mylonite.scan.schema_sanitise` (``SchemaDialect``, ``dialect_for``,
``sanitise_tool_schema``) plus its wiring into ``scan._llm.litellm_tool_call_async``
(the planner's SOLE chokepoint for sending tool schemas to an LLM) and the
``fallback_breakdown["tool_schema_sanitised"]`` counter.

Deliberately does NOT touch the adapter/``TargetDescriptor`` layer — that path
must stay unsanitised (see ``test_planner_sanitises_its_own_copy_not_the_source_schema``
below) so attack modules keep reasoning over the target's real tool surface.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.scan._llm import LiteLLMCallCounter, litellm_tool_call_async, llm_scope
from mylonite.scan.llm_planner import LLMPlanner
from mylonite.scan.llm_types import ToolDescription, ToolResult
from mylonite.scan.model_ref import ModelRef
from mylonite.scan.schema_sanitise import (
    SchemaDialect,
    dialect_for,
    sanitise_tool_schema,
)

# ---------------------------------------------------------------------------
# Realistic MCP-server-generated schema fixtures.
#
# Python MCP SDKs typically build tool ``inputSchema`` via
# ``pydantic.BaseModel.model_json_schema()``. That emits ``$defs``/``$ref`` for
# any nested model, ``anyOf`` for any ``Optional[...]``/``X | None`` field, and
# (with a ``Literal[...]`` of one value) a ``const``. These fixtures mirror
# that shape rather than inventing an unrealistic one.
# ---------------------------------------------------------------------------


def _schema_with_ref() -> dict[str, Any]:
    """A pydantic-generated schema: a nested model pulled out into $defs."""
    return {
        "type": "object",
        "properties": {
            "note_id": {"type": "string"},
            "filter": {"$ref": "#/$defs/NoteFilter"},
        },
        "required": ["note_id"],
        "$defs": {
            "NoteFilter": {
                "type": "object",
                "properties": {
                    "tag": {"type": "string"},
                    "archived": {"type": "boolean"},
                },
                "required": ["tag"],
            }
        },
    }


def _schema_with_any_of() -> dict[str, Any]:
    """Optional[str] under pydantic v2 becomes an anyOf of [string, null]."""
    return {
        "type": "object",
        "properties": {
            "note_id": {"type": "string"},
            "tag": {
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "description": "Optional tag filter.",
            },
        },
        "required": ["note_id"],
    }


def _schema_with_const() -> dict[str, Any]:
    """Literal["email"] under pydantic v2 becomes {"const": "email"}."""
    return {
        "type": "object",
        "properties": {
            "channel": {"const": "email", "type": "string"},
            "to": {"type": "string"},
        },
        "required": ["channel", "to"],
        "additionalProperties": False,
    }


def _clean_schema() -> dict[str, Any]:
    """No $ref/anyOf/const/additionalProperties -- STRICT should be a no-op."""
    return {
        "type": "object",
        "properties": {
            "note_id": {"type": "string", "description": "the note id"},
            "count": {"type": "integer"},
        },
        "required": ["note_id"],
    }


# ---------------------------------------------------------------------------
# dialect_for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provider",
    ["anthropic", "openai"],
)
def test_dialect_for_permissive_providers(provider: str) -> None:
    ref = ModelRef(raw=f"{provider}/some-model", provider=provider)
    assert dialect_for(ref) is SchemaDialect.PERMISSIVE


@pytest.mark.parametrize(
    "provider",
    ["google", "bedrock"],
)
def test_dialect_for_strict_providers(provider: str) -> None:
    ref = ModelRef(raw=f"{provider}/some-model", provider=provider)
    assert dialect_for(ref) is SchemaDialect.STRICT


def test_dialect_for_gemini_alias_normalises_to_google_strict() -> None:
    """``ModelRef.provider`` is already normalised (gemini/vertex_ai -> google)
    by ``providers.provider_from_model`` -- ``dialect_for`` just needs to
    recognise the normalised spelling."""
    ref = ModelRef(raw="gemini/gemini-1.5-pro", provider="google")
    assert dialect_for(ref) is SchemaDialect.STRICT


def test_dialect_for_unknown_provider_defaults_to_permissive() -> None:
    """An unrecognised/undetermined provider defaults to PERMISSIVE (a no-op
    passthrough) rather than STRICT -- mangling a schema for a provider that
    might actually tolerate the full JSON Schema feature set would be a
    worse failure mode than doing nothing."""
    ref = ModelRef(raw="some-custom-model", provider=None)
    assert dialect_for(ref) is SchemaDialect.PERMISSIVE

    ref2 = ModelRef(raw="mistral/mistral-large", provider="mistral")
    assert dialect_for(ref2) is SchemaDialect.PERMISSIVE


# ---------------------------------------------------------------------------
# sanitise_tool_schema — PERMISSIVE
# ---------------------------------------------------------------------------


def test_permissive_is_a_no_op_for_ref() -> None:
    schema = _schema_with_ref()
    assert sanitise_tool_schema(schema, SchemaDialect.PERMISSIVE) == schema


def test_permissive_is_a_no_op_for_any_of() -> None:
    schema = _schema_with_any_of()
    assert sanitise_tool_schema(schema, SchemaDialect.PERMISSIVE) == schema


def test_permissive_is_a_no_op_for_const() -> None:
    schema = _schema_with_const()
    assert sanitise_tool_schema(schema, SchemaDialect.PERMISSIVE) == schema


# ---------------------------------------------------------------------------
# sanitise_tool_schema — STRICT
# ---------------------------------------------------------------------------


def test_strict_inlines_ref_and_defs() -> None:
    schema = _schema_with_ref()
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert "$defs" not in out
    filter_schema = out["properties"]["filter"]
    assert "$ref" not in filter_schema
    # The referenced object's own shape made it into the referencing location.
    assert filter_schema["type"] == "object"
    assert filter_schema["properties"]["tag"] == {"type": "string"}
    assert filter_schema["properties"]["archived"] == {"type": "boolean"}


def test_strict_flattens_any_of() -> None:
    schema = _schema_with_any_of()
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    tag_schema = out["properties"]["tag"]
    assert "anyOf" not in tag_schema
    assert tag_schema["type"] == "string"
    # Sibling keys survive the flattening.
    assert tag_schema["description"] == "Optional tag filter."


def test_strict_converts_const_to_single_value_enum() -> None:
    schema = _schema_with_const()
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    channel_schema = out["properties"]["channel"]
    assert "const" not in channel_schema
    assert channel_schema["enum"] == ["email"]


def test_strict_infers_type_for_a_bare_const() -> None:
    """pydantic's model_json_schema() emits a bare {"const": ...} for a
    single-value Literal[...] -- no "type" key at all. A STRICT provider's
    OpenAPI-derived parser generally expects every property to carry an
    explicit "type", so the const->enum conversion should backfill one."""
    schema = {
        "type": "object",
        "properties": {"kind": {"const": "issue"}},
        "required": ["kind"],
    }
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    kind_schema = out["properties"]["kind"]
    assert kind_schema["enum"] == ["issue"]
    assert kind_schema["type"] == "string"


def test_strict_does_not_override_an_explicit_type_alongside_const() -> None:
    schema = {"const": True, "type": "boolean"}
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert out["type"] == "boolean"
    assert out["enum"] == [True]


def test_strict_drops_additional_properties() -> None:
    schema = _schema_with_const()  # also carries additionalProperties: False
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert "additionalProperties" not in out


def test_strict_idempotent_on_clean_schema() -> None:
    schema = _clean_schema()
    assert sanitise_tool_schema(schema, SchemaDialect.STRICT) == schema


def test_permissive_idempotent_on_clean_schema() -> None:
    schema = _clean_schema()
    assert sanitise_tool_schema(schema, SchemaDialect.PERMISSIVE) == schema


def test_strict_does_not_mutate_the_input_schema() -> None:
    """Purity: the caller's dict must come back unchanged, byte for byte,
    even though the function's return value differs."""
    schema = _schema_with_ref()
    import copy

    original = copy.deepcopy(schema)
    sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert schema == original


# ---------------------------------------------------------------------------
# sanitise_tool_schema — TOTAL (never raises)
# ---------------------------------------------------------------------------


def test_never_raises_on_dangling_ref() -> None:
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/DoesNotExist"}},
    }
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert isinstance(out, dict)


def test_never_raises_on_deeply_nested_any_of() -> None:
    nested: dict[str, Any] = {"type": "string"}
    for _ in range(50):
        nested = {"anyOf": [nested, {"type": "null"}]}
    schema = {"type": "object", "properties": {"x": nested}}
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert isinstance(out, dict)


def test_never_raises_on_self_referential_ref() -> None:
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/Loop"}},
        "$defs": {"Loop": {"$ref": "#/$defs/Loop"}},
    }
    out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
    assert isinstance(out, dict)


def test_never_raises_on_malformed_shapes() -> None:
    """Fields that are the wrong JSON *type* entirely (a list where a dict is
    expected, ``None`` where a dict is expected, ...) must degrade, not raise."""
    weird_schemas: list[Any] = [
        {"type": "object", "properties": "not-a-dict"},
        {"type": "object", "properties": {"x": None}},
        {"type": "object", "properties": {"x": ["not", "a", "dict"]}},
        {"anyOf": "not-a-list"},
        {"anyOf": []},
        {"$defs": "not-a-dict"},
        {"$ref": 12345},
        {},
        {"const": {"nested": "value"}},
    ]
    for schema in weird_schemas:
        out = sanitise_tool_schema(schema, SchemaDialect.STRICT)
        assert isinstance(out, dict), f"failed on {schema!r}"


def test_never_raises_on_non_dict_input() -> None:
    # Defensive: sanitise_tool_schema is typed to take a dict, but a caller
    # somewhere upstream handing it something else must not crash the scan.
    for bad_input in [None, "not a schema", 123, ["a", "list"]]:
        out = sanitise_tool_schema(bad_input, SchemaDialect.STRICT)  # type: ignore[arg-type]
        assert isinstance(out, dict)
        out2 = sanitise_tool_schema(bad_input, SchemaDialect.PERMISSIVE)  # type: ignore[arg-type]
        assert isinstance(out2, dict)


# ---------------------------------------------------------------------------
# Wiring into litellm_tool_call_async (the planner's chokepoint)
# ---------------------------------------------------------------------------


def _text_response(text: str = "done.") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


@pytest.mark.asyncio
async def test_tool_call_async_sanitises_tools_for_strict_model() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _text_response()

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_notes",
                "description": "fetch notes",
                "parameters": _schema_with_ref(),
            },
        }
    ]
    await litellm_tool_call_async(
        model="gemini/gemini-1.5-pro",
        messages=[{"role": "user", "content": "hi"}],
        tools=tools,
        completion_fn=stub,
    )
    sent_tools = seen[0]["tools"]
    sent_params = sent_tools[0]["function"]["parameters"]
    assert "$ref" not in str(sent_params)
    assert "$defs" not in sent_params


@pytest.mark.asyncio
async def test_tool_call_async_leaves_tools_untouched_for_permissive_model() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _text_response()

    original_params = _schema_with_ref()
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_notes",
                "description": "fetch notes",
                "parameters": original_params,
            },
        }
    ]
    await litellm_tool_call_async(
        model="anthropic/claude-haiku-4-5",
        messages=[{"role": "user", "content": "hi"}],
        tools=tools,
        completion_fn=stub,
    )
    sent_tools = seen[0]["tools"]
    assert sent_tools[0]["function"]["parameters"] == original_params
    assert "$ref" in sent_tools[0]["function"]["parameters"]["properties"]["filter"]


# ---------------------------------------------------------------------------
# The adapter/TargetDescriptor path stays untouched.
# ---------------------------------------------------------------------------


class _FakeServer:
    """A minimal ``_ServerLike`` whose ``list_tools`` reports a real,
    unsanitised MCP schema (with $ref/anyOf/const), the way an MCP adapter
    reporting a ``TargetDescriptor`` would."""

    def __init__(self) -> None:
        self.tool_description = ToolDescription(
            name="get_notes",
            description="fetch notes",
            input_schema=_schema_with_ref(),
        )

    async def list_tools(self) -> list[ToolDescription]:
        return [self.tool_description]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        return ToolResult(name=name, content="ok")


@pytest.mark.asyncio
async def test_planner_sanitises_its_own_copy_not_the_source_schema() -> None:
    """The planner sends a sanitised COPY to a STRICT-dialect model's
    completion call, but the server's own ``ToolDescription.input_schema``
    (what attack modules see via ``TargetDescriptor``) must be completely
    untouched -- both while the planner is mid-run and after it returns."""
    server = _FakeServer()
    original_input_schema = server.tool_description.input_schema
    import copy

    before = copy.deepcopy(original_input_schema)

    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _text_response()

    planner = LLMPlanner(
        server=server, model="bedrock/anthropic.claude-3-haiku", completion_fn=stub
    )
    await planner.run("Hi.")

    # The source-of-truth schema is byte-for-byte unchanged.
    assert server.tool_description.input_schema == before
    assert "$ref" in str(server.tool_description.input_schema)

    # But what was actually SENT to the STRICT-dialect model was sanitised.
    sent_params = seen[0]["tools"][0]["function"]["parameters"]
    assert "$ref" not in str(sent_params)


# ---------------------------------------------------------------------------
# fallback_breakdown["tool_schema_sanitised"] counter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_counter_increments_when_sanitisation_changes_a_schema() -> None:
    counter = LiteLLMCallCounter(cap=10)

    async def stub(**_: Any) -> SimpleNamespace:
        return _text_response()

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_notes",
                "description": "fetch notes",
                "parameters": _schema_with_ref(),
            },
        }
    ]
    with llm_scope(counter=counter):
        await litellm_tool_call_async(
            model="gemini/gemini-1.5-pro",
            messages=[{"role": "user", "content": "hi"}],
            tools=tools,
            completion_fn=stub,
        )
    assert counter.tool_schema_sanitised == 1


@pytest.mark.asyncio
async def test_counter_does_not_increment_for_an_already_clean_schema() -> None:
    counter = LiteLLMCallCounter(cap=10)

    async def stub(**_: Any) -> SimpleNamespace:
        return _text_response()

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_notes",
                "description": "fetch notes",
                "parameters": _clean_schema(),
            },
        }
    ]
    with llm_scope(counter=counter):
        await litellm_tool_call_async(
            model="gemini/gemini-1.5-pro",
            messages=[{"role": "user", "content": "hi"}],
            tools=tools,
            completion_fn=stub,
        )
    assert counter.tool_schema_sanitised == 0


@pytest.mark.asyncio
async def test_counter_does_not_increment_for_permissive_dialect() -> None:
    counter = LiteLLMCallCounter(cap=10)

    async def stub(**_: Any) -> SimpleNamespace:
        return _text_response()

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_notes",
                "description": "fetch notes",
                "parameters": _schema_with_ref(),
            },
        }
    ]
    with llm_scope(counter=counter):
        await litellm_tool_call_async(
            model="anthropic/claude-haiku-4-5",
            messages=[{"role": "user", "content": "hi"}],
            tools=tools,
            completion_fn=stub,
        )
    assert counter.tool_schema_sanitised == 0
