"""Dialect-aware tool-schema normalisation (T15/H4).

MCP servers emit whatever their SDK generates for tool ``inputSchema`` --
commonly ``pydantic.BaseModel.model_json_schema()`` output, which includes
``$defs``/``$ref`` (nested models pulled into a references section), ``anyOf``
(any ``Optional[X]``/``X | None`` field), ``const`` (a single-value
``Literal[...]``), and ``additionalProperties``. OpenAI's and Anthropic's
tool-calling APIs tolerate all of this -- they either understand it natively
or silently ignore what they don't. Gemini/Vertex AI and Bedrock Converse's
function-calling APIs are built on a cut-down OpenAPI-style subset of JSON
Schema and REJECT or MANGLE requests containing these features (a real,
documented interop gap between providers' function-calling implementations
and the full JSON Schema spec -- not a Mylonite bug to work around case by
case).

This module is the fix: :func:`dialect_for` maps a resolved
:class:`~mylonite.scan.model_ref.ModelRef` to the dialect its provider needs,
and :func:`sanitise_tool_schema` normalises one tool's JSON Schema for that
dialect. Wired into the ONE place a tool schema is ever sent to an LLM for
tool-calling: ``scan._llm.litellm_tool_call_async`` (the planner's chokepoint,
see T14). It is deliberately NOT wired into the adapter/``TargetDescriptor``
layer -- attack modules must keep reasoning over the target's REAL tool
surface, unsanitised, or they'd be planning attacks against a fiction.

Both public functions are PURE (no I/O, no logging side effects visible to a
caller, never mutate an input in place) and TOTAL (:func:`sanitise_tool_schema`
never raises -- a malformed-but-JSON-shaped schema degrades to a safe
fallback rather than crashing a scan over a provider's schema quirk).
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from mylonite.scan.model_ref import ModelRef

logger = logging.getLogger(__name__)


class SchemaDialect(Enum):
    """Which JSON Schema feature subset a provider's tool-calling API accepts.

    ``PERMISSIVE`` -- the provider tolerates the full JSON Schema feature set
    used by ``$ref``/``$defs``/``anyOf``/``const``/``additionalProperties``
    (OpenAI, Anthropic). ``sanitise_tool_schema`` is a no-op under this
    dialect.

    ``STRICT`` -- the provider needs a cut-down subset: references inlined,
    ``anyOf`` flattened, ``const`` expressed as a single-value ``enum``, and
    ``additionalProperties`` dropped (Gemini, Vertex AI, Bedrock Converse).
    """

    PERMISSIVE = "permissive"
    STRICT = "strict"


#: Providers whose function-calling API needs :data:`SchemaDialect.STRICT`.
#: Keyed on ``ModelRef.provider``'s ALREADY-NORMALISED spelling (see
#: ``scan.providers._normalise_provider`` / ``_ALIASES``) -- ``gemini`` and
#: ``vertex_ai`` both normalise to ``"google"`` before they ever reach here,
#: so this set only needs the canonical form.
_STRICT_PROVIDERS: frozenset[str] = frozenset({"google", "bedrock"})


def dialect_for(ref: ModelRef) -> SchemaDialect:
    """The :class:`SchemaDialect` ``ref``'s provider's tool-calling API needs.

    Known STRICT providers (Gemini/Vertex -> ``"google"``, Bedrock ->
    ``"bedrock"``) map to :data:`SchemaDialect.STRICT`. Everything else --
    including an unrecognised/undetermined provider (``ref.provider is
    None``) -- defaults to :data:`SchemaDialect.PERMISSIVE`.

    That default is a deliberate choice, not an oversight: PERMISSIVE is a
    no-op passthrough, so the worst case for a provider we guessed wrong
    about is an unmodified schema (today's status quo, and correct for the
    common case of OpenAI/Anthropic/a self-hosted/proxy model). Defaulting
    to STRICT instead would risk mangling a schema (inlining refs, dropping
    ``additionalProperties``, ...) for a provider that never needed it.
    """
    provider = (ref.provider or "").strip().lower()
    if provider in _STRICT_PROVIDERS:
        return SchemaDialect.STRICT
    return SchemaDialect.PERMISSIVE


#: Cycle/runaway-recursion guard for the STRICT sanitiser. No realistic
#: MCP tool schema nests this deep; hitting it means a ``$ref``/``anyOf``
#: chain that (accidentally or adversarially) doesn't bottom out, and the
#: safe move is to degrade the offending node rather than recurse forever.
_MAX_DEPTH = 30


def _collect_defs(schema: dict[str, Any]) -> dict[str, Any]:
    """Local reference targets from ``$defs``/``definitions``, filtered to
    dict-shaped entries (a malformed entry is simply not resolvable)."""
    defs: dict[str, Any] = {}
    for key in ("$defs", "definitions"):
        raw = schema.get(key)
        if isinstance(raw, dict):
            for name, value in raw.items():
                if isinstance(value, dict):
                    defs[name] = value
    return defs


def _resolve_ref(ref: Any, defs: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve a LOCAL ``#/$defs/Name`` or ``#/definitions/Name`` pointer.

    Only local, single-level pointers are supported -- the only shape
    pydantic's ``model_json_schema()`` (and every MCP SDK schema generator
    Mylonite has observed) actually emits. Anything else (an external URI, a
    JSON Pointer into a nested path, a non-string ``$ref``) resolves to
    ``None`` and the caller falls back to a safe generic schema rather than
    guessing.
    """
    if not isinstance(ref, str):
        return None
    for prefix in ("#/$defs/", "#/definitions/"):
        if ref.startswith(prefix):
            resolved = defs.get(ref[len(prefix) :])
            if isinstance(resolved, dict):
                return resolved
    return None


#: What an unresolvable node (a dangling ref, an exhausted anyOf, a
#: depth/cycle bailout) degrades to. ``string`` is the most universally
#: accepted JSON Schema type across every provider's function-calling
#: subset -- a permissive fallback that keeps the surrounding tool call
#: syntactically valid at the cost of losing that one field's precise shape.
_FALLBACK_NODE: dict[str, Any] = {"type": "string"}


def _json_type_of(value: Any) -> str | None:
    """The JSON Schema ``type`` name for a Python-native ``const``/``enum``
    value, or ``None`` if it doesn't map cleanly (e.g. a heterogeneous
    structure) -- used only to backfill a missing ``type`` alongside a
    ``const``-turned-``enum``, never to override one the schema already set.

    ``bool`` is checked before ``int`` deliberately: ``bool`` is a subclass
    of ``int`` in Python, so ``isinstance(True, int)`` is also true and would
    misclassify a boolean const as ``"integer"`` if checked in the other
    order.
    """
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return None


def _sanitise_any_of(
    node: dict[str, Any],
    any_of: list[Any],
    defs: dict[str, Any],
    depth: int,
    seen: frozenset[str],
) -> dict[str, Any]:
    """Flatten a top-level ``anyOf`` into a single schema.

    Tradeoff (documented, deliberate): this picks the first non-``null``
    branch's shape (after recursively sanitising it) and merges it under the
    ``anyOf`` node's own sibling keys -- which correctly handles the
    overwhelmingly common MCP case, ``Optional[X]`` compiling to
    ``anyOf: [X, {"type": "null"}]``. A genuine multi-type union
    (``str | int``) loses precision: only the first non-null branch survives.
    STRICT-dialect providers generally can't express a true union in their
    tool-parameter schema anyway (this is exactly the gap this module exists
    to paper over), so "pick one clean branch" is a better failure mode than
    either dropping the parameter or forwarding an ``anyOf`` the provider
    will reject outright.
    """
    branches = [b for b in any_of if isinstance(b, dict)]
    sanitised_branches = [_sanitise_node(b, defs, depth=depth + 1, seen=seen) for b in branches]
    non_null = [b for b in sanitised_branches if isinstance(b, dict) and b.get("type") != "null"]
    chosen: dict[str, Any]
    if non_null:
        chosen = non_null[0]
    elif sanitised_branches and isinstance(sanitised_branches[0], dict):
        chosen = sanitised_branches[0]
    else:
        chosen = _FALLBACK_NODE
    out = dict(node)
    del out["anyOf"]
    # The anyOf node's own explicit keys (e.g. a "description" written next
    # to the anyOf) win over the chosen branch's; the branch only fills gaps.
    for key, value in chosen.items():
        out.setdefault(key, value)
    return out


def _sanitise_node(node: Any, defs: dict[str, Any], *, depth: int, seen: frozenset[str]) -> Any:
    """Recursively sanitise one JSON Schema node for STRICT. Total: any
    unexpected shape degrades to :data:`_FALLBACK_NODE` rather than raising
    (the type-narrowing below is deliberately defensive, not load-bearing
    for the happy path)."""
    if depth > _MAX_DEPTH:
        return dict(_FALLBACK_NODE)
    if isinstance(node, list):
        return [_sanitise_node(item, defs, depth=depth + 1, seen=seen) for item in node]
    if not isinstance(node, dict):
        return node

    out = dict(node)  # never mutate the caller's dict

    ref = out.get("$ref")
    if ref is not None:
        if not isinstance(ref, str) or ref in seen:
            return dict(_FALLBACK_NODE)  # dangling/non-string ref or a cycle
        resolved = _resolve_ref(ref, defs)
        if resolved is None:
            return dict(_FALLBACK_NODE)
        inlined = _sanitise_node(resolved, defs, depth=depth + 1, seen=seen | {ref})
        merged = dict(inlined) if isinstance(inlined, dict) else dict(_FALLBACK_NODE)
        for key, value in out.items():
            if key != "$ref":
                merged[key] = value  # sibling keys (e.g. description) win
        out = merged

    out.pop("$defs", None)
    out.pop("definitions", None)

    any_of = out.get("anyOf")
    if isinstance(any_of, list) and any_of:
        out = _sanitise_any_of(out, any_of, defs, depth, seen)
    elif "anyOf" in out:
        # anyOf present but empty/malformed -- drop it rather than forward
        # something a STRICT provider will reject.
        out.pop("anyOf", None)

    if "const" in out:
        const_value = out.pop("const")
        out["enum"] = [const_value]
        # pydantic's model_json_schema() emits a bare {"const": ...} for a
        # single-value Literal[...] field -- NO "type" key at all, since the
        # const value alone is unambiguous to a full-JSON-Schema reader. A
        # STRICT provider's OpenAPI-derived schema parser generally expects
        # every property to carry an explicit "type", so infer one from the
        # const value's own JSON type when the node doesn't already have one.
        if "type" not in out:
            inferred = _json_type_of(const_value)
            if inferred is not None:
                out["type"] = inferred

    out.pop("additionalProperties", None)

    properties = out.get("properties")
    if isinstance(properties, dict):
        out["properties"] = {
            key: _sanitise_node(value, defs, depth=depth + 1, seen=seen)
            for key, value in properties.items()
        }

    items = out.get("items")
    if isinstance(items, (dict, list)):
        out["items"] = _sanitise_node(items, defs, depth=depth + 1, seen=seen)

    return out


def sanitise_tool_schema(schema: dict[str, Any], dialect: SchemaDialect) -> dict[str, Any]:
    """Normalise one tool's JSON Schema for ``dialect``.

    PURE (never mutates ``schema``) and TOTAL (never raises -- any
    unexpected shape or internal error degrades to returning ``schema``
    itself unchanged, which is always at least what today's un-sanitised
    behaviour already sends).

    Under :data:`SchemaDialect.PERMISSIVE` this is a no-op passthrough.

    Under :data:`SchemaDialect.STRICT` it: inlines ``$ref``/``$defs``
    references, flattens a top-level ``anyOf`` (see :func:`_sanitise_any_of`
    for the documented tradeoff), converts ``const`` to a single-value
    ``enum``, and drops ``additionalProperties`` entirely (Gemini/Vertex's
    OpenAPI-derived schema parser does not accept that keyword at all;
    omitting it is always safe since JSON Schema's own default is
    permissive).
    """
    if not isinstance(schema, dict):
        # Total: a caller handing this something schema-shaped-but-not-a-dict
        # (a stray None/str from a misbehaving upstream) must not crash the
        # scan. There's nothing sane to sanitise, so hand back an empty dict
        # rather than the non-dict input the type signature promises callers
        # will never see anyway.
        return {}
    if dialect is SchemaDialect.PERMISSIVE:
        return schema
    try:
        defs = _collect_defs(schema)
        result = _sanitise_node(schema, defs, depth=0, seen=frozenset())
        return result if isinstance(result, dict) else dict(schema)
    except Exception:
        logger.debug(
            "sanitise_tool_schema: STRICT sanitisation raised unexpectedly; "
            "returning the original schema unchanged",
            exc_info=True,
        )
        return schema
