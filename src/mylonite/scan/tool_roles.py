"""Heuristic tool-role classification over a target's discovered tools.

Pure, deterministic (schema + name heuristics — no LLM, no live calls). Two
consumers share this single source of truth:

* the ``mylonite scan --scaffold`` target scaffold, which seeds concrete
  ``seed_arm`` / ``effect_probe`` candidates instead of blank templates, and
* :func:`mylonite.scan.attack_loop.discover_attack_plan`, which builds an
  ``AttackPlan`` so the adaptive loop needs no hand-authored choreography.

Every assignment is a HINT — never authoritative for any verdict.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from mylonite.scan._control_primitives import sanitize_tool_description


class _ToolRoles(NamedTuple):
    """Best-guess role assignment over a target's discovered tools.

    Drives the auto-populated ``seed_arm`` / ``effect_probe`` in the
    ``scan --scaffold`` target scaffold so the operator starts from concrete
    candidates rather than blank
    templates — the single biggest custom-target onboarding friction. Every field
    is a HINT to confirm, never authoritative.
    """

    seed_arm_tool: str | None  # a tool that stores untrusted content (good seed_arm)
    seed_arm_param: str | None  # the string param of seed_arm_tool to hold {payload}
    retrieve_tool: str | None  # surfaces stored content WITHOUT needing an id (the recall path)
    verify_tool: str | None  # reports a side effect (good effect_probe verify_tool)
    sink_tools: list[str]  # consequential-action tools (W4 candidates)
    #: A ready-to-use ``args_template`` for ``seed_arm_tool`` with ``{payload}``
    #: at the content slot — nested when the slot is nested. ``None`` when no
    #: slot was found. ``seed_arm_param`` stays the TOP-LEVEL property name (so
    #: existing callers and printed hints are unchanged); this carries the full
    #: shape for the batched-record tools that a flat ``{param: "{payload}"}``
    #: cannot express.
    seed_arm_args_template: dict[str, Any] | None = None


def _words(spec: str) -> tuple[str, ...]:
    """Whitespace-split a spec string into a tuple of hint fragments."""
    return tuple(spec.split())


# Name words for the store / recall pick (not load-bearing for any verdict). Matched
# as whole words of the name (``_hints_match``), so ``post_to_thread`` is not a
# recall tool because "thread" contains "read" (#297).
_STORE_NAME_HINTS = _words(
    "save store remember add create write post append note notes record records insert "
    "put memory memories memorize memorise log"
)
_RETRIEVE_NAME_HINTS = _words(
    "recall list search history feed inbox recent browse read get find load query"
)
_OBSERVE_NAME_HINTS = _words("sent outbox history status log audit recent list feed report get")
#: Verbs that name a readback: a tool that returns what the target stores. The
#: effect_probe fallback when no tool reads like an outbox or status report.
#: Matched as whole tokens (``read_graph`` -> {"read", "graph"}). No "fetch":
#: that reads like egress, and an egress tool is a W3 target, not an observer.
#: No "open" or "query": ``open_pull_request`` and ``execute_query`` write.
_READBACK_NAME_HINTS = _words("read get list search find view show lookup")
#: Any of these tokens in a name rules a tool out as a readback, whatever its
#: annotations say. The probe calls ``verify_tool`` before and after every
#: attempt, so a write picked here would run over and over (``get_or_create_user``,
#: ``search_and_delete``, a ``delete_all`` that claims ``readOnlyHint``).
_WRITE_VERB_HINTS = _words(
    "create update write add set insert put execute run exec open delete remove send post "
    "clear reset deploy logout login signout revoke approve purge drop truncate cancel "
    "archive move rename kill stop start restart"
)
_SINK_NAME_HINTS = _words(
    "send email post publish pay transfer purchase execute "
    "delete remove dispatch share forward submit"
)
_CONTENT_PARAM_HINTS = _words(
    "body content text message note memo comment data value payload description"
)
_ID_PARAM_HINTS = _words("id key uuid handle ref index")


#: Splits any non-alphanumeric run AND a camelCase boundary into separate
#: tokens: "note_id" -> {"note", "id"}, "noteId" -> {"note", "id"}. Used by
#: ``_hints_match`` instead of a plain substring test.
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokens(name: str) -> set[str]:
    """Lowercase, camelCase/snake_case-aware tokens of a param/tool name.

    DCR-0015: matching a hint with plain ``h in name.lower()`` substring search
    false-positives whenever a name merely CONTAINS a short hint as part of a
    longer word — e.g. the 2-letter ``"id"`` hint matches inside ``"guidance"``
    or ``"valid"``; ``"key"`` matches inside ``"keyword"``. Splitting the name
    into whole tokens and requiring an EXACT token match keeps genuine cases
    (``video_id``, ``noteId``, ``api_key``) matching while rejecting those.
    """
    with_boundaries = _CAMEL_BOUNDARY_RE.sub("_", name)
    return {t for t in _TOKEN_SPLIT_RE.split(with_boundaries.lower()) if t}


def _hints_match(name: str, hints: tuple[str, ...]) -> bool:
    """True if any of ``hints`` is a whole TOKEN of ``name`` (see ``_tokens``)."""
    tokens = _tokens(name)
    return any(h in tokens for h in hints)


def _resolve_local_ref(schema: dict[str, Any], ref: str) -> dict[str, Any] | None:
    """Resolve a LOCAL JSON-Schema ``$ref`` (``#/$defs/X`` or ``#/definitions/X``)
    against this tool's own schema.

    No external/remote refs — MCP ``inputSchema`` documents are self-contained,
    and resolving anything else would mean fetching an arbitrary URI named by a
    customer's server.
    """
    if not ref.startswith("#/"):
        return None
    node: Any = schema
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _resolve_prop(schema: dict[str, Any], spec: Any, *, depth: int = 0) -> Any:
    """Follow a property's own ``$ref`` to the schema it names.

    A required param declared only as ``{"$ref": "#/$defs/Metric"}`` has no
    inline ``"type"``, so every caller that reads ``spec.get("type")`` directly
    (``_satisfiable``, ``literal_for``) saw it as typeless and either rejected a
    perfectly usable chain source or fell back to the bland default literal —
    degrading a probe back toward the unanswerable shape this module exists to
    avoid, never a false verdict, but a real loss of chain-probe coverage on any
    server whose SDK factors shared param types out into ``$defs``.
    """
    if not isinstance(spec, dict) or depth > 4:
        return spec
    ref = spec.get("$ref")
    if not isinstance(ref, str):
        return spec
    target = _resolve_local_ref(schema, ref)
    if target is None:
        return spec
    # Sibling keys (e.g. a property-level `description` alongside the `$ref`)
    # win over the resolved schema's own, so a caller adding a more specific
    # description to a shared type isn't overridden by it.
    merged = {**target, **{k: v for k, v in spec.items() if k != "$ref"}}
    return _resolve_prop(schema, merged, depth=depth + 1)


def _schema_props(tool: Any) -> dict[str, Any]:
    schema = getattr(tool, "json_schema", {}) or {}
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    props = props if isinstance(props, dict) else {}
    return {name: _resolve_prop(schema, spec) for name, spec in props.items()}


def _schema_required(tool: Any) -> list[str]:
    schema = getattr(tool, "json_schema", {}) or {}
    req = schema.get("required", []) if isinstance(schema, dict) else []
    return [str(r) for r in req] if isinstance(req, list) else []


def _is_string_param(spec: Any) -> bool:
    return isinstance(spec, dict) and spec.get("type") == "string"


def _content_param(tool: Any) -> str | None:
    """The string param of ``tool`` most likely to hold untrusted content."""
    props = _schema_props(tool)
    string_params = [name for name, spec in props.items() if _is_string_param(spec)]
    # Prefer an explicitly content-shaped name, else the first non-id string param.
    for name in string_params:
        if _hints_match(name, _CONTENT_PARAM_HINTS):
            return name
    for name in string_params:
        if not _hints_match(name, _ID_PARAM_HINTS):
            return name
    return string_params[0] if string_params else None


def _genuine_content_param(tool: Any) -> str | None:
    """The free-text content slot of ``tool``, or ``None`` if it has none.

    Stricter than :func:`_content_param`: it refuses to fall back to an
    id-shaped string param. A tool whose only string param is an id (e.g.
    ``read_note(note_id)``) is a reader, not a store — so it must NOT be picked
    as a plant target by :func:`mylonite.scan.attack_loop.discover_attack_plan`.
    """
    props = _schema_props(tool)
    string_params = [name for name, spec in props.items() if _is_string_param(spec)]
    # Reject id-shaped params first — a name like "note_id" contains an "id"
    # TOKEN (a handle, not a free-text slot); see _hints_match/DCR-0015.
    non_id = [name for name in string_params if not _hints_match(name, _ID_PARAM_HINTS)]
    for name in non_id:
        if _hints_match(name, _CONTENT_PARAM_HINTS):
            return name
    return non_id[0] if non_id else None


#: Classifier/label fields — they name or categorise a record rather than carry
#: its free text. Tried LAST as a content slot. Without this, server-memory's
#: ``{name, entityType, observations[]}`` yielded ``name`` (an entity label,
#: usually short and often echoed back verbatim) over ``observations`` (the
#: free-text body an indirect-injection payload actually needs to ride in).
_LABEL_PARAM_HINTS = _words("name type kind status state role label slug")


def _rank_content_fields(sub: dict[str, Any]) -> list[str]:
    """Object fields ordered by how likely each is to hold free text.

    1. An explicitly content-shaped NAME (``body``/``content``/``text``/…).
    2. An ARRAY-of-strings — a repeated free-text field (``observations``,
       ``contents``, ``messages``) is content by shape even when its name
       matches no hint. This is the tier that makes batched-record schemas work
       without hardcoding any particular server's vocabulary.
    3. Any other non-id, non-label field.
    4. Label/classifier fields, last — better than failing, but a poor slot.

    Id-shaped fields are excluded entirely: a handle is not a content slot.
    """

    def is_string_array(spec: Any) -> bool:
        return (
            isinstance(spec, dict)
            and spec.get("type") == "array"
            and _is_string_param(spec.get("items"))
        )

    candidates = [n for n in sub if not _hints_match(n, _ID_PARAM_HINTS)]
    tier1 = [n for n in candidates if _hints_match(n, _CONTENT_PARAM_HINTS)]
    tier2 = [n for n in candidates if n not in tier1 and is_string_array(sub[n])]
    rest = [n for n in candidates if n not in tier1 and n not in tier2]
    tier3 = [n for n in rest if not _hints_match(n, _LABEL_PARAM_HINTS)]
    tier4 = [n for n in rest if n not in tier3]
    return [*tier1, *tier2, *tier3, *tier4]


#: How deep to descend looking for a content slot. Real MCP batch-write schemas
#: nest at most `param -> items -> field` (2) or `param -> items -> field ->
#: items` (3); the cap stops a pathological/recursive schema from spinning.
_MAX_CONTENT_DEPTH = 4


def _content_slot_template(tool: Any) -> tuple[str, dict[str, Any]] | None:
    """A ready ``args_template`` with ``{payload}`` at this tool's content slot.

    Returns ``(top_level_param_name, args_template)`` or ``None``.

    ``_content_param`` only ever inspected TOP-LEVEL ``properties`` for a
    ``type == "string"``, so it was structurally blind to the batched
    array-of-records write that is a common MCP idiom — e.g. server-memory's
    ``create_entities(entities: [{name, entityType, observations: [str]}])``,
    whose only top-level property is an array. Auto-wire reported "no obvious
    content-storing tool found" for the entire class of such tools.

    This walks the schema instead, and because ``args_template`` already
    supports nested literals (docs/target-file.md: ``{payload}`` at a bare
    string leaf), the nested slot needs no new plumbing to be usable — a minimal
    envelope is synthesised around it. Objects fill only what they must: any
    sibling REQUIRED string gets a neutral placeholder so the call validates,
    while optional siblings are left out.
    """
    props = _schema_props(tool)
    if not props:
        return None
    # Prefer a flat string param when one exists — the higher-fidelity shape,
    # and what every existing target file and test already expects.
    flat = _genuine_content_param(tool)
    if flat is not None:
        return flat, {flat: "{payload}"}
    # Same ranking as nested objects, so a top-level id/label param is excluded
    # here too. Without this the fallback happily planted the payload into
    # `create_link(target_id=...)` — an id is a handle, not a content slot, the
    # exact trap `_genuine_content_param` exists to avoid.
    for top_name in _rank_content_fields(props):
        built = _build_payload_value(props[top_name], depth=0)
        if built is not None:
            return top_name, {top_name: built}
    return None


def _build_payload_value(spec: Any, *, depth: int) -> Any | None:
    """A minimal literal for ``spec`` containing ``{payload}``, or None.

    ``None`` means "no free-text slot reachable inside this subschema" — never
    an empty/placeholder value, so a caller can distinguish "nothing here" from
    "here, and it is blank".
    """
    if depth > _MAX_CONTENT_DEPTH or not isinstance(spec, dict):
        return None
    kind = spec.get("type")
    if kind == "string":
        # An id-shaped leaf is a handle, not a free-text slot (DCR-0015).
        return "{payload}"
    if kind == "array":
        inner = _build_payload_value(spec.get("items"), depth=depth + 1)
        return None if inner is None else [inner]
    if kind == "object" or "properties" in spec:
        sub = spec.get("properties")
        if not isinstance(sub, dict) or not sub:
            return None
        required = spec.get("required")
        required_names = {str(r) for r in required} if isinstance(required, list) else set()
        for field in _rank_content_fields(sub):
            built = _build_payload_value(sub[field], depth=depth + 1)
            if built is None:
                continue
            obj: dict[str, Any] = {field: built}
            # Fill sibling REQUIRED strings so the synthesised call validates.
            for other in required_names - {field}:
                if _is_string_param(sub.get(other)):
                    obj[other] = "mylonite-probe"
            return obj
    return None


def _id_param(tool: Any) -> str | None:
    """The id-shaped param name of ``tool`` (required params first).

    Unlike :func:`_content_param`, this is used by the adaptive loop, which
    MINTS the id itself and embeds it in both the plant call and the drive
    message — so a store/read pair keyed by an id is exploitable here even
    though the single-shot scaffold's ``retrieve_tool`` heuristic must skip it.
    """
    props = _schema_props(tool)
    required = set(_schema_required(tool))
    candidates = [n for n in props if _hints_match(n, _ID_PARAM_HINTS)]
    for name in candidates:
        if name in required:
            return name
    return candidates[0] if candidates else None


def _requires_id(tool: Any) -> bool:
    """True if the tool REQUIRES an id-shaped param — so it can't surface content
    without already knowing the handle (the ``save_note``/``read_note`` trap)."""
    return any(_hints_match(r, _ID_PARAM_HINTS) for r in _schema_required(tool))


def _names_a_write(name: str) -> bool:
    """True when a tool's name carries a write or sink verb as a whole token.

    Rules a tool out as an effect_probe ``verify_tool`` candidate, whatever its
    annotations claim: the probe calls it before and after every attempt.
    """
    return _hints_match(name, _SINK_NAME_HINTS) or _hints_match(name, _WRITE_VERB_HINTS)


def _readback_tool(tools: list[Any]) -> str | None:
    """A tool that reads the target's store back, as an effect_probe candidate.

    The fallback for a surface with no outbox- or status-named tool (#217's
    server-memory: ``read_graph``). A candidate is named like a read
    (:data:`_READBACK_NAME_HINTS`, whole tokens) or annotated ``readOnlyHint``,
    is not annotated as a write, has no write verb in its name
    (:data:`_SINK_NAME_HINTS`, :data:`_WRITE_VERB_HINTS`), and needs no record id (the planner never
    learns one). One that takes no required argument reads the whole store and
    is preferred; otherwise the first in listing order. A hint only: the
    scaffold writes it commented, and nothing enables it.
    """
    candidates: list[tuple[int, int, str]] = []
    for index, tool in enumerate(tools):
        name = getattr(tool, "name", "") or ""
        annotations = getattr(tool, "annotations", None) or {}
        if annotations.get("readOnlyHint") is False or annotations.get("destructiveHint"):
            continue
        if _names_a_write(name):
            continue
        read_like = annotations.get("readOnlyHint") is True or _hints_match(
            name, _READBACK_NAME_HINTS
        )
        if not name or not read_like or _requires_id(tool):
            continue
        candidates.append((1 if _schema_required(tool) else 0, index, name))
    return min(candidates)[2] if candidates else None


def _classify_tools(tools: list[Any]) -> _ToolRoles:
    """Bucket discovered tools into seed-arm / retrieve / verify / sink roles.

    Pure and deterministic (schema + name heuristics, no LLM, no live calls).
    The retrieve role deliberately requires a NO-id retrieval path: a store whose
    only readback needs the new record's id can't be exercised by the planner
    (which never learns the id), so we surface that gap instead of suggesting a
    seed_arm that will silently never deliver.
    """
    seed_arm_tool: str | None = None
    seed_arm_param: str | None = None
    seed_arm_args_template: dict[str, Any] | None = None
    retrieve_tool: str | None = None
    verify_tool: str | None = None
    sink_tools: list[str] = []

    for tool in tools:
        name = getattr(tool, "name", "") or ""
        low = name.lower()
        # Walks nested array/object schemas, not just top-level string props, so
        # a batched-record write tool is no longer invisible to auto-wire.
        slot = _content_slot_template(tool)
        if seed_arm_tool is None and slot is not None and _hints_match(name, _STORE_NAME_HINTS):
            seed_arm_tool, (seed_arm_param, seed_arm_args_template) = name, slot
        if (
            retrieve_tool is None
            and _hints_match(name, _RETRIEVE_NAME_HINTS)
            and not _requires_id(tool)
        ):
            retrieve_tool = name
        if (
            verify_tool is None
            and any(h in low for h in _OBSERVE_NAME_HINTS)
            and not _requires_id(tool)
            and not _names_a_write(name)
        ):
            verify_tool = name
        if any(h in low for h in _SINK_NAME_HINTS):
            sink_tools.append(name)

    if verify_tool is None:
        verify_tool = _readback_tool(tools)

    return _ToolRoles(
        seed_arm_tool=seed_arm_tool,
        seed_arm_param=seed_arm_param,
        retrieve_tool=retrieve_tool,
        verify_tool=verify_tool,
        sink_tools=sink_tools,
        seed_arm_args_template=seed_arm_args_template,
    )


class ReadbackChoice(NamedTuple):
    """The tool an effect_probe would read the target's state back through.

    ``tied`` says the readback is strongly tied to a consequential tool (a
    result word, or the recall of a store it writes), so a W3/W4 effect through
    that tool would show in it; only a tied readback is proposed live. A shared
    noun alone is not enough: an inbox reader (``list_emails``) shares a noun
    with a sender (``send_email``) but need not show what was sent. ``needs_args`` says the tool has required arguments the
    scaffold can only stub.
    """

    tool: str
    tied: bool
    needs_args: bool


#: Words a readback name uses for what a consequential verb produced: a
#: ``sent_log`` or ``outbox`` reports what ``send_email`` sent. Never a bare
#: noun such as ``mail``: an inbox reader (``read_mail``) lists what arrived,
#: not what was sent.
_EFFECT_WORDS_BY_VERB: dict[str, frozenset[str]] = {
    "send": frozenset({"sent", "outbox", "outgoing", "delivered", "deliveries"}),
    "email": frozenset({"sent", "outbox", "outgoing"}),
    "post": frozenset({"posted", "posts", "outbox", "published"}),
    "publish": frozenset({"published", "posts"}),
    "create": frozenset({"created"}),
    "write": frozenset({"written", "writes"}),
    "delete": frozenset({"deleted", "trash"}),
    "remove": frozenset({"removed"}),
    "pay": frozenset({"payments", "paid", "transactions"}),
    "transfer": frozenset({"transfers", "transactions"}),
    "fetch": frozenset({"fetched", "requests", "fetches"}),
    "dispatch": frozenset({"dispatched", "dispatches"}),
}
#: Tokens that never tie two tools (generic verbs and filler).
_TIE_STOPWORDS = frozenset(
    {*_READBACK_NAME_HINTS, *_WRITE_VERB_HINTS, *_SINK_NAME_HINTS, *_OBSERVE_NAME_HINTS}
    | {"all", "my", "the", "a", "an", "by", "to", "of", "for", "new", "item", "items"}
)


def _stem(token: str) -> str:
    return token[:-1] if len(token) > 3 and token.endswith("s") else token


#: Tie strengths, strongest first. Only ``_TIE_LIVE`` and above is "tied".
_TIE_RESULT_WORD = 3  # the readback names the verb's result: sent_log for send_email
_TIE_STORE_RECALL = 2  # the id-free recall of a store a consequential tool writes
_TIE_LIVE = _TIE_STORE_RECALL
_TIE_SHARED_NOUN = 1  # a shared noun only: list_messages for send_message


def _tie_strength(readback: str, consequential: str) -> int:
    """How strongly a readback's name ties it to a consequential tool:
    ``_TIE_RESULT_WORD`` when it names what the tool's verb produced,
    ``_TIE_SHARED_NOUN`` when the two only share a noun, 0 otherwise."""
    r_tokens = _tokens(readback)
    c_tokens = _tokens(consequential)
    effect_words = set().union(*(_EFFECT_WORDS_BY_VERB.get(t, frozenset()) for t in c_tokens))
    if r_tokens & effect_words:
        return _TIE_RESULT_WORD
    r_nouns = {_stem(t) for t in r_tokens - _TIE_STOPWORDS}
    c_nouns = {_stem(t) for t in c_tokens - _TIE_STOPWORDS}
    return _TIE_SHARED_NOUN if r_nouns & c_nouns else 0


def _is_safe_readback(tool: Any, consequential: set[str]) -> bool:
    """The strict rules a tool must pass before the scan may call it before
    and after every attempt: no write or destructive annotation, not
    consequential, no write verb in its name, a whole-word read name (or a
    ``readOnlyHint``), and no record id it would need to know."""
    name = getattr(tool, "name", "") or ""
    annotations = getattr(tool, "annotations", None) or {}
    if not name or name in consequential:
        return False
    if annotations.get("readOnlyHint") is False or annotations.get("destructiveHint"):
        return False
    if _names_a_write(name) or _requires_id(tool):
        return False
    return annotations.get("readOnlyHint") is True or _hints_match(
        name, _OBSERVE_NAME_HINTS + _READBACK_NAME_HINTS
    )


def effect_readback(tools: list[Any]) -> ReadbackChoice | None:
    """The readback an effect_probe should use, or ``None`` when no tool is safe.

    The single detector shared by ``scan --scaffold`` (which writes a probe
    live only on a tied readback that needs no arguments) and the scan's
    effect-unconfirmable message, so the two agree. A candidate must pass
    :func:`_is_safe_readback`. Among those, the strongest tie to a
    consequential tool wins over listing order: a result word (``sent_log`` or
    ``outbox`` for ``send_email``), then the id-free recall of a store that a
    consequential tool writes (``read_graph`` for ``create_entities``), then a
    shared noun only (``list_messages`` for ``send_message``), which never
    counts as tied. Then a tool with no required argument wins.
    """
    from mylonite.scan.control_shim import consequential_tool_names

    consequential = {name for name, _reason in consequential_tool_names(tools)}
    roles = _classify_tools(tools)
    store_pair_recall = (
        roles.retrieve_tool
        if roles.seed_arm_tool is not None and roles.seed_arm_tool in consequential
        else None
    )
    ranked: list[tuple[int, int, int, str, bool]] = []
    for index, tool in enumerate(tools):
        if not _is_safe_readback(tool, consequential):
            continue
        name = getattr(tool, "name", "") or ""
        tie = max((_tie_strength(name, c) for c in consequential), default=0)
        if name == store_pair_recall:
            tie = max(tie, _TIE_STORE_RECALL)
        needs_args = bool(_schema_required(tool))
        ranked.append((-tie, 1 if needs_args else 0, index, name, needs_args))
    if not ranked:
        return None
    neg_tie, _args, _index, name, needs_args = min(ranked)
    return ReadbackChoice(tool=name, tied=-neg_tie >= _TIE_LIVE, needs_args=needs_args)


# --- delivery-channel detectors (v0.7.x) -------------------------------------
# These widen Mylonite beyond the kitchen-sink store->recall shape so seeds can
# be delivered through the channels a REAL target actually exposes:
#   * direct_content  — a tool that processes attacker-supplied free text
#                       (process_document/summarize/analyze): the payload rides
#                       in as that argument; no plant, no recall.
#   * tool_description — an existing tool whose OWN description carries an
#                        instruction aimed at the agent (tool poisoning): no
#                        delivery needed; drive the planner to use the tool.

#: Tool-name fragments that denote "processes free-text content the user supplies"
#: (as opposed to STORING it). Drives the direct_content channel.
_PROCESSOR_NAME_HINTS = _words(
    "process summarize summarise analyze analyse answer translate review ingest "
    "parse classify extract explain read scan check evaluate respond chat ask query"
)

#: Imperative-prose patterns that signal a tool description is steering the agent
#: (plain-prose tool poisoning — the gap sanitize_tool_description documents).
_INSTRUCTION_PROSE = re.compile(
    r"\b("
    r"you must|you should|you need to|always |never |before (you|responding|answering)|"
    r"after (you|reading|calling)|first .{0,40}\bthen\b|do not (mention|tell|reveal)|"
    r"ignore (the |all |previous|prior)|disregard |as an ai|system override|"
    r"important:|note:|when (this tool|you|the user|called)|make sure to|be sure to|"
    r"in addition,? (also|you)|additionally,? (call|send|include|fetch)"
    r")",
    re.IGNORECASE,
)


def description_carries_instruction(description: str) -> str | None:
    """Return a short excerpt if a tool description appears to steer the agent.

    Catches BOTH the structured smuggle forms ``sanitize_tool_description`` strips
    (``<IMPORTANT>``/brackets/parentheticals) AND plain imperative prose aimed at
    the agent (the gap that sanitiser documents). ``None`` means the description
    reads as a normal capability description.
    """
    if not description:
        return None
    # Structured smuggle: sanitising changes the text -> a smuggle form was present.
    if sanitize_tool_description(description) != description:
        return description.strip()[:240]
    # Plain-prose steering: an imperative directed at the agent.
    m = _INSTRUCTION_PROSE.search(description)
    if m:
        # Return the sentence around the match for the judge's context.
        start = description.rfind(".", 0, m.start()) + 1
        end = description.find(".", m.end())
        end = end + 1 if end != -1 else len(description)
        return description[start:end].strip()[:240]
    return None


def instruction_bearing_tools(tools: list[Any]) -> list[tuple[str, str]]:
    """Tools whose own description steers the agent → (name, suspicious excerpt).

    The candidates for the W1 ``tool_description`` channel.
    """
    out: list[tuple[str, str]] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", "") or ""
        excerpt = description_carries_instruction(desc)
        if name and excerpt:
            out.append((name, excerpt))
    return out


def content_processor_tools(tools: list[Any]) -> list[tuple[str, str]]:
    """Tools that process attacker-suppliable free text → (name, content param).

    The candidates for the W2 ``direct_content`` channel: a tool with a genuine
    free-text content slot whose name reads as "process this content" (not store).
    """
    out: list[tuple[str, str]] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        low = name.lower()
        param = _genuine_content_param(tool)
        if not name or param is None:
            continue
        is_store = any(h in low for h in _STORE_NAME_HINTS)
        is_processor = any(h in low for h in _PROCESSOR_NAME_HINTS)
        if is_processor and not is_store:
            out.append((name, param))
    return out


def _read_by_id_tool(tools: list[Any]) -> str | None:
    """First retrieval-shaped tool that takes an id-shaped param (read-by-id).

    The adaptive loop can drive this (it knows the id it minted), so it is a
    valid retrieval path even though :func:`_classify_tools` excludes id-keyed
    readbacks from ``retrieve_tool``.
    """
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        if _hints_match(name, _RETRIEVE_NAME_HINTS) and _id_param(tool) is not None:
            return name or None
    return None


__all__ = [
    "_STORE_NAME_HINTS",
    "ReadbackChoice",
    "_ToolRoles",
    "_classify_tools",
    "_content_param",
    "_genuine_content_param",
    "_id_param",
    "_read_by_id_tool",
    "_requires_id",
    "_schema_props",
    "_schema_required",
    "effect_readback",
]
