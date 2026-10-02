"""Canonical tool-surface signature for the mid-session rug-pull check.

The adapter lists the tools when the planner starts, lists them again after it
finishes, and compares the two. A change to ANY field a server sends for a tool
can change what the agent does with it: an added parameter, a widened enum, a
flipped ``destructiveHint``, a new ``outputSchema``. So every field is signed,
not just the description.

The recipe (form ``v2``) is documented so anyone can recompute a digest:

* the tool as the server sent it, every top-level key, explicit ``null`` kept
  distinct from an absent key;
* object keys sorted; ``required`` and ``enum`` arrays compared as sets;
* ``$ref`` kept as literal text and never dereferenced;
* tools keyed by name, so listing order does not matter;
* ``sha256`` over compact JSON, prefixed ``v2:sha256:``.

The diff names each changed field as a JSON pointer (RFC 6901), for example
``/send_note/annotations/destructiveHint``. It never carries field values, so
injected text in a description or title is not repeated in the evidence; a
changed description is shown only as a digest and a length.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from mylonite.scan.llm_types import ToolDescription

#: The form version stamped on every digest and on the response metadata. A
#: comparison without it is not read as a stable surface.
SURFACE_FORM = "v2"

#: The wire fields of an MCP ``Tool`` this module knows about (wire names). Any
#: other top-level key a server sends is signed too, so an SDK upgrade or a
#: vendor extension cannot silently fall outside the signature. A test pins this
#: list against the installed SDK so a new field gets a deliberate review.
RECOGNISED_TOOL_FIELDS: tuple[str, ...] = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "icons",
    "execution",
    "_meta",
)

#: Array-valued keys whose order carries no meaning, compared as sets.
_SET_KEYS = frozenset({"required", "enum"})

#: Most JSON pointers listed in one diff; the rest are counted, not listed.
MAX_DIFF_PATHS = 50

#: What the stable reason says was signed, by source of the listing.
SIGNED_ALL_FIELDS = "every tool field"
SIGNED_CONVERTED_FIELDS = "name, description, input schema and annotations"


def wire_tool_dump(tool: Any) -> dict[str, Any] | None:
    """The tool exactly as the server sent it, or None if it cannot be dumped.

    ``exclude_unset`` keeps only the keys present on the wire, so an explicit
    ``null`` and an absent key stay different; ``by_alias`` restores wire names
    such as ``_meta``; unknown keys survive because the SDK model allows extras.
    """
    dump = getattr(tool, "model_dump", None)
    if not callable(dump):
        return None
    try:
        out = dump(mode="json", by_alias=True, exclude_unset=True)
    except Exception:
        return None
    return out if isinstance(out, dict) else None


def _strip_none(value: object) -> object:
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    return value


def tool_view(tool: ToolDescription) -> dict[str, Any]:
    """The full-fidelity view of one tool AFTER the control shim.

    Starts from the wire dump the tool carries and overlays the fields the
    planner is actually given, so a control that rewrites a description (the
    guarded arm) is reflected, while every other field still comes from the
    server. A tool with no wire dump (an in-process target) signs the
    converted fields only.
    """
    view: dict[str, Any] = dict(tool.wire) if tool.wire else {}
    view["name"] = tool.name
    view["description"] = tool.description
    view["inputSchema"] = tool.input_schema
    wire_annotations = view.get("annotations")
    stripped = _strip_none(wire_annotations) if wire_annotations is not None else None
    if tool.annotations:
        if stripped != tool.annotations:
            view["annotations"] = dict(tool.annotations)
    elif stripped:
        # The server declared hints and a control removed them before the
        # planner saw the tool: sign what the planner saw.
        view.pop("annotations", None)
    return view


def canonicalise(value: object, key: str | None = None) -> object:
    """Sorted-key, set-aware canonical form of a JSON value (``$ref`` is text)."""
    if isinstance(value, dict):
        return {k: canonicalise(v, k) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [canonicalise(v) for v in value]
        if key in _SET_KEYS:
            unique = {_dumps(v): v for v in items}
            return [unique[k] for k in sorted(unique)]
        return items
    return value


def _dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def surface_views(tools: Iterable[ToolDescription], *, wire_only: bool = False) -> dict[str, Any]:
    """``{tool name: canonical view}``. ``wire_only`` signs the raw server dump
    (the below-shim view, kept as evidence) instead of the post-shim view."""
    out: dict[str, Any] = {}
    for t in tools:
        if wire_only:
            if t.wire is None:
                continue
            out[t.name] = canonicalise(t.wire)
        else:
            out[t.name] = canonicalise(tool_view(t))
    return out


def has_wire(tools: Iterable[ToolDescription]) -> bool:
    """True when every listed tool carries its wire dump (all fields signed)."""
    listed = list(tools)
    return bool(listed) and all(t.wire is not None for t in listed)


def digest(view: object) -> str:
    """The versioned digest of one canonical tool view."""
    return f"{SURFACE_FORM}:sha256:" + hashlib.sha256(_dumps(view).encode("utf-8")).hexdigest()


def _pointer(parts: Iterable[str]) -> str:
    return "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in parts)


def _changed_paths(a: object, b: object, parts: list[str], out: list[str]) -> None:
    if a == b:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(_pointer([*parts, k]))
            else:
                _changed_paths(a[k], b[k], [*parts, k], out)
        return
    out.append(_pointer(parts))


def _text_fingerprint(view: Mapping[str, Any]) -> dict[str, object]:
    text = view.get("description")
    if not isinstance(text, str):
        return {"present": False}
    return {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "length": len(text)}


def diff_surfaces(first: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any] | None:
    """Field-level diff of two canonical surfaces, or None when they match.

    Carries tool names, JSON pointers, versioned digests and, for a changed
    description, its digest and length. Never a field's value.
    """
    added = sorted(set(current) - set(first))
    removed = sorted(set(first) - set(current))
    changed = sorted(n for n in current if n in first and current[n] != first[n])
    if not (added or removed or changed):
        return None
    paths: list[str] = [_pointer([n]) for n in sorted(added + removed)]
    descriptions: dict[str, dict[str, object]] = {}
    for name in changed:
        before, after = first[name], current[name]
        _changed_paths(before, after, [name], paths)
        if (before.get("description") if isinstance(before, dict) else None) != (
            after.get("description") if isinstance(after, dict) else None
        ):
            descriptions[name] = {
                "before": _text_fingerprint(before),
                "after": _text_fingerprint(after),
            }
    paths = sorted(set(paths))
    out: dict[str, Any] = {
        "form": SURFACE_FORM,
        "added": added,
        "removed": removed,
        "changed": changed,
        "paths": paths[:MAX_DIFF_PATHS],
        "digests": {n: {"before": digest(first[n]), "after": digest(current[n])} for n in changed},
    }
    if len(paths) > MAX_DIFF_PATHS:
        out["paths_not_listed"] = len(paths) - MAX_DIFF_PATHS
    if descriptions:
        out["descriptions"] = descriptions
    return out
