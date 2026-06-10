"""Composable building blocks for per-target predicates.

The v0.2.2 MCP stdio adapter's bundled targets (filesystem, fetch, github)
each need predicates that inspect ``response.tool_calls`` and the
serialised MCP trace. These three primitives factor out the recurring
patterns so each per-target predicate composes them rather than reinventing
JSON parsing and sequence checks.

Naming note: ``tool_call_sequence`` (not ``sequence``) — the plain word
``sequence`` shadows ``collections.abc.Sequence`` / ``typing.Sequence`` in
import namespaces, which is the kind of footgun that bites at 3am.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any


def tool_was_called(tool_calls: Sequence[str], name: str) -> bool:
    """True iff ``name`` appears at least once in the tool-call sequence."""
    return name in tool_calls


def tool_was_called_with_arg(
    mcp_trace_blob: str,
    name: str,
    arg_name: str,
    value_predicate: Callable[[Any], bool],
) -> bool:
    """Inspect a serialised MCP trace for a call matching an arg-value test.

    ``mcp_trace_blob`` is the JSON-string form of a list of
    ``{"tool": str, "args": dict}`` entries — the shape v0.2.2 adapters
    serialise into ``response.metadata["mcp_trace_planner"]``. The function
    parses, scans for calls named ``name`` carrying ``arg_name`` in their
    args, and returns True if any of those values satisfy ``value_predicate``.

    Returns False on malformed JSON, missing fields, or zero matching calls.
    """
    try:
        trace = json.loads(mcp_trace_blob or "[]")
    except json.JSONDecodeError:
        return False
    if not isinstance(trace, list):
        return False
    for entry in trace:
        if not isinstance(entry, dict) or entry.get("tool") != name:
            continue
        args = entry.get("args", {}) or {}
        if not isinstance(args, dict):
            continue
        if arg_name in args and value_predicate(args[arg_name]):
            return True
    return False


def tool_call_sequence(tool_calls: Sequence[str], first: str, then: str) -> bool:
    """True iff ``first`` appears at an index before ``then`` in ``tool_calls``.

    Both names must be present. Used by per-target predicates to detect the
    read-then-act pattern characteristic of indirect injection (e.g.
    filesystem's ``read_file`` before ``write_file``, github's ``get_issue``
    before ``create_issue``).
    """
    if first not in tool_calls or then not in tool_calls:
        return False
    return tool_calls.index(first) < tool_calls.index(then)
