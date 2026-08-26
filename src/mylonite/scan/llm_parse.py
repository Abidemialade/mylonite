"""Model-output -> typed-value narrowing: the step where nondeterministic model
text becomes a deterministic value the oracle can act on.

Extracted from ``mylonite.scan._llm`` so this parsing layer can be tested,
reused and reasoned about without a live-call code path. ``_llm``'s transport
entry points and ``_parse_or_fallback`` orchestrator import from here; the
planner (``scan.llm_planner``) imports :func:`_try_repair` here too, rather than
reaching into the private ``_llm`` module.

The functions keep their leading-underscore names (they are internal to the
``scan`` package), but they are now a coherent, independently-importable unit --
see ``tests/scan/test_llm_parse.py``, which exercises them directly.
"""

from __future__ import annotations

import json
import re
from typing import Any

from json_repair import repair_json


def _extract_text(response: Any) -> str:
    """Pull the text out of a LiteLLM completion response.

    LiteLLM normalises providers but the response object is
    ``OpenAI`-shaped: ``response.choices[0].message.content``.
    """
    try:
        return str(response.choices[0].message.content)
    except (AttributeError, IndexError, TypeError):
        return ""


def _first_balanced_object(text: str) -> str | None:
    """Return the first balanced ``{...}`` span in ``text``, or ``None``.

    Brace depth is tracked with awareness of JSON string literals so that
    braces *inside* a string value (``{"reason": "use } carefully"}``) do not
    miscount. This is what makes extraction robust to surrounding prose and to
    code fences (the leading ```` ```json ```` and trailing ```` ``` ```` are
    simply skipped over before/after the object).
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _extract_json_object(text: str) -> str | None:
    """Best-effort extraction of a single JSON object from LLM output.

    Current Anthropic models wrap structured output in ```` ```json ````
    fences and sometimes add surrounding prose; a bare ``json.loads`` fails on
    all of that. We strip an optional surrounding fence, then return the first
    balanced ``{...}`` span. Returns ``None`` if no object is present.
    """
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.startswith("```"):
        # Drop the opening fence (optional language tag) and any closing fence.
        stripped = re.sub(r"^```[A-Za-z0-9_-]*[ \t]*\r?\n?", "", stripped, count=1)
        stripped = re.sub(r"\r?\n?[ \t]*```\s*$", "", stripped, count=1).strip()
    return _first_balanced_object(stripped)


def _tool_call_arguments(response: Any) -> str | None:
    """Return JSON from the first tool call's ``arguments``, if present.

    Several providers implement "JSON mode" by returning the object as a tool
    call (``message.content`` empty, the JSON in
    ``message.tool_calls[0].function.arguments``) rather than as text. The
    judge/customiser want that JSON too, so we look here when ``content`` has
    no usable object. Every access is ``getattr``-guarded so the content-only
    test stubs (no ``tool_calls`` attribute) fall straight through.
    """
    try:
        message = response.choices[0].message
    except (AttributeError, IndexError, TypeError):
        return None
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        return None
    try:
        args = tool_calls[0].function.arguments
    except (AttributeError, IndexError, TypeError):
        return None
    if isinstance(args, str) and args.strip():
        return args
    if isinstance(args, dict):  # some providers hand back a dict already
        try:
            return json.dumps(args)
        except (TypeError, ValueError):  # non-serialisable values → treat as no candidate
            return None
    return None


def _raw_json_text(response: Any) -> str:
    """The text to extract JSON from: ``content`` if it has an object, else tool-call args.

    Unifies the content path and the JSON-in-tool_call path so BOTH flow through
    the same balanced-object extraction and truncation check below — crucial so a
    truncated tool-call argument is never handed to json-repair.
    """
    content = _extract_text(response)
    if "{" in content:
        return content
    return _tool_call_arguments(response) or content


def _extract_json_candidate(response: Any) -> str | None:
    """Best-effort balanced JSON object from a response (content or tool call).

    Returns ``None`` when no balanced ``{...}`` is recoverable — including the
    truncated case, from either source (see ``_looks_truncated``).
    """
    return _extract_json_object(_raw_json_text(response))


def _looks_truncated(response: Any) -> bool:
    """True when the JSON-bearing text opened a ``{`` that never closed.

    Checks whichever source carried the JSON (content OR tool call), so the
    fallback detail is honest and we never hand truncated text to ``json-repair``
    (which would fabricate the missing close and a plausible-but-wrong value).
    """
    text = _raw_json_text(response)
    return "{" in text and _first_balanced_object(text) is None


def _try_repair(candidate: str) -> Any | None:
    """Rescue near-miss non-strict JSON (trailing commas, single quotes, Python
    ``True``/``False``, unquoted keys) with ``json-repair``.

    Used only AFTER strict ``json.loads`` fails. **Refuses to repair an
    unbalanced/truncated candidate** — json-repair would fabricate the missing
    close and a plausible-but-wrong value, which (passing ``expected_keys``)
    could silently corrupt a verdict. This guard also protects the planner's
    raw-tool-argument repair path. Returns the parsed object, or ``None``.
    """
    if _first_balanced_object(candidate) is None:
        return None
    try:
        result = repair_json(candidate, return_objects=True)
    except Exception:
        return None
    if result is None or result == "":
        return None
    return result
