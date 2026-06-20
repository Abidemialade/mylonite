"""LiteLLM call helper + process-wide call counter.

Closes the two issues the eng review surfaced:

* **A1 — budget leak.** Every LLM call in the scan loop (customiser, judge,
  in-process planner) routes through ``litellm_json_call`` /
  ``litellm_json_call_async``. The wrapper increments a single
  ``LiteLLMCallCounter`` so ``--max-llm-calls`` is a real cap, not just a
  count of orchestration calls.
* **C1 — DRY.** Customiser and Judge both did "LiteLLM call → expect JSON →
  ``try/except`` parse → fallback." Folded here into one helper with a sync
  and an async entry point.

The counter is a context manager so callers can nest scopes (the
``ScanEngine`` wraps the whole run; individual calls increment via
the active context). If no context is active, calls still execute — useful for
ad-hoc tests — but no budget enforcement happens.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final

import litellm
from json_repair import repair_json
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class BudgetExceededError(RuntimeError):
    """Raised when an LLM call would push the active counter over its cap."""


@dataclass
class LiteLLMCallCounter:
    """Process-wide LLM-call counter, scoped via ``contextvars``.

    Construct one per scan; activate via ``with counter.active(): ...``. Every
    call to ``litellm_json_call`` / ``litellm_json_call_async`` inside that
    scope increments the counter and raises ``BudgetExceededError`` once the
    cap is hit.
    """

    cap: int
    count: int = 0
    consecutive_failures: int = 0
    by_caller: dict[str, int] = field(default_factory=dict)

    def record(self, caller: str) -> None:
        if self.count + 1 > self.cap:
            msg = (
                f"--max-llm-calls budget of {self.cap} exhausted "
                f"(by caller breakdown: {self.by_caller})"
            )
            raise BudgetExceededError(msg)
        self.count += 1
        self.by_caller[caller] = self.by_caller.get(caller, 0) + 1

    def mark_success(self) -> None:
        self.consecutive_failures = 0

    def mark_failure(self) -> None:
        self.consecutive_failures += 1

    @contextmanager
    def active(self) -> Iterator[None]:
        token = _ACTIVE_COUNTER.set(self)
        try:
            yield
        finally:
            _ACTIVE_COUNTER.reset(token)


_ACTIVE_COUNTER: contextvars.ContextVar[LiteLLMCallCounter | None] = contextvars.ContextVar(
    "mylonite_active_call_counter", default=None
)


def active_counter() -> LiteLLMCallCounter | None:
    """Return the currently-active counter (or ``None`` if no scope is active)."""
    return _ACTIVE_COUNTER.get()


def _bump(caller: str) -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.record(caller)


def _mark_success() -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.mark_success()


def _mark_failure() -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.mark_failure()


def _extract_text(response: Any) -> str:
    """Pull the text out of a LiteLLM completion response.

    LiteLLM normalises providers but the response object is
    ``OpenAI`-shaped: ``response.choices[0].message.content``.
    """
    try:
        return str(response.choices[0].message.content)
    except (AttributeError, IndexError, TypeError):
        return ""


# Reserved, collision-proof keys stamped onto a returned fallback dict so the
# caller (judge/customiser) can distinguish *why* it got a fallback. The
# ``_mylonite_`` prefix guarantees no clash with any ``expected_keys``
# (``body`` / ``success`` / ``confidence`` / ``reason``). Callers MUST
# ``pop_fallback_cause`` so the sentinels never leak into a verdict or payload.
_FALLBACK_CAUSE_KEY: Final = "_mylonite_fallback_cause"
_FALLBACK_DETAIL_KEY: Final = "_mylonite_fallback_detail"

#: Fallback because the LiteLLM call itself raised (network / auth / TLS).
FALLBACK_CALL_RAISED: Final = "call_raised"
#: Fallback because the call returned but its text was not usable JSON.
FALLBACK_UNPARSEABLE: Final = "unparseable_output"


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


def _snippet(text: str, limit: int = 160) -> str:
    """A short single-line excerpt of raw model output for diagnostics."""
    return " ".join(text.split())[:limit]


def _exc_detail(exc: BaseException, limit: int = 200) -> str:
    """A short ``Type: message`` rendering of an exception for the verdict reason."""
    return f"{type(exc).__name__}: {exc}"[:limit]


def _with_cause(fallback: Mapping[str, Any], cause: str, detail: str) -> dict[str, Any]:
    """Return a copy of ``fallback`` stamped with the fallback-cause sentinels."""
    out = dict(fallback)
    out[_FALLBACK_CAUSE_KEY] = cause
    out[_FALLBACK_DETAIL_KEY] = detail
    return out


def pop_fallback_cause(result: dict[str, Any]) -> tuple[str | None, str | None]:
    """Remove and return ``(cause, detail)`` from a helper result.

    Returns ``(None, None)`` for a genuinely-parsed result. Callers should
    always call this so the reserved sentinel keys never reach a ``Verdict``,
    a ``Payload.metadata``, or downstream ``expected_keys`` validation.
    """
    cause = result.pop(_FALLBACK_CAUSE_KEY, None)
    detail = result.pop(_FALLBACK_DETAIL_KEY, None)
    return cause, detail


def _parse_or_fallback(
    response: Any,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
) -> dict[str, Any]:
    """Provider-tolerant JSON parse of a completion response; fall back on failure.

    Robust across LLMs: reads JSON from ``message.content`` (handling code
    fences + surrounding prose) OR a tool call's ``arguments``; parses strict
    JSON first, then rescues near-miss non-strict JSON with ``json-repair``;
    rejects truncated output rather than letting repair fabricate values. On any
    output-side failure the returned dict carries the ``FALLBACK_UNPARSEABLE``
    cause sentinel (see ``pop_fallback_cause``).
    """
    expected = set(expected_keys)
    raw = _extract_text(response)
    candidate = _extract_json_candidate(response)
    if candidate is None:
        if _looks_truncated(response):
            detail = "looks truncated: unbalanced '{' (provider likely hit a token limit)"
            logger.info("%s: LLM JSON looks truncated; using fallback", caller)
        else:
            detail = _snippet(raw)
            logger.info("%s: LLM returned no JSON object; using fallback", caller)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, detail)
    try:
        parsed: Any = json.loads(candidate)
    except json.JSONDecodeError:
        # Strict parse failed — try a repair pass for non-strict JSON. The
        # candidate is brace-balanced (truncation was handled above), so repair
        # rescues formatting near-misses without fabricating a missing close.
        parsed = _try_repair(candidate)
        if parsed is None:
            logger.info("%s: LLM JSON did not parse (repair failed); using fallback", caller)
            return _with_cause(fallback, FALLBACK_UNPARSEABLE, _snippet(raw))
        logger.info("%s: LLM JSON rescued by json-repair (non-strict output)", caller)
    if not isinstance(parsed, dict):
        logger.info("%s: LLM JSON was not an object; using fallback", caller)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, _snippet(raw))
    if not expected.issubset(parsed):
        missing = sorted(expected - parsed.keys())
        logger.info("%s: LLM JSON missing required keys (%s); using fallback", caller, missing)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, f"missing keys: {missing}")
    return parsed


def _supported_response_mode(model: str) -> str | None:
    """Strongest structured-output mode LiteLLM reports for ``model``, or ``None``.

    Every introspection call is guarded: an unknown/custom/proxy model (or a
    renamed LiteLLM helper in a future version) degrades to ``None`` — prose-only
    — never an error. The prompt already asks for JSON, and the tolerant parser
    still runs, so degrading is safe.
    """
    try:
        if litellm.supports_response_schema(model=model):
            return "json_schema"
    except Exception:
        pass
    try:
        params = litellm.get_supported_openai_params(model=model) or []
        if "response_format" in params:
            return "json_object"
    except Exception:
        pass
    return None


def build_response_format(model: str, schema_model: type[BaseModel] | None) -> Any | None:
    """Pick the strongest supported ``response_format`` for ``model``.

    Returns the Pydantic class for json_schema (LiteLLM translates it per
    provider, including Anthropic's tool-mode emulation), ``{"type":
    "json_object"}`` for a syntactic-JSON guarantee, or ``None`` to omit the
    parameter entirely (prose-only).
    """
    mode = _supported_response_mode(model)
    if mode == "json_schema" and schema_model is not None:
        return schema_model
    if mode in ("json_schema", "json_object"):
        return {"type": "json_object"}
    return None


def litellm_json_call(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: Callable[..., Any] | None = None,
    schema_model: type[BaseModel] | None = None,
) -> dict[str, Any]:
    """Sync wrapper around ``litellm.completion`` that returns parsed JSON.

    On any exception from LiteLLM or any parse failure, returns ``fallback``.
    Increments the active call counter; raises ``BudgetExceededError`` if the
    cap is hit before the call is made.

    ``completion_fn`` exists for tests — pass a stub instead of patching the
    module. Defaults to ``litellm.completion``.
    """
    _bump(caller)
    fn = completion_fn or litellm.completion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    call_kwargs: dict[str, Any] = {"model": model, "messages": messages}
    response_format = build_response_format(model, schema_model)
    if response_format is not None:
        call_kwargs["response_format"] = response_format
    try:
        response = fn(**call_kwargs)
    except Exception as exc:
        logger.exception("%s: LiteLLM completion raised", caller)
        _mark_failure()
        return _with_cause(fallback, FALLBACK_CALL_RAISED, _exc_detail(exc))
    _mark_success()
    return _parse_or_fallback(response, expected_keys, fallback, caller)


async def litellm_json_call_async(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: Callable[..., Any] | None = None,
    schema_model: type[BaseModel] | None = None,
) -> dict[str, Any]:
    """Async sibling of ``litellm_json_call`` using ``litellm.acompletion``."""
    _bump(caller)
    fn = completion_fn or litellm.acompletion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    call_kwargs: dict[str, Any] = {"model": model, "messages": messages}
    response_format = build_response_format(model, schema_model)
    if response_format is not None:
        call_kwargs["response_format"] = response_format
    try:
        response = await fn(**call_kwargs)
    except Exception as exc:
        logger.exception("%s: LiteLLM acompletion raised", caller)
        _mark_failure()
        return _with_cause(fallback, FALLBACK_CALL_RAISED, _exc_detail(exc))
    _mark_success()
    return _parse_or_fallback(response, expected_keys, fallback, caller)
