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
``ScanEngine`` in PR 6 will wrap the whole run; individual calls increment via
the active context). If no context is active, calls still execute — useful for
ad-hoc tests — but no budget enforcement happens.
"""

from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import litellm

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


def _parse_or_fallback(
    text: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
) -> dict[str, Any]:
    """Strict JSON parse then ``expected_keys`` check; fall back on either failure."""
    expected = set(expected_keys)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.info("%s: LLM returned non-JSON; using fallback", caller)
        return dict(fallback)
    if not isinstance(parsed, dict):
        logger.info("%s: LLM JSON was not an object; using fallback", caller)
        return dict(fallback)
    if not expected.issubset(parsed):
        logger.info(
            "%s: LLM JSON missing required keys (%s); using fallback",
            caller,
            sorted(expected - parsed.keys()),
        )
        return dict(fallback)
    return parsed


def litellm_json_call(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: Callable[..., Any] | None = None,
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
    try:
        response = fn(model=model, messages=messages)
    except Exception:
        logger.exception("%s: LiteLLM completion raised", caller)
        _mark_failure()
        return dict(fallback)
    _mark_success()
    text = _extract_text(response)
    return _parse_or_fallback(text, expected_keys, fallback, caller)


async def litellm_json_call_async(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Async sibling of ``litellm_json_call`` using ``litellm.acompletion``."""
    _bump(caller)
    fn = completion_fn or litellm.acompletion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        response = await fn(model=model, messages=messages)
    except Exception:
        logger.exception("%s: LiteLLM acompletion raised", caller)
        _mark_failure()
        return dict(fallback)
    _mark_success()
    text = _extract_text(response)
    return _parse_or_fallback(text, expected_keys, fallback, caller)
