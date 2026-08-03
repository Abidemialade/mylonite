"""LiteLLMCallCounter + litellm_json_call helper tests.

Covers the budget enforcement (A1), the JSON-or-fallback parsing (C1), and
the sync + async entry points.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.scan._llm import (
    FALLBACK_CALL_RAISED,
    FALLBACK_UNPARSEABLE,
    BudgetExceededError,
    LiteLLMCallCounter,
    _extract_json_object,
    active_counter,
    litellm_json_call,
    litellm_json_call_async,
    pop_fallback_cause,
)


def _stub_response(text: str) -> SimpleNamespace:
    """Construct a minimal LiteLLM-shaped completion response."""
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _tool_call_response(arguments: str, content: str = "") -> SimpleNamespace:
    """A response whose JSON arrives in a tool call's arguments (some providers' JSON mode)."""
    call = SimpleNamespace(function=SimpleNamespace(name="emit", arguments=arguments))
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=[call]))]
    )


def test_json_from_tool_call_arguments_parses() -> None:
    """Issue: some providers return the object in tool_calls, not content."""

    def stub(**_: Any) -> SimpleNamespace:
        return _tool_call_response('{"body": "from-tool"}', content="")

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause is None
    assert result == {"body": "from-tool"}


@pytest.mark.parametrize(
    "content",
    [
        '{"body": "hi",}',  # trailing comma
        "{'body': 'hi'}",  # single quotes
        '{body: "hi"}',  # unquoted key
    ],
)
def test_non_strict_json_rescued_by_repair(content: str) -> None:
    """Non-Claude / local models emit non-strict JSON; json-repair rescues it."""

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response(content)

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause is None
    assert result == {"body": "hi"}


def test_truncated_json_is_rejected_not_repaired() -> None:
    """A truncated object must fall back (NOT be fabricated by json-repair)."""

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "hi')  # never closes

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, detail = pop_fallback_cause(result)
    assert cause == FALLBACK_UNPARSEABLE
    assert "truncated" in (detail or "")
    assert result == {"body": "fb"}


def test_counter_increments_inside_active_scope() -> None:
    counter = LiteLLMCallCounter(cap=5)

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "hi"}')

    with counter.active():
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fallback"},
            caller="test",
            completion_fn=stub,
        )
    assert counter.count == 1
    assert counter.by_caller == {"test": 1}


def test_counter_does_not_track_outside_active_scope() -> None:
    """Calls outside an active scope still execute — just no enforcement."""
    counter = LiteLLMCallCounter(cap=1)

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "hi"}')

    # Not inside `with counter.active():` — call should pass through.
    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    assert result == {"body": "hi"}
    assert counter.count == 0
    assert active_counter() is None


def test_budget_exceeded_raises_before_next_call() -> None:
    counter = LiteLLMCallCounter(cap=2)

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "hi"}')

    with counter.active():
        for _ in range(2):
            litellm_json_call(
                model="stub",
                prompt="p",
                expected_keys={"body"},
                fallback={"body": "fb"},
                caller="test",
                completion_fn=stub,
            )
        with pytest.raises(BudgetExceededError):
            litellm_json_call(
                model="stub",
                prompt="p",
                expected_keys={"body"},
                fallback={"body": "fb"},
                caller="test",
                completion_fn=stub,
            )


def test_invalid_json_returns_fallback() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response("not json")

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause == FALLBACK_UNPARSEABLE
    assert result == {"body": "fb"}


def test_missing_required_key_returns_fallback() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"wrong": "thing"}')

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause == FALLBACK_UNPARSEABLE
    assert result == {"body": "fb"}


def test_completion_exception_returns_fallback_and_marks_failure() -> None:
    counter = LiteLLMCallCounter(cap=5)

    def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    with counter.active():
        result = litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    cause, detail = pop_fallback_cause(result)
    assert cause == FALLBACK_CALL_RAISED
    assert "provider down" in (detail or "")
    assert result == {"body": "fb"}
    assert counter.consecutive_failures == 1


@pytest.mark.parametrize(
    "content",
    [
        '```json\n{"body": "hi"}\n```',  # fenced with language tag (current Anthropic shape)
        '```\n{"body": "hi"}\n```',  # bare fence, no language tag
        'Here is the JSON you asked for:\n```json\n{"body": "hi"}\n```\nHope it helps!',
        'Sure — {"body": "hi"} — done.',  # object embedded in prose, no fence
    ],
)
def test_fenced_or_prose_json_parses_not_fallback(content: str) -> None:
    """Issue #6: current models wrap JSON in ```json fences / prose; must parse."""

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response(content)

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause is None  # genuine parse, not a fallback
    assert result == {"body": "hi"}


def test_brace_inside_string_value_does_not_miscount() -> None:
    """The balanced-object scan must ignore braces inside JSON string literals."""

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('```json\n{"reason": "use } carefully", "body": "ok"}\n```')

    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause is None
    assert result == {"reason": "use } carefully", "body": "ok"}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"a": 1}', '{"a": 1}'),
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
        ('prose {"a": {"b": 2}} trailing', '{"a": {"b": 2}}'),
        ('{"s": "has } brace"}', '{"s": "has } brace"}'),
        ("no object here", None),
        ("", None),
    ],
)
def test_extract_json_object(text: str, expected: str | None) -> None:
    assert _extract_json_object(text) == expected


def test_success_resets_consecutive_failures() -> None:
    counter = LiteLLMCallCounter(cap=5)
    counter.consecutive_failures = 2  # simulate prior failures

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "hi"}')

    with counter.active():
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert counter.consecutive_failures == 0


def test_litellm_json_call_passes_an_explicit_timeout() -> None:
    """DCR-0018: every completion call carries an explicit timeout — a stuck
    provider call must not be able to hang indefinitely with no bound at all."""
    seen: list[dict[str, Any]] = []

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
        timeout_s=5.0,
    )
    assert seen[0]["timeout"] == 5.0


def test_litellm_json_call_defaults_a_timeout_when_not_specified() -> None:
    seen: list[dict[str, Any]] = []

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    assert isinstance(seen[0]["timeout"], float) and seen[0]["timeout"] > 0


@pytest.mark.asyncio
async def test_litellm_json_call_async_passes_an_explicit_timeout() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    await litellm_json_call_async(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
        timeout_s=7.0,
    )
    assert seen[0]["timeout"] == 7.0


@pytest.mark.asyncio
async def test_async_helper_works_same_way() -> None:
    counter = LiteLLMCallCounter(cap=3)

    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "async"}')

    with counter.active():
        result = await litellm_json_call_async(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert result == {"body": "async"}
    assert counter.count == 1
