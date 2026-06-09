"""LiteLLMCallCounter + litellm_json_call helper tests.

Covers the budget enforcement (A1), the JSON-or-fallback parsing (C1), and
the sync + async entry points.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.scan._llm import (
    BudgetExceededError,
    LiteLLMCallCounter,
    active_counter,
    litellm_json_call,
    litellm_json_call_async,
)


def _stub_response(text: str) -> SimpleNamespace:
    """Construct a minimal LiteLLM-shaped completion response."""
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


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
    assert result == {"body": "fb"}
    assert counter.consecutive_failures == 1


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
