"""LiteLLMCallCounter + litellm_json_call helper tests.

Covers the budget enforcement (A1), the JSON-or-fallback parsing (C1), and
the sync + async entry points.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import litellm
import pytest

from mylonite.scan._llm import (
    FALLBACK_CALL_RAISED,
    FALLBACK_UNPARSEABLE,
    BudgetExceededError,
    LiteLLMCallCounter,
    NonRecoverableProviderError,
    active_counter,
    active_policy,
    litellm_json_call,
    litellm_json_call_async,
    litellm_text_call,
    litellm_tool_call_async,
    llm_scope,
    pop_fallback_cause,
)
from mylonite.scan.llm_parse import _extract_json_object
from mylonite.scan.llm_policy import LLMPolicy


def _stub_response(text: str) -> SimpleNamespace:
    """Construct a minimal LiteLLM-shaped completion response."""
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _provider_exc(name: str) -> BaseException:
    """A real LiteLLM typed exception instance (e.g. ``AuthenticationError``).

    Mirrors ``test_llm_crossmodel.py``'s ``_make`` helper — constructing the
    real typed class (rather than a plain ``RuntimeError`` with a matching
    message) is what proves ``classify_provider_error``'s typed-exception-first
    path, not just its substring fallback.
    """
    cls = getattr(litellm, name)
    try:
        return cls(message="boom", llm_provider="openai", model="gpt-4o")
    except TypeError:
        return cls("boom")


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


# --- T4: non-recoverable provider failures re-raise, transient ones still fall back ---
#
# auth/tls/context_window will never succeed on retry (a misconfigured API key
# doesn't fix itself between calls), so these must propagate as a loud,
# classifiable error instead of quietly degrading to an "inconclusive" verdict
# (the exact failure mode a security tool must not have). rate_limit/network/
# unknown are genuinely transient and must keep the pre-existing fallback
# behaviour unchanged — see ``test_rate_limit_error_still_falls_back_unchanged``.


def test_auth_error_reraises_not_fallback() -> None:
    counter = LiteLLMCallCounter(cap=5)

    def stub(**_: Any) -> SimpleNamespace:
        raise _provider_exc("AuthenticationError")

    with counter.active(), pytest.raises(NonRecoverableProviderError) as excinfo:
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert excinfo.value.diagnosis.category == "auth"
    # The counter still records the failed attempt — a re-raise doesn't lose
    # the consecutive-failure signal the engine's provider-unreachable abort
    # relies on.
    assert counter.consecutive_failures == 1


def test_tls_error_reraises_not_fallback() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        # Real shape LiteLLM wraps a corporate-proxy TLS failure in — an
        # APIConnectionError-flavoured message, not a typed TLS exception (see
        # diagnostics.classify_provider_error's "TLS FIRST" substring check).
        raise RuntimeError(
            "AnthropicException - APIConnectionError - [SSL: CERTIFICATE_VERIFY_FAILED] "
            "unable to get local issuer certificate"
        )

    with pytest.raises(NonRecoverableProviderError) as excinfo:
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert excinfo.value.diagnosis.category == "tls"


def test_context_window_error_reraises_not_fallback() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        raise _provider_exc("ContextWindowExceededError")

    with pytest.raises(NonRecoverableProviderError) as excinfo:
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert excinfo.value.diagnosis.category == "context_window"


def test_rate_limit_error_still_falls_back_unchanged() -> None:
    """Regression guard: a genuinely transient category must NOT be re-raised."""
    counter = LiteLLMCallCounter(cap=5)

    def stub(**_: Any) -> SimpleNamespace:
        raise _provider_exc("RateLimitError")

    with counter.active():
        result = litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    cause, _ = pop_fallback_cause(result)
    assert cause == FALLBACK_CALL_RAISED
    assert result == {"body": "fb"}
    assert counter.consecutive_failures == 1


@pytest.mark.asyncio
async def test_async_auth_error_reraises_not_fallback() -> None:
    """The async sibling classifies+re-raises the same way as the sync entry point."""

    async def stub(**_: Any) -> SimpleNamespace:
        raise _provider_exc("AuthenticationError")

    with pytest.raises(NonRecoverableProviderError) as excinfo:
        await litellm_json_call_async(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert excinfo.value.diagnosis.category == "auth"


@pytest.mark.asyncio
async def test_async_network_error_still_falls_back_unchanged() -> None:
    """Regression guard for the async entry point's transient path."""

    async def stub(**_: Any) -> SimpleNamespace:
        raise _provider_exc("APIConnectionError")

    result = await litellm_json_call_async(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=stub,
    )
    cause, _ = pop_fallback_cause(result)
    assert cause == FALLBACK_CALL_RAISED
    assert result == {"body": "fb"}


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


# --- T14/H2 code-review follow-up: direct chokepoint coverage ---------------
#
# Every call site (litellm_json_call[_async], litellm_tool_call_async,
# litellm_text_call) is supposed to merge active_policy().kwargs() into the
# call it makes. Everything above only ever asserted on `timeout`; these
# tests assert on the OTHER policy fields (drop_params/temperature/
# max_tokens/seed/num_retries) so a regression that silently drops the merge
# from any one call site is actually caught.


def test_litellm_json_call_merges_default_policy_kwargs_when_unscoped() -> None:
    """No llm_scope active -> LLMPolicy()'s documented defaults still apply
    (this is the actual bug T14 fixed: before it, NONE of these kwargs were
    ever set at all, so a provider's own defaults silently applied)."""
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
    assert seen[0]["temperature"] == 0.0
    assert seen[0]["max_tokens"] == 2048
    assert seen[0]["drop_params"] is True
    assert seen[0]["num_retries"] == 2
    assert seen[0]["seed"] == 0


def test_litellm_json_call_merges_a_scoped_policy() -> None:
    """A caller-supplied LLMPolicy (via llm_scope) overrides the defaults --
    proving the merge reads the ACTIVE policy, not a hardcoded one."""
    seen: list[dict[str, Any]] = []

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    policy = LLMPolicy(temperature=0.9, max_tokens=64, drop_params=False, num_retries=5, seed=None)
    with llm_scope(policy=policy):
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert seen[0]["temperature"] == 0.9
    assert seen[0]["max_tokens"] == 64
    assert seen[0]["drop_params"] is False
    assert seen[0]["num_retries"] == 5
    assert "seed" not in seen[0]  # seed=None is omitted by LLMPolicy.kwargs()
    # Outside the `with` block the scope is gone -- active_policy() reverts.
    assert active_policy() == LLMPolicy()


def test_litellm_json_call_includes_api_base_when_policy_sets_it() -> None:
    seen: list[dict[str, Any]] = []

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    with llm_scope(policy=LLMPolicy(api_base="https://my-proxy.internal/v1")):
        litellm_json_call(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert seen[0]["api_base"] == "https://my-proxy.internal/v1"


@pytest.mark.asyncio
async def test_litellm_json_call_async_merges_a_scoped_policy() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response('{"body": "hi"}')

    with llm_scope(policy=LLMPolicy(temperature=0.5, max_tokens=99)):
        await litellm_json_call_async(
            model="stub",
            prompt="p",
            expected_keys={"body"},
            fallback={"body": "fb"},
            caller="test",
            completion_fn=stub,
        )
    assert seen[0]["temperature"] == 0.5
    assert seen[0]["max_tokens"] == 99
    assert seen[0]["drop_params"] is True  # untouched fields keep LLMPolicy's defaults


# --- litellm_tool_call_async (the planner's chokepoint) ---------------------


@pytest.mark.asyncio
async def test_litellm_tool_call_async_merges_active_policy_kwargs() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="hi"))])

    with llm_scope(policy=LLMPolicy(temperature=0.3, max_tokens=77, drop_params=False)):
        response = await litellm_tool_call_async(
            model="stub",
            messages=[{"role": "user", "content": "hi"}],
            completion_fn=stub,
        )
    assert seen[0]["temperature"] == 0.3
    assert seen[0]["max_tokens"] == 77
    assert seen[0]["drop_params"] is False
    assert seen[0]["model"] == "stub"
    assert response.choices[0].message.content == "hi"  # raw response, not parsed JSON


@pytest.mark.asyncio
async def test_litellm_tool_call_async_passes_tools_and_tool_choice_only_when_given() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=""))])

    tools = [{"type": "function", "function": {"name": "f", "parameters": {}}}]
    await litellm_tool_call_async(
        model="stub", messages=[], tools=tools, completion_fn=stub, caller="planner"
    )
    assert seen[0]["tools"] == tools
    assert seen[0]["tool_choice"] == "auto"

    seen.clear()
    await litellm_tool_call_async(model="stub", messages=[], completion_fn=stub)
    assert "tools" not in seen[0]
    assert "tool_choice" not in seen[0]


@pytest.mark.asyncio
async def test_litellm_tool_call_async_bumps_budget_counter() -> None:
    counter = LiteLLMCallCounter(cap=5)

    async def stub(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))])

    with counter.active():
        await litellm_tool_call_async(
            model="stub", messages=[], completion_fn=stub, caller="planner"
        )
    assert counter.by_caller == {"planner": 1}
    assert counter.count == 1


@pytest.mark.asyncio
async def test_litellm_tool_call_async_marks_failure_and_reraises_on_exception() -> None:
    counter = LiteLLMCallCounter(cap=5)

    async def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    with counter.active(), pytest.raises(RuntimeError, match="provider down"):
        await litellm_tool_call_async(model="stub", messages=[], completion_fn=stub)
    # Exceptions propagate (never swallowed into a fallback, unlike
    # litellm_json_call) -- but a failure is still recorded for the engine's
    # provider_failure_threshold.
    assert counter.consecutive_failures == 1


@pytest.mark.asyncio
async def test_litellm_tool_call_async_explicit_timeout_overrides_policy() -> None:
    seen: list[dict[str, Any]] = []

    async def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=""))])

    with llm_scope(policy=LLMPolicy(timeout=120.0)):
        await litellm_tool_call_async(model="stub", messages=[], completion_fn=stub, timeout_s=9.0)
    assert seen[0]["timeout"] == 9.0

    seen.clear()
    with llm_scope(policy=LLMPolicy(timeout=42.0)):
        await litellm_tool_call_async(model="stub", messages=[], completion_fn=stub)
    assert seen[0]["timeout"] == 42.0  # timeout_s=None (default) defers to the policy


# --- litellm_text_call (gate mitigation's chokepoint) ------------------------


def test_litellm_text_call_merges_policy_and_returns_text() -> None:
    seen: list[dict[str, Any]] = []

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.append(kwargs)
        return _stub_response("a suggestion")

    with llm_scope(policy=LLMPolicy(temperature=0.6, max_tokens=33)):
        result = litellm_text_call(
            model="stub", prompt="p", caller="gate_mitigation", completion_fn=stub
        )
    assert result == "a suggestion"
    assert seen[0]["temperature"] == 0.6
    assert seen[0]["max_tokens"] == 33
    assert seen[0]["drop_params"] is True


def test_litellm_text_call_bumps_budget_counter() -> None:
    counter = LiteLLMCallCounter(cap=5)

    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response("x")

    with counter.active():
        litellm_text_call(model="stub", prompt="p", caller="gate_mitigation", completion_fn=stub)
    assert counter.by_caller.get("gate_mitigation", 0) == 1


def test_litellm_text_call_returns_none_on_exception_never_raises() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    result = litellm_text_call(
        model="stub", prompt="p", caller="gate_mitigation", completion_fn=stub
    )
    assert result is None  # must never raise -- enrichment is best-effort


def test_litellm_text_call_returns_none_on_empty_response() -> None:
    def stub(**_: Any) -> SimpleNamespace:
        return _stub_response("   ")  # whitespace-only

    result = litellm_text_call(
        model="stub", prompt="p", caller="gate_mitigation", completion_fn=stub
    )
    assert result is None


# --- llm_scope: nestability + selective (counter-only / policy-only) scoping -


def test_llm_scope_nested_policy_overrides_outer() -> None:
    """llm_scope's own docstring claims it's "nestable -- a caller can layer a
    narrower policy inside a wider one"; this exercises exactly that."""
    outer = LLMPolicy(temperature=0.1)
    inner = LLMPolicy(temperature=0.9)
    with llm_scope(policy=outer):
        assert active_policy().temperature == 0.1
        with llm_scope(policy=inner):
            assert active_policy().temperature == 0.9
        # Back to the outer policy after the inner scope exits.
        assert active_policy().temperature == 0.1
    # Back to the default after both exit.
    assert active_policy() == LLMPolicy()


def test_llm_scope_counter_only_leaves_policy_untouched() -> None:
    """Passing only `counter=` (no `policy=`) must not disturb whatever policy
    (or lack of one) was already active -- the two contextvars are independent."""
    policy = LLMPolicy(temperature=0.77)
    counter = LiteLLMCallCounter(cap=1)
    with llm_scope(policy=policy), llm_scope(counter=counter):
        assert active_policy().temperature == 0.77  # untouched by the counter-only scope
        assert active_counter() is counter


def test_llm_scope_policy_only_leaves_counter_untouched() -> None:
    counter = LiteLLMCallCounter(cap=1)
    with counter.active(), llm_scope(policy=LLMPolicy(temperature=0.42)):
        assert active_counter() is counter  # untouched by the policy-only scope
        assert active_policy().temperature == 0.42
