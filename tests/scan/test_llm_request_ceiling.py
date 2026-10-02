"""The hard LLM request ceiling (``MYLONITE_MAX_LLM_REQUESTS``).

Process-wide, counts every request sent to a provider (retries included), and
never lets one more out once it is spent. Unset, nothing changes.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import litellm
import pytest

from mylonite.scan import _llm
from mylonite.scan._llm import (
    REQUEST_CEILING_ENV,
    BudgetExceededError,
    InvalidRequestCeilingError,
    LiteLLMCallCounter,
    LLMRequestCeilingError,
    configure_request_ceiling,
    litellm_json_call,
    litellm_json_call_async,
    litellm_text_call,
    litellm_tool_call_async,
    llm_scope,
    request_ceiling,
    request_ceiling_hit,
    requests_sent,
)
from mylonite.scan.llm_policy import LLMPolicy

_JSON = '{"success": false, "confidence": 0.0, "reason": "stub"}'


def _response(text: str = _JSON) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _rate_limit() -> BaseException:
    return litellm.RateLimitError(message="slow down", llm_provider="openai", model="gpt-4o")


def _auth() -> BaseException:
    return litellm.AuthenticationError(message="bad key", llm_provider="openai", model="gpt-4o")


class _Recorder:
    """A sync completion stub that fails ``fail_first`` times, then answers."""

    def __init__(self, fail_first: int = 0, exc: Any = _rate_limit) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_first = fail_first
        self.exc = exc

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if len(self.calls) <= self.fail_first:
            raise self.exc()
        return _response()


def _json_call(fn: Any, **extra: Any) -> dict[str, Any]:
    return litellm_json_call(
        model="gpt-4o",
        prompt="p",
        expected_keys=("success",),
        fallback={"success": False},
        caller="judge",
        completion_fn=fn,
        **extra,
    )


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _instant(_s: float) -> None:
        return None

    monkeypatch.setattr(_llm, "_sleep", lambda _s: None)
    monkeypatch.setattr(_llm, "_async_sleep", _instant)


def test_unset_passes_kwargs_through_and_never_refuses() -> None:
    fn = _Recorder()
    with llm_scope(policy=LLMPolicy(num_retries=2)):
        for _ in range(5):
            _json_call(fn)
    assert request_ceiling() is None
    assert len(fn.calls) == 5
    # LiteLLM keeps doing its own retries exactly as before.
    assert fn.calls[0]["num_retries"] == 2
    assert "max_retries" not in fn.calls[0]
    assert requests_sent() == 5
    assert request_ceiling_hit() is None


def test_set_ceiling_turns_off_litellm_retries_and_counts_each_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    fn = _Recorder(fail_first=2)
    with llm_scope(policy=LLMPolicy(num_retries=2)):
        result = _json_call(fn)
    assert result["success"] is False
    assert len(fn.calls) == 3, "two retries after the first attempt"
    assert all(c["num_retries"] == 0 and c["max_retries"] == 0 for c in fn.calls)
    assert requests_sent() == 3


def test_retries_count_against_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "2")
    fn = _Recorder(fail_first=5)
    with llm_scope(policy=LLMPolicy(num_retries=2)), pytest.raises(LLMRequestCeilingError):
        _json_call(fn)
    assert len(fn.calls) == 2, "the third attempt (a retry) must never be sent"
    assert request_ceiling_hit() == 2


def test_non_recoverable_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    fn = _Recorder(fail_first=5, exc=_auth)
    with (
        llm_scope(policy=LLMPolicy(num_retries=2)),
        pytest.raises(_llm.NonRecoverableProviderError),
    ):
        _json_call(fn)
    assert len(fn.calls) == 1


def test_ceiling_is_shared_across_scan_and_validate_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan and a validation in one process draw on one ceiling, whatever
    per-scan ``--max-llm-calls`` counters they each run under."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "4")
    fn = _Recorder()
    with llm_scope(counter=LiteLLMCallCounter(cap=50)):  # the scan
        for _ in range(3):
            _json_call(fn)
    with llm_scope(counter=LiteLLMCallCounter(cap=120)):  # the validation
        _json_call(fn)
        with pytest.raises(LLMRequestCeilingError) as info:
            _json_call(fn)
    assert len(fn.calls) == 4
    assert "LLM request ceiling of 4" in str(info.value)
    assert isinstance(info.value, BudgetExceededError)


def test_trip_is_sticky_even_if_a_caller_swallows_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "1")
    fn = _Recorder()
    _json_call(fn)
    for _ in range(3):
        with pytest.raises(LLMRequestCeilingError):
            _json_call(fn)
    assert len(fn.calls) == 1


def test_all_four_chokepoints_are_charged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "4")
    sync = _Recorder()
    sent: list[str] = []

    async def acomp(**_kw: Any) -> Any:
        sent.append("async")
        return _response()

    _json_call(sync)
    litellm_text_call(model="gpt-4o", prompt="p", caller="mitigation", completion_fn=sync)

    async def _drive() -> None:
        await litellm_json_call_async(
            model="gpt-4o",
            prompt="p",
            expected_keys=("success",),
            fallback={"success": False},
            caller="judge",
            completion_fn=acomp,
        )
        await litellm_tool_call_async(
            model="gpt-4o", messages=[{"role": "user", "content": "p"}], completion_fn=acomp
        )
        await litellm_tool_call_async(
            model="gpt-4o", messages=[{"role": "user", "content": "p"}], completion_fn=acomp
        )

    with pytest.raises(LLMRequestCeilingError):
        asyncio.run(_drive())
    assert len(sync.calls) + len(sent) == 4
    assert requests_sent() == 4


def test_ceiling_error_is_not_swallowed_into_a_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """``litellm_json_call`` falls back on provider faults; the ceiling is not one."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "1")
    _json_call(_Recorder())
    with pytest.raises(LLMRequestCeilingError):
        _json_call(_Recorder())


def test_explicit_ceiling_wins_over_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "100")
    configure_request_ceiling(1)
    _json_call(_Recorder())
    with pytest.raises(LLMRequestCeilingError):
        _json_call(_Recorder())


@pytest.mark.parametrize("raw", ["0", "-3", "ten", "1.5"])
def test_invalid_ceiling_values_are_refused(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, raw)
    with pytest.raises(InvalidRequestCeilingError):
        request_ceiling()
    with pytest.raises(InvalidRequestCeilingError):
        configure_request_ceiling(0)


def test_a_refused_call_is_not_counted_as_a_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """The spend line reports calls that ran; a refused one never did."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "2")
    counter = LiteLLMCallCounter(cap=50)
    with llm_scope(counter=counter):
        _json_call(_Recorder())
        _json_call(_Recorder())
        for _ in range(3):
            with pytest.raises(LLMRequestCeilingError):
                _json_call(_Recorder())
    assert counter.count == 2


def test_preflight_reports_a_spent_ceiling_not_an_unreachable_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mylonite.scan.preflight import provider_preflight_direct

    monkeypatch.setenv(REQUEST_CEILING_ENV, "1")
    _json_call(_Recorder())
    with pytest.raises(LLMRequestCeilingError):
        provider_preflight_direct("openai", "gpt-4o", timeout_s=5.0)
