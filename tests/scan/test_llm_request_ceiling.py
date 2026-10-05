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


class _AsyncRecorder:
    """Async sibling of :class:`_Recorder`, for the planner chokepoint
    (``litellm_tool_call_async``), which awaits ``completion_fn``."""

    def __init__(self, fail_first: int = 0, exc: Any = _rate_limit) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_first = fail_first
        self.exc = exc

    async def __call__(self, **kwargs: Any) -> Any:
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


def test_num_retries_unset_defaults_to_two_attempts_under_a_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_send_plan`` must not read a ``call_kwargs`` with no ``num_retries``
    key at all (``None``) as zero retries -- that would silently remove the
    resilience a 429 gets with no ceiling set, where LiteLLM's own default
    retries would otherwise apply. ``None`` defaults to
    ``_DEFAULT_CEILING_RETRIES`` (2); every real chokepoint already supplies
    ``num_retries`` via ``LLMPolicy``'s own default of the same value, so
    this exercises the belt-and-braces default directly, independent of the
    policy."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    kwargs, attempts = _llm._send_plan({"model": "gpt-4o"})
    assert attempts == 3
    assert kwargs["num_retries"] == 0
    assert kwargs["max_retries"] == 0


def test_explicit_zero_retries_still_means_exactly_one_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``num_retries=0`` always wins over the default -- it means
    exactly one attempt, the operator's own choice, not a gap to fill in."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    _, attempts = _llm._send_plan({"model": "gpt-4o", "num_retries": 0})
    assert attempts == 1


def test_num_retries_unset_retries_a_rate_limit_once_under_a_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end, with no policy scoped at all (the realistic 'the operator
    never touched num_retries' case): one 429 then success still succeeds,
    and both attempts are charged to the ceiling."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    fn = _Recorder(fail_first=1)
    result = _json_call(fn)
    assert result == {"success": False, "confidence": 0.0, "reason": "stub"}
    assert len(fn.calls) == 2
    assert requests_sent() == 2


def test_three_consecutive_rate_limits_exhaust_retries_without_a_silent_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The planner chokepoint (``litellm_tool_call_async``) never swallows a
    provider failure into a fallback -- once every retry is spent it still
    raises, so the MCP adapter above it can label the skip "rate_limit"
    (``MCPSessionAdapterBase._classify_failure``) instead of silently
    treating it as a decided attempt. Three failures (one attempt plus the
    two default retries) exhausts retries, not the ceiling."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    fn = _AsyncRecorder(fail_first=3)

    async def _drive() -> None:
        await litellm_tool_call_async(
            model="gpt-4o", messages=[{"role": "user", "content": "p"}], completion_fn=fn
        )

    with pytest.raises(litellm.RateLimitError):
        asyncio.run(_drive())
    assert len(fn.calls) == 3, "one attempt plus two default retries, then give up"
    assert requests_sent() == 3
    assert request_ceiling_hit() is None, "retries were exhausted, not the ceiling"


def test_401_under_a_ceiling_is_exactly_one_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """An auth failure (401/403) is never retried, ceiling or not -- same
    assertion as ``test_non_recoverable_errors_are_not_retried``, but with no
    policy scoped (the default ``num_retries``), to pin the no-retry rule
    against the belt-and-braces default added above, not just an explicit
    ``num_retries=2``."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    fn = _Recorder(fail_first=5, exc=_auth)
    with pytest.raises(_llm.NonRecoverableProviderError):
        _json_call(fn)
    assert len(fn.calls) == 1


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


# --- retries under a ceiling -------------------------------------------------


class _Headers(dict[str, str]):
    pass


def _rate_limit_with(headers: dict[str, str]) -> BaseException:
    exc = _rate_limit()
    exc.response = SimpleNamespace(headers=_Headers(headers))  # type: ignore[attr-defined]
    return exc


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"retry-after": "5"}, 5.0),
        ({"retry-after-ms": "2500"}, 2.5),
        ({"retry-after": "600"}, 60.0),  # capped
        ({"retry-after": "0"}, 0.5),  # never less than the backoff
        ({}, 0.5),
    ],
)
def test_rate_limit_wait_honours_retry_after(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str], expected: float
) -> None:
    monkeypatch.setattr(_llm, "_jitter", lambda: 0.0)
    assert _llm._retry_wait_s(_rate_limit_with(headers), 0, "gpt-4o") == pytest.approx(expected)


def test_retry_after_http_date_is_understood(monkeypatch: pytest.MonkeyPatch) -> None:
    import email.utils
    import time

    monkeypatch.setattr(_llm, "_jitter", lambda: 0.0)
    when = email.utils.formatdate(time.time() + 20, usegmt=True)
    wait = _llm._retry_wait_s(_rate_limit_with({"retry-after": when}), 0, "gpt-4o")
    assert 15.0 <= wait <= 21.0


def test_backoff_grows_and_jitter_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = _rate_limit()
    monkeypatch.setattr(_llm, "_jitter", lambda: 0.0)
    assert [_llm._retry_wait_s(exc, a, "gpt-4o") for a in range(4)] == [0.5, 1.0, 2.0, 4.0]
    monkeypatch.setattr(_llm, "_jitter", lambda: 1.0)
    assert _llm._retry_wait_s(exc, 1, "gpt-4o") == pytest.approx(1.25)
    assert _llm._retry_wait_s(exc, 20, "gpt-4o") == 60.0


def test_retry_after_is_ignored_for_non_rate_limit_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_llm, "_jitter", lambda: 0.0)
    exc = litellm.APIConnectionError(message="reset", llm_provider="openai", model="gpt-4o")
    exc.response = SimpleNamespace(headers={"retry-after": "30"})  # type: ignore[attr-defined]
    assert _llm._retry_wait_s(exc, 0, "gpt-4o") == 0.5


def test_send_sleeps_for_what_the_provider_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    monkeypatch.setattr(_llm, "_jitter", lambda: 0.0)
    waits: list[float] = []
    monkeypatch.setattr(_llm, "_sleep", waits.append)
    fn = _Recorder(fail_first=1, exc=lambda: _rate_limit_with({"retry-after": "7"}))
    with llm_scope(policy=LLMPolicy(num_retries=2)):
        _json_call(fn)
    assert waits == [7.0]
    assert len(fn.calls) == 2


def test_mylonite_and_stub_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Errors that are bugs or missing fixtures are never retried, so they
    cannot spend the ceiling on sleeps that will not help."""
    from mylonite._replay import MissingFixtureError

    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    for exc in (lambda: MissingFixtureError("no fixture"), lambda: TypeError("bad stub")):
        fn = _Recorder(fail_first=5, exc=exc)
        with llm_scope(policy=LLMPolicy(num_retries=2)):
            _json_call(fn)  # swallowed into a fallback, as before
        assert len(fn.calls) == 1
    server = _Recorder(
        fail_first=1,
        exc=lambda: litellm.InternalServerError(
            message="500", llm_provider="openai", model="gpt-4o"
        ),
    )
    with llm_scope(policy=LLMPolicy(num_retries=2)):
        _json_call(server)
    assert len(server.calls) == 2, "a provider 5xx is still retried"


def test_a_global_litellm_retry_count_cannot_leak_into_ceiling_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LiteLLM's sync wrapper falls back to ``litellm.num_retries`` when the call
    says 0. Under a ceiling that would be uncounted retries, so refuse."""
    monkeypatch.setattr(litellm, "num_retries", 3)
    fn = _Recorder()
    # No ceiling: today's behaviour, untouched.
    _json_call(fn)
    assert len(fn.calls) == 1
    monkeypatch.setenv(REQUEST_CEILING_ENV, "10")
    with pytest.raises(InvalidRequestCeilingError, match=r"litellm.num_retries"):
        _json_call(fn)
    assert len(fn.calls) == 1, "nothing may be sent"
    monkeypatch.setattr(litellm, "num_retries", None)
    _json_call(fn)
    assert len(fn.calls) == 2


def test_the_env_value_is_parsed_once_per_value(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = _llm.parse_request_ceiling

    def counting(raw: str) -> int:
        calls.append(raw)
        return real(raw)

    monkeypatch.setattr(_llm, "parse_request_ceiling", counting)
    monkeypatch.setenv(REQUEST_CEILING_ENV, "50")
    for _ in range(5):
        _json_call(_Recorder())
    assert calls == ["50"]
    monkeypatch.setenv(REQUEST_CEILING_ENV, "60")
    assert request_ceiling() == 60
    assert calls == ["50", "60"]


def test_a_bad_env_value_fails_before_anything_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "lots")
    fn = _Recorder()
    with pytest.raises(InvalidRequestCeilingError):
        _json_call(fn)  # not swallowed into a fallback
    assert fn.calls == []
