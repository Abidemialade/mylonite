"""The reachability preflight: one tiny completion per distinct role model,
never a full reference scan (V1), with the run's own ``api_base`` applied
(T7: both preflights used to run outside ``llm_scope``, so a configured
custom endpoint -- a remote Ollama, a self-hosted vLLM, an OpenAI-compatible
proxy -- was never actually asked by the check; it fell back to the default
policy and read "provider unreachable" even though the provider was up).
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import litellm
import pytest

from mylonite.scan.preflight import PreflightFailure, provider_preflight, provider_preflight_direct

_PREFLIGHT_FNS = [provider_preflight, provider_preflight_direct]


class _Recorder:
    """Records every call's kwargs; always answers "ok"."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        message = SimpleNamespace(content="ok", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(litellm, "acompletion", rec)
    return rec


@pytest.mark.parametrize("fn", _PREFLIGHT_FNS)
def test_one_tiny_call_per_distinct_role_model(fn: Any, recorder: _Recorder) -> None:
    """Three roles, two of them sharing a model: exactly two calls, not a scan."""
    ok = fn(
        "anthropic",
        "anthropic/model-a",
        "anthropic/model-a",
        "anthropic/model-b",
        timeout_s=5.0,
    )

    assert ok is True
    assert [c["model"] for c in recorder.calls] == ["anthropic/model-a", "anthropic/model-b"]
    for call in recorder.calls:
        # The same tiny-request shape the key preflight already uses.
        assert call.get("max_tokens", 2048) <= 16
        assert call.get("num_retries", 2) == 0


@pytest.mark.parametrize("fn", _PREFLIGHT_FNS)
def test_a_configured_api_base_reaches_every_ping(fn: Any, recorder: _Recorder) -> None:
    """T7 repro: a custom endpoint must actually be asked, not the default
    policy -- previously ``api_base`` had no way to reach either preflight."""
    ok = fn(
        "ollama",
        "ollama_chat/llama3.2",
        "ollama_chat/llama3.2",
        timeout_s=5.0,
        api_base="http://example-llm-host:11434",  # allow-literal: example
    )

    assert ok is True
    assert recorder.calls
    assert all(
        c.get("api_base") == "http://example-llm-host:11434"  # allow-literal: example
        for c in recorder.calls
    )


def test_provider_preflight_never_imports_the_reference_target(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V1: the reference-path reachability check used to run a full 9-seed
    scan (importing mcp_kitchen_sink via `scan.wiring.build_scan`). It's now
    the same tiny ping as the custom path, so it never touches that package."""
    monkeypatch.setitem(sys.modules, "mcp_kitchen_sink", None)  # poison the import

    assert provider_preflight("anthropic", "anthropic/model-a", timeout_s=5.0) is True


@pytest.mark.parametrize("fn", _PREFLIGHT_FNS)
def test_a_stalled_ping_reads_as_network_not_credentials(
    fn: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider (or a hung fake) that never answers is a timeout, never a
    credentials problem."""
    import asyncio

    async def _hanging(**_: Any) -> Any:
        await asyncio.sleep(30)

    monkeypatch.setattr(litellm, "acompletion", _hanging)
    failure = PreflightFailure()

    ok = fn("anthropic", "anthropic/model-a", timeout_s=0.2, failure=failure)

    assert ok is False
    assert failure.category == "network"
    assert failure.model == "anthropic/model-a"


@pytest.mark.parametrize("fn", _PREFLIGHT_FNS)
def test_failure_names_the_role_model_that_actually_failed(
    fn: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V2: with three distinct role models, the failure records the one that
    was actually unreachable, never always the first/primary model."""

    async def _refuse_the_second(*, model: str, **_: Any) -> Any:
        if model == "anthropic/judge-model":
            raise litellm.AuthenticationError(
                message="invalid x-api-key", llm_provider="anthropic", model=model
            )
        message = SimpleNamespace(content="ok", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)

    monkeypatch.setattr(litellm, "acompletion", _refuse_the_second)
    failure = PreflightFailure()

    ok = fn(
        "anthropic",
        "anthropic/planner-model",
        "anthropic/judge-model",
        timeout_s=5.0,
        failure=failure,
    )

    assert ok is False
    assert failure.category == "auth"
    assert failure.model == "anthropic/judge-model"
