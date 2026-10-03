"""The key preflight: one tiny call per distinct role model, before any target work.

A wrong key or a missing required header must stop the run in one line, exit
4, before the target launches. The preflight itself must stay cheap and must
count against the hard request ceiling like any other request.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import typer

from mylonite.exit_codes import EXIT_PROVIDER
from mylonite.providers.registry import PROVIDERS
from mylonite.scan import auth_preflight
from mylonite.scan._llm import LLMRequestCeilingError, configure_request_ceiling
from mylonite.scan.llm_headers import LLM_HEADERS_ENV, configure_llm_headers, reset_llm_headers

#: Captured at import, before the suite-wide autouse fixture swaps the
#: preflight for a no-op (see tests/conftest.py).
_REAL_PREFLIGHT = auth_preflight.auth_preflight_or_exit

_KEY_MODEL = "anthropic/test-model"
_OTHER_MODEL = "openai/test-model"
_HEADER_400 = "anthropic-workspace-id header is required for this API key"
_SENTINEL = "wrkspc-sentinel-5c21d"


@pytest.fixture(autouse=True)
def _real_preflight(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(auth_preflight, "auth_preflight_or_exit", _REAL_PREFLIGHT)
    monkeypatch.delenv(LLM_HEADERS_ENV, raising=False)
    reset_llm_headers()
    yield
    reset_llm_headers()


class _FakeCompletion:
    """Records each call; raises ``error`` if one is set."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        message = SimpleNamespace(content="ok", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> _FakeCompletion:
    completion = _FakeCompletion()
    monkeypatch.setattr(litellm, "acompletion", completion)
    return completion


def test_one_call_when_every_role_uses_the_same_model(fake: _FakeCompletion) -> None:
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL, _KEY_MODEL, _KEY_MODEL)
    assert len(fake.calls) == 1


def test_one_call_per_distinct_model(fake: _FakeCompletion) -> None:
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL, _OTHER_MODEL, _KEY_MODEL)
    assert [c["model"] for c in fake.calls] == [_KEY_MODEL, _OTHER_MODEL]


def test_the_call_is_tiny_and_never_retried(fake: _FakeCompletion) -> None:
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL)
    (call,) = fake.calls
    assert call["max_tokens"] <= 16
    assert call["num_retries"] == 0


def test_a_model_proven_once_is_not_called_again_in_the_same_run(
    fake: _FakeCompletion,
) -> None:
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL)
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL, _KEY_MODEL)
    assert len(fake.calls) == 1


def test_a_local_model_needs_no_key_and_is_not_called(fake: _FakeCompletion) -> None:
    local = PROVIDERS["ollama"].example_model
    assert local is not None
    auth_preflight.auth_preflight_or_exit(local)
    assert fake.calls == []


def test_configured_headers_ride_on_the_preflight_call(fake: _FakeCompletion) -> None:
    configure_llm_headers([f"anthropic-workspace-id={_SENTINEL}"])
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL, api_base=None)
    assert fake.calls[0]["extra_headers"] == {"anthropic-workspace-id": _SENTINEL}


def test_the_preflight_counts_against_the_request_ceiling(fake: _FakeCompletion) -> None:
    configure_request_ceiling(1)
    with pytest.raises(LLMRequestCeilingError):
        auth_preflight.auth_preflight_or_exit(_KEY_MODEL, _OTHER_MODEL)
    assert len(fake.calls) == 1


def _run_expecting_exit(capsys: pytest.CaptureFixture[str]) -> str:
    with pytest.raises(typer.Exit) as info:
        auth_preflight.auth_preflight_or_exit(_KEY_MODEL)
    assert info.value.exit_code == EXIT_PROVIDER
    err = capsys.readouterr().err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    assert "Traceback" not in err
    return lines[0]


def test_a_401_exits_4_in_one_line_naming_the_key_variable(
    fake: _FakeCompletion, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.error = litellm.AuthenticationError(
        message="invalid x-api-key", llm_provider="anthropic", model=_KEY_MODEL
    )
    line = _run_expecting_exit(capsys)
    assert PROVIDERS["anthropic"].key_env[0] in line
    assert "invalid or expired" in line


def test_a_400_header_required_exits_4_naming_the_header_option(
    fake: _FakeCompletion, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.error = litellm.BadRequestError(
        message=_HEADER_400, model=_KEY_MODEL, llm_provider="anthropic"
    )
    line = _run_expecting_exit(capsys)
    assert "--llm-header" in line
    assert LLM_HEADERS_ENV in line


def test_the_error_line_never_echoes_a_header_value(
    fake: _FakeCompletion, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_llm_headers([f"anthropic-workspace-id={_SENTINEL}"])
    fake.error = litellm.AuthenticationError(
        message=f"invalid key for workspace {_SENTINEL}",
        llm_provider="anthropic",
        model=_KEY_MODEL,
    )
    line = _run_expecting_exit(capsys)
    assert _SENTINEL not in line


def test_the_error_line_encodes_on_a_cp1252_console(
    fake: _FakeCompletion, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.error = litellm.BadRequestError(
        message=_HEADER_400, model=_KEY_MODEL, llm_provider="anthropic"
    )
    _run_expecting_exit(capsys).encode("cp1252")


@pytest.mark.parametrize(
    "error",
    [
        litellm.APIConnectionError(message="connection reset", llm_provider="x", model="m"),
        litellm.RateLimitError(message="429", llm_provider="x", model="m"),
    ],
    ids=["network", "rate-limit"],
)
def test_a_non_key_failure_does_not_block_the_run(
    fake: _FakeCompletion, error: BaseException
) -> None:
    """Reachability and rate limits keep their own later, more specific handling."""
    fake.error = error
    auth_preflight.auth_preflight_or_exit(_KEY_MODEL)
    assert len(fake.calls) == 1
