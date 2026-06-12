"""Cross-LLM regression matrix.

The point of this file is to prove the framework doesn't just handle *Claude's*
output shape. It exercises JSON ingestion across the shapes different providers
actually emit (fenced, clean, JSON-in-tool_call, non-strict, truncated), the
capability-gated structured-output request path, and provider-correct error
diagnostics. All offline (stubbed completions / monkeypatched introspection).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import litellm
import pytest
from pydantic import BaseModel

from mylonite.scan._llm import (
    FALLBACK_UNPARSEABLE,
    build_response_format,
    litellm_json_call,
    pop_fallback_cause,
)
from mylonite.scan.diagnostics import classify_provider_error
from mylonite.scan.providers import env_vars_for, provider_from_model


def _content(text: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _tool_json(arguments: str, content: str = "") -> SimpleNamespace:
    call = SimpleNamespace(function=SimpleNamespace(name="emit", arguments=arguments))
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=[call]))]
    )


def _run(response: SimpleNamespace) -> dict[str, Any]:
    return litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="test",
        completion_fn=lambda **_: response,
    )


# --- parse matrix: real per-provider output shapes --------------------------


@pytest.mark.parametrize(
    ("label", "response", "expected"),
    [
        ("claude_fenced", _content('```json\n{"body": "hi"}\n```'), {"body": "hi"}),
        ("openai_clean", _content('{"body": "hi"}'), {"body": "hi"}),
        ("gemini_fenced_no_lang", _content('```\n{"body": "hi"}\n```'), {"body": "hi"}),
        ("prose_wrapped", _content('Sure!\n{"body": "hi"}\nDone.'), {"body": "hi"}),
        ("json_in_tool_call", _tool_json('{"body": "hi"}', content=""), {"body": "hi"}),
        ("non_strict_trailing_comma", _content('{"body": "hi",}'), {"body": "hi"}),
        ("non_strict_single_quotes", _content("{'body': 'hi'}"), {"body": "hi"}),
        ("non_strict_unquoted_key", _content('{body: "hi"}'), {"body": "hi"}),
        # Array-wrapped: the brace matcher extracts the first object inside —
        # the right call for our single-object callers.
        ("array_wrapped", _content('[{"body": "hi"}]'), {"body": "hi"}),
    ],
)
def test_parse_matrix(label: str, response: SimpleNamespace, expected: dict[str, Any] | None) -> None:
    result = _run(response)
    cause, _ = pop_fallback_cause(result)
    if expected is None:
        assert cause == FALLBACK_UNPARSEABLE, label
        assert result == {"body": "fb"}, label
    else:
        assert cause is None, label
        assert result == expected, label


def test_truncated_falls_back_not_fabricated() -> None:
    result = _run(_content('{"body": "hi'))
    cause, detail = pop_fallback_cause(result)
    assert cause == FALLBACK_UNPARSEABLE
    assert "truncated" in (detail or "")
    assert result == {"body": "fb"}


def test_truncated_tool_call_argument_is_not_fabricated() -> None:
    """Regression: a truncated tool-call JSON arg must fall back, NOT be repaired
    into a fabricated success verdict (would corrupt the differential oracle)."""
    truncated = '{"success": true, "confidence": 0.95, "reason": "the agent clearly exfiltr'
    result = litellm_json_call(
        model="stub",
        prompt="p",
        expected_keys={"success", "confidence", "reason"},
        fallback={"success": False, "confidence": 0.0, "reason": ""},
        caller="test",
        completion_fn=lambda **_: _tool_json(truncated, content=""),
    )
    cause, detail = pop_fallback_cause(result)
    assert cause == FALLBACK_UNPARSEABLE
    assert "truncated" in (detail or "")
    assert result["success"] is False  # NOT fabricated to True


# --- capability detection (structured-output request gating) ----------------


class _Schema(BaseModel):
    body: str


def _patch_caps(monkeypatch: pytest.MonkeyPatch, *, schema: bool, params: list[str]) -> None:
    monkeypatch.setattr(litellm, "supports_response_schema", lambda **_: schema)
    monkeypatch.setattr(litellm, "get_supported_openai_params", lambda **_: params)


def test_build_response_format_json_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_caps(monkeypatch, schema=True, params=["response_format"])
    assert build_response_format("m", _Schema) is _Schema


def test_build_response_format_json_object_only(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_caps(monkeypatch, schema=False, params=["response_format"])
    assert build_response_format("m", _Schema) == {"type": "json_object"}


def test_build_response_format_none_when_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_caps(monkeypatch, schema=False, params=[])
    assert build_response_format("m", _Schema) is None


def test_build_response_format_degrades_when_introspection_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The critical fail-safe: a raising introspection call must not propagate."""

    def _boom(**_: Any) -> bool:
        raise RuntimeError("litellm internal change")

    def _boom_params(**_: Any) -> list[str]:
        raise RuntimeError("also broken")

    monkeypatch.setattr(litellm, "supports_response_schema", _boom)
    monkeypatch.setattr(litellm, "get_supported_openai_params", _boom_params)
    assert build_response_format("m", _Schema) is None  # degrades to prose-only


def test_response_format_forwarded_only_when_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_caps(monkeypatch, schema=False, params=["response_format"])
    seen: dict[str, Any] = {}

    def stub(**kwargs: Any) -> SimpleNamespace:
        seen.update(kwargs)
        return _content('{"body": "hi"}')

    litellm_json_call(
        model="m",
        prompt="p",
        expected_keys={"body"},
        fallback={"body": "fb"},
        caller="t",
        completion_fn=stub,
        schema_model=_Schema,
    )
    assert seen.get("response_format") == {"type": "json_object"}


# --- provider-agnostic diagnostics ------------------------------------------


def _make(name: str) -> BaseException:
    cls = getattr(litellm, name)
    try:
        return cls(message="boom", llm_provider="openai", model="gpt-4o")
    except TypeError:
        return cls("boom")


@pytest.mark.parametrize(
    ("provider", "expected_var"),
    [
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("google", "GEMINI_API_KEY"),
        ("gemini", "GEMINI_API_KEY"),  # litellm-internal spelling normalised
    ],
)
def test_auth_remedy_names_right_env_var(provider: str, expected_var: str) -> None:
    diag = classify_provider_error(_make("AuthenticationError"), provider=provider)
    assert diag.category == "auth"
    assert expected_var in diag.remedy


def test_auth_remedy_bedrock_names_aws_vars() -> None:
    diag = classify_provider_error(_make("AuthenticationError"), provider="bedrock")
    assert "AWS_ACCESS_KEY_ID" in diag.remedy and "AWS_SECRET_ACCESS_KEY" in diag.remedy


def test_auth_remedy_honours_env_var_override() -> None:
    diag = classify_provider_error(
        _make("AuthenticationError"), provider="openai", env_var_override="MY_CUSTOM_KEY"
    )
    assert "MY_CUSTOM_KEY" in diag.remedy


def test_typed_exceptions_map_to_categories() -> None:
    assert classify_provider_error(_make("RateLimitError")).category == "rate_limit"
    assert classify_provider_error(_make("APIConnectionError")).category in {"network", "tls"}
    assert classify_provider_error(_make("ContextWindowExceededError")).category == "context_window"


def test_tls_wrapped_in_connection_error_is_tls_not_network() -> None:
    exc = RuntimeError("APIConnectionError - [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer")
    assert classify_provider_error(exc).category == "tls"


# --- provider inference -----------------------------------------------------


def test_provider_from_model() -> None:
    assert provider_from_model("gpt-4o", declared="openai") == "openai"
    assert provider_from_model("anthropic/claude-haiku-4-5") == "anthropic"
    assert provider_from_model("gemini/gemini-1.5-pro") == "google"  # normalised
    assert provider_from_model("totally-made-up-model-xyz") is None  # get_llm_provider raises → None


def test_env_vars_for() -> None:
    assert env_vars_for("openai") == ("OPENAI_API_KEY",)
    assert env_vars_for("bedrock") == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    assert env_vars_for("ollama") == ()
    assert env_vars_for("openai", override="X") == ("X",)
    assert env_vars_for(None) == ()
