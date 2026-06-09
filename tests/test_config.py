"""Config schema sanity checks."""

from __future__ import annotations

import pytest

from mylonite.config import (
    AuthorizationConfig,
    LLMConfig,
    LoggingConfig,
    MyloniteSettings,
)


def test_llm_provider_required() -> None:
    with pytest.raises(ValueError):
        LLMConfig()  # type: ignore[call-arg]


def test_llm_provider_accepts_known() -> None:
    cfg = LLMConfig(provider="anthropic", model="claude-sonnet-4-6")
    assert cfg.provider == "anthropic"
    assert cfg.model == "claude-sonnet-4-6"


def test_require_llm_raises_when_missing() -> None:
    settings = MyloniteSettings()
    assert settings.llm is None
    with pytest.raises(RuntimeError, match="No LLM provider configured"):
        settings.require_llm()


def test_require_llm_returns_when_set() -> None:
    settings = MyloniteSettings(
        llm=LLMConfig(provider="stub", model="stub-model"),
    )
    assert settings.require_llm().provider == "stub"


def test_authorization_defaults_to_off() -> None:
    cfg = AuthorizationConfig()
    assert cfg.authorize is False
    assert cfg.allowed_targets == []


def test_logging_defaults_redact() -> None:
    cfg = LoggingConfig()
    assert cfg.redact_secrets is True
    assert cfg.level == "INFO"
