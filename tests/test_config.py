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


def test_run_config_round_trips(tmp_path):
    from pathlib import Path

    from mylonite.config import RunConfig, load_run_config

    cfg = tmp_path / "mylonite.yaml"
    cfg.write_text(
        "target_file: ./target.yaml\nauthorize: my-app\nprovider: anthropic\n"
        "model: claude-sonnet-4-6\nmax_llm_calls: 25\n",
        encoding="utf-8",
    )
    rc = load_run_config(cfg)
    assert rc == RunConfig(
        target_file=Path("./target.yaml"),
        authorize="my-app",
        provider="anthropic",
        model="claude-sonnet-4-6",
        max_llm_calls=25,
    )


def test_run_config_empty_and_partial(tmp_path):
    from mylonite.config import load_run_config

    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert load_run_config(empty).provider is None  # all fields default to None

    partial = tmp_path / "partial.yaml"
    partial.write_text("provider: openai\n", encoding="utf-8")
    rc = load_run_config(partial)
    assert rc.provider == "openai"
    assert rc.target_file is None


def test_run_config_rejects_unknown_key(tmp_path):
    import pytest
    from pydantic import ValidationError

    from mylonite.config import load_run_config

    bad = tmp_path / "bad.yaml"
    bad.write_text("bogus_key: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_run_config(bad)
