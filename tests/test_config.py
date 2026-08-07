"""Config schema sanity checks.

``MyloniteSettings``/``LLMConfig`` were deleted in 0.7.9 (T14/H3) -- a
repo-wide grep found zero real ``src/`` call sites; ``RunConfig`` +
:func:`mylonite.config.require_llm_configured` are the live replacement
for the "no default provider, fail loudly" invariant they used to (on
paper) provide.
"""

from __future__ import annotations

import pytest

from mylonite.config import (
    AuthorizationConfig,
    LLMNotConfiguredError,
    LoggingConfig,
    RunConfig,
    env_run_config,
    load_run_config,
    require_llm_configured,
)
from mylonite.scan.llm_policy import CredentialedApiBaseError


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
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert load_run_config(empty).provider is None  # all fields default to None

    partial = tmp_path / "partial.yaml"
    partial.write_text("provider: openai\n", encoding="utf-8")
    rc = load_run_config(partial)
    assert rc.provider == "openai"
    assert rc.target_file is None


def test_run_config_rejects_unknown_key(tmp_path):
    from pydantic import ValidationError

    bad = tmp_path / "bad.yaml"
    bad.write_text("bogus_key: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_run_config(bad)


# --- T14/H3: RunConfig extension (role models + LLMPolicy fields) -----------


def test_run_config_accepts_role_models_and_policy_fields(tmp_path):
    cfg = tmp_path / "mylonite.yaml"
    cfg.write_text(
        "model: claude-sonnet-4-6\n"
        "planner_model: claude-opus-4-1\n"
        "customiser_model: claude-opus-4-1\n"
        "judge_model: claude-haiku-4-5\n"
        "api_base: https://my-proxy.internal/v1\n"
        "max_tokens: 4096\n"
        "temperature: 0.2\n"
        "timeout: 90\n"
        "num_retries: 3\n"
        "root: .mylonite-custom\n",
        encoding="utf-8",
    )
    rc = load_run_config(cfg)
    assert rc.planner_model == "claude-opus-4-1"
    assert rc.customiser_model == "claude-opus-4-1"
    assert rc.judge_model == "claude-haiku-4-5"
    assert rc.api_base == "https://my-proxy.internal/v1"
    assert rc.max_tokens == 4096
    assert rc.temperature == 0.2
    assert rc.timeout == 90
    assert rc.num_retries == 3
    assert str(rc.root) == ".mylonite-custom"


# --- T14/CEO §3: credentialed api_base rejected ON LOAD ----------------------


@pytest.mark.parametrize(
    "api_base",
    [
        "https://user:pass@my-proxy.internal/v1",
        "https://my-proxy.internal/v1?api_key=sk-abc123",
    ],
)
def test_run_config_rejects_credentialed_api_base_on_load(tmp_path, api_base) -> None:
    from pydantic import ValidationError

    cfg = tmp_path / "mylonite.yaml"
    cfg.write_text(f"api_base: {api_base!r}\n", encoding="utf-8")
    with pytest.raises(ValidationError) as excinfo:
        load_run_config(cfg)
    assert "env var" in str(excinfo.value)


def test_run_config_direct_construction_also_rejects_credentialed_api_base() -> None:
    from pydantic import ValidationError

    # Pydantic wraps the field_validator's raised CredentialedApiBaseError in
    # its own ValidationError; the underlying message (and env-var pointer)
    # still surfaces.
    with pytest.raises(ValidationError) as excinfo:
        RunConfig(api_base="https://user:pass@my-proxy.internal/v1")
    assert "env var" in str(excinfo.value)


# --- T14/H3: require_llm_configured (the surviving require_llm() invariant) -


def test_require_llm_configured_raises_when_no_credential_anywhere(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMNotConfiguredError) as excinfo:
        require_llm_configured(model="claude-sonnet-4-6")
    msg = str(excinfo.value)
    assert "ANTHROPIC_API_KEY" in msg
    assert "--model" in msg or "mylonite.yaml" in msg


def test_require_llm_configured_passes_when_key_set(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    require_llm_configured(model="claude-sonnet-4-6")  # must not raise


def test_require_llm_configured_passes_for_a_local_provider(monkeypatch) -> None:
    """ollama/vllm/a litellm-proxy need no API key -- must never be flagged."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    require_llm_configured(model="ollama/llama3")  # must not raise


def test_require_llm_configured_passes_for_an_unrecognised_model(monkeypatch) -> None:
    """An unroutable/unknown model is ModelRef's problem, not this function's --
    it only asks 'is there evidently a credential', not 'is this a real model'."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    require_llm_configured(model="totally-unknown-model-xyz")  # must not raise


# --- T14: flat MYLONITE_* env vars (lowest-precedence source) ---------------


def test_env_run_config_reads_flat_mylonite_vars(monkeypatch) -> None:
    monkeypatch.setenv("MYLONITE_MODEL", "claude-opus-4-1")
    monkeypatch.setenv("MYLONITE_API_BASE", "https://my-proxy.internal/v1")
    monkeypatch.setenv("MYLONITE_MAX_TOKENS", "4096")
    monkeypatch.setenv("MYLONITE_TEMPERATURE", "0.3")
    monkeypatch.setenv("MYLONITE_PLANNER_MODEL", "claude-sonnet-4-6")
    rc = env_run_config()
    assert rc.model == "claude-opus-4-1"
    assert rc.api_base == "https://my-proxy.internal/v1"
    assert rc.max_tokens == 4096
    assert rc.temperature == 0.3
    assert rc.planner_model == "claude-sonnet-4-6"


def test_env_run_config_defaults_to_all_none(monkeypatch) -> None:
    for var in (
        "MYLONITE_MODEL",
        "MYLONITE_PROVIDER",
        "MYLONITE_PLANNER_MODEL",
        "MYLONITE_CUSTOMISER_MODEL",
        "MYLONITE_JUDGE_MODEL",
        "MYLONITE_API_BASE",
        "MYLONITE_MAX_TOKENS",
        "MYLONITE_TEMPERATURE",
        "MYLONITE_TIMEOUT",
        "MYLONITE_NUM_RETRIES",
    ):
        monkeypatch.delenv(var, raising=False)
    rc = env_run_config()
    assert rc == RunConfig()


def test_env_run_config_rejects_credentialed_api_base(monkeypatch) -> None:
    monkeypatch.setenv("MYLONITE_API_BASE", "https://user:pass@my-proxy.internal/v1")
    with pytest.raises(CredentialedApiBaseError):
        env_run_config()
