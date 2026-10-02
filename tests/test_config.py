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


#: Every Bedrock credential env var across every accepted form -- cleared
#: before each of the tests below so one form's ambient value in the test
#: environment can't make a DIFFERENT form's test pass by accident.
_ALL_BEDROCK_CREDENTIAL_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_PROFILE",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
)


def _clear_bedrock_credentials(monkeypatch) -> None:
    for var in _ALL_BEDROCK_CREDENTIAL_VARS:
        monkeypatch.delenv(var, raising=False)


def test_require_llm_configured_bedrock_never_blocks_on_a_half_complete_pair(monkeypatch) -> None:
    """Review follow-up: Bedrock is `credential_best_effort` -- AWS's real
    credential chain also includes a default ~/.aws profile, SSO, and
    instance/container roles with NO environment-variable footprint at all,
    so a check that can't see one of those must warn, never block. A
    half-complete static pair (one of the two vars set) is exactly as
    "no explicit form matched" as nothing being set at all -- it must not
    raise either, just warn and proceed."""
    _clear_bedrock_credentials(monkeypatch)

    warning = require_llm_configured(model="bedrock/anthropic.claude-3-sonnet")
    assert warning is not None
    assert "AWS_ACCESS_KEY_ID" in warning
    assert "AWS_SECRET_ACCESS_KEY" in warning

    # Only ONE of the two set -- still "no explicit form matched"; still a
    # warning, never a raise.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE")
    warning = require_llm_configured(model="bedrock/anthropic.claude-3-sonnet")
    assert warning is not None

    # BOTH set -- the static pair IS a complete form now: no warning at all.
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")
    assert require_llm_configured(model="bedrock/anthropic.claude-3-sonnet") is None


@pytest.mark.parametrize(
    ("env_vars"),
    [
        {"AWS_PROFILE": "my-named-profile"},
        {"AWS_BEARER_TOKEN_BEDROCK": "fake-bearer-token"},
        {
            "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/my-role",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/token",
        },
        {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/fake"},
        {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.2/v2/credentials/fake"},
    ],
    ids=["aws-profile", "bearer-token", "oidc-role-pair", "ecs-relative-uri", "ecs-full-uri"],
)
def test_require_llm_configured_bedrock_accepts_alternative_credential_forms(
    monkeypatch, env_vars: dict[str, str]
) -> None:
    """Registry review follow-up: AWS's credential chain accepts more than
    the static access/secret keypair -- a named profile, an API bearer
    token, an OIDC role, or an ECS/CodeBuild container role all legitimately
    configure Bedrock, and requiring the static pair specifically used to
    reject every one of them."""
    _clear_bedrock_credentials(monkeypatch)
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # A fully-matched explicit form -- no warning, nothing to proceed past.
    assert require_llm_configured(model="bedrock/anthropic.claude-3-sonnet") is None


def test_require_llm_configured_bedrock_with_no_credential_form_warns_and_proceeds(
    monkeypatch,
) -> None:
    """With nothing set, Bedrock never raises (review follow-up) -- it
    returns a one-line, non-fatal warning naming the CANONICAL (static-pair)
    form plus that alternatives exist, so the caller can print it and still
    proceed: a default ~/.aws profile, SSO, or an instance role may well be
    configured with no environment variable at all to prove it."""
    _clear_bedrock_credentials(monkeypatch)

    warning = require_llm_configured(model="bedrock/anthropic.claude-3-sonnet")
    assert warning is not None
    assert "AWS_ACCESS_KEY_ID" in warning
    assert "AWS_SECRET_ACCESS_KEY" in warning
    assert "AWS_PROFILE" in warning  # named as a checked alternative, not just silently omitted
    assert "proceeding" in warning.lower()


def test_require_llm_configured_azure_requires_base_and_version_too(monkeypatch) -> None:
    """Code-review follow-up: an Azure deployment needs its endpoint + API
    version alongside the key (LiteLLM reads AZURE_API_BASE/AZURE_API_VERSION
    too) -- required_env_vars (not env_vars_for alone) is what surfaces those,
    so an operator with only AZURE_API_KEY set is told what's ACTUALLY
    missing before burning a live call, not just told the key looks present."""
    monkeypatch.setenv("AZURE_API_KEY", "fake-azure-key")
    monkeypatch.delenv("AZURE_API_BASE", raising=False)
    monkeypatch.delenv("AZURE_API_VERSION", raising=False)

    with pytest.raises(LLMNotConfiguredError) as excinfo:
        require_llm_configured(model="azure/my-deployment")
    msg = str(excinfo.value)
    assert "AZURE_API_BASE" in msg
    assert "AZURE_API_VERSION" in msg
    assert "AZURE_API_KEY" not in msg  # already-set var not listed as missing

    monkeypatch.setenv("AZURE_API_BASE", "https://my-azure.openai.azure.com")
    monkeypatch.setenv("AZURE_API_VERSION", "2024-02-01")
    require_llm_configured(model="azure/my-deployment")  # must not raise


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
