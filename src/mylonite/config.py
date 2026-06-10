"""Typed runtime configuration for Mylonite.

The configuration object is intentionally strict:

* The LLM provider has **no default** — every consumer must declare one before
  any LLM call. Phase 0 does not call LLMs, but the schema is in place so
  Phase 1 callers fail loudly on misconfiguration rather than silently
  defaulting to a hosted model.
* Target authorization is opt-in per scan: ``AuthorizationConfig.authorize``
  must be set to ``True`` and the target hostname/identifier must appear in
  ``allowed_targets`` for any tool that touches a target.
* Logging defaults to redacting secret-shaped tokens from log records and
  rendered CLI reports (see ``LoggingConfig`` and ``mylonite._redaction``).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

LlmProvider = Literal[
    "anthropic",
    "openai",
    "azure",
    "bedrock",
    "google",
    "ollama",
    "vllm",
    "litellm-proxy",
    "stub",
]


class LLMConfig(BaseModel):
    """LLM provider config, consumed by every LiteLLM call site.

    No default provider: callers must pick one. This avoids the failure mode
    where a misconfigured Mylonite silently fans out to a hosted provider the
    user did not intend.
    """

    model_config = ConfigDict(extra="forbid")

    provider: LlmProvider = Field(
        ...,
        description="LiteLLM provider id. Required; no default.",
    )
    model: str = Field(
        ...,
        description="Model identifier passed to LiteLLM (e.g. 'claude-sonnet-4-6').",
    )
    base_url: str | None = Field(
        default=None,
        description="Override base URL for self-hosted or proxy endpoints.",
    )
    api_key_env_var: str | None = Field(
        default=None,
        description="Name of the env var holding the provider API key, if any.",
    )


class AuthorizationConfig(BaseModel):
    """Per-scan authorization gate.

    Mylonite refuses to run against an unauthorized target. See ``SECURITY.md``.
    """

    model_config = ConfigDict(extra="forbid")

    authorize: bool = Field(
        default=False,
        description="Master switch. Must be True for any target-touching command.",
    )
    allowed_targets: list[str] = Field(
        default_factory=list,
        description="Hostnames, URLs, or local paths the user asserts ownership of.",
    )


class LoggingConfig(BaseModel):
    """Logging behaviour.

    Defaults err on the side of caution. When ``redact_secrets`` is on (the
    default), the CLI installs a redacting filter on the ``mylonite`` logger tree
    so secret-shaped tokens (provider key prefixes, AWS access-key ids, bearer
    tokens, PEM private-key blocks, ``key=value`` credential assignments) are
    masked out of every log record, and the rendered CLI scan/report strings are
    redacted before they are echoed. See ``mylonite._redaction``.

    Persisted replay fixtures, ``exploit_*.json`` / ``scan_report.json``
    artefacts, and generated test source are deterministic and contain no raw
    provider secrets by construction; redaction is intentionally NOT applied to
    them so they stay loadable and replayable. Library users who want to disable
    the log filter can call ``mylonite._redaction.install_log_redaction(False)``.
    """

    model_config = ConfigDict(extra="forbid")

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    redact_secrets: bool = True


class MyloniteSettings(BaseSettings):
    """Top-level settings object.

    Loaded from environment variables (``MYLONITE_*``) or an explicit
    YAML/JSON file passed via the CLI. Nested models are flattened with a
    double underscore delimiter — e.g. ``MYLONITE_LLM__PROVIDER=anthropic``.
    """

    model_config = SettingsConfigDict(
        env_prefix="MYLONITE_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    llm: LLMConfig | None = None
    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def require_llm(self) -> LLMConfig:
        """Return the LLM config or raise.

        Phase 1+ call sites use this so the error surfaces at the call site
        rather than as a confusing ``None`` later.
        """
        if self.llm is None:
            msg = (
                "No LLM provider configured. Set MYLONITE_LLM__PROVIDER, "
                "MYLONITE_LLM__MODEL, and (if applicable) MYLONITE_LLM__API_KEY_ENV_VAR, "
                "or pass --config pointing at a config file. See .env.example."
            )
            raise RuntimeError(msg)
        return self.llm
