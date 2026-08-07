"""Typed runtime configuration for Mylonite.

The configuration object is intentionally strict:

* The LLM provider has **no default** — every consumer must declare one before
  Call sites fail loudly on misconfiguration rather than silently
  defaulting to a hosted model. See :func:`require_llm_configured`.
* Target authorization is opt-in per scan: ``AuthorizationConfig.authorize``
  must be set to ``True`` and the target hostname/identifier must appear in
  ``allowed_targets`` for any tool that touches a target.
* Logging defaults to redacting secret-shaped tokens from log records and
  rendered CLI reports (see ``LoggingConfig`` and ``mylonite._redaction``).

``MyloniteSettings``/``LLMConfig`` (a ``pydantic-settings`` object keyed off
``MYLONITE_LLM__PROVIDER``/``MYLONITE_LLM__MODEL``) were deleted in 0.7.9
(T14/H3): a repo-wide search found zero ``src/`` call sites — every live
command resolves its model/provider through
:class:`~mylonite.scan.model_ref.ModelRef` and :class:`RunConfig` below
instead, and nothing exported it. Reviving a third, unreachable config path
with its own (never-set) env-var spelling would have been worse than
deleting it outright. ``RunConfig`` (``mylonite.yaml``) is the one
declarative config surface; :func:`require_llm_configured` is the one place
the "no default provider, fail loudly" invariant its docstring described is
actually enforced at runtime.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mylonite.scan.llm_policy import validate_api_base


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


class RunConfig(BaseModel):
    """Declarative run configuration (``mylonite.yaml``).

    One file that threads a run so the same flags need not be re-passed across
    ``scan`` / ``generate`` / ``validate`` / ``gate`` / ``ablate`` — single-file
    run ergonomics. Every field is optional and an explicit CLI flag always
    wins; a field left unset simply doesn't override the command default.
    ``mylonite.yaml`` is auto-discovered from the current directory by every
    command that accepts ``--config`` (T14 generalised this from a
    ``gate``-only behaviour). Example::

        target_file: ./target.yaml
        authorize: my-app
        provider: anthropic
        model: claude-sonnet-4-6
        planner_model: claude-opus-4-1
        max_llm_calls: 50
        api_base: https://my-litellm-proxy.internal/v1
        max_tokens: 4096
        temperature: 0.0
        timeout: 90
        num_retries: 3
        root: .mylonite-custom
    """

    model_config = ConfigDict(extra="forbid")

    target_file: Path | None = Field(
        default=None, description="Path to the custom-target YAML (the `--target-file`)."
    )
    authorize: str | None = Field(
        default=None, description="Ownership assertion for a custom/non-reference target."
    )
    provider: str | None = Field(
        default=None,
        description="LiteLLM provider id. DEPRECATED -- prefix `model` instead.",
    )
    model: str | None = Field(default=None, description="Model identifier passed to LiteLLM.")
    planner_model: str | None = Field(
        default=None,
        description="Model that DRIVES the agent-under-test (the planner). Defaults to `model`.",
    )
    customiser_model: str | None = Field(
        default=None,
        description="Model that crafts/refines attack payloads. Defaults to `model`.",
    )
    judge_model: str | None = Field(
        default=None,
        description="Model for the LLM-judge verdict fallback. Defaults to `model`.",
    )
    max_llm_calls: int | None = Field(
        default=None, ge=1, description="Process-wide LLM call cap (budget) for a scan."
    )
    api_base: str | None = Field(
        default=None,
        description=(
            "Override base URL for a self-hosted/proxy LiteLLM endpoint (Ollama, "
            "vLLM, a corporate LiteLLM proxy/gateway, ...). MUST NOT embed a "
            "credential (no userinfo, no key-shaped query param) -- mylonite.yaml "
            "is a COMMITTED file; put the credential in an env var instead. "
            "Validated on load -- see `validate_api_base`."
        ),
    )
    max_tokens: int | None = Field(
        default=None, ge=1, description="Per-call max_tokens passed to every LiteLLM completion."
    )
    temperature: float | None = Field(
        default=None,
        ge=0.0,
        description="Per-call temperature. The oracle's rate-gap measurement assumes 0.0.",
    )
    timeout: float | None = Field(
        default=None, gt=0, description="Per-call socket-level timeout (seconds)."
    )
    num_retries: int | None = Field(default=None, ge=0, description="Per-call LiteLLM retry count.")
    root: Path | None = Field(
        default=None,
        description=(
            "Override the artefact root (replaces the built-in default root every "
            "command's scans/generated/gate artefacts nest under). An explicit "
            "--output-dir/--out flag still wins; this in turn wins over the "
            "MYLONITE_ROOT env var. See mylonite.layout.Layout."
        ),
    )

    @field_validator("api_base")
    @classmethod
    def _reject_credentialed_api_base(cls, value: str | None) -> str | None:
        """Validate on load (CEO §3): a credentialed api_base in a COMMITTED
        mylonite.yaml would leak the secret into version control. Raises
        (surfacing as a ``ValidationError`` from ``load_run_config``, which the
        CLI maps to ``EXIT_CONFIG``) rather than silently stripping or
        silently allowing it. See ``mylonite.scan.llm_policy.validate_api_base``
        — the SAME check ``LLMPolicy`` itself runs on construction, so this is
        defense in depth (catches it at yaml-load time too), not the only gate.
        """
        validate_api_base(value)
        return value


def load_run_config(path: Path) -> RunConfig:
    """Parse a ``mylonite.yaml`` run config into a validated :class:`RunConfig`."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if data is None:
        return RunConfig()
    if not isinstance(data, dict):
        msg = f"run config {path} must contain a YAML mapping at the top level"
        raise ValueError(msg)
    return RunConfig.model_validate(data)


#: Flat ``MYLONITE_*`` env vars (T14) — the SAME naming convention already
#: used elsewhere in the codebase (``MYLONITE_ROOT``, ``MYLONITE_NO_TRUSTSTORE``,
#: ``MYLONITE_LIVE_TARGET``) rather than the deleted ``MyloniteSettings``'
#: ``pydantic-settings`` double-underscore nesting (``MYLONITE_LLM__PROVIDER``),
#: which nothing ever actually set. Lowest-precedence source in every command's
#: resolution order: explicit CLI flag > mylonite.yaml > this env var > the
#: command's own built-in default.
class _EnvRunConfig(BaseSettings):
    """Reads the flat ``MYLONITE_*`` env vars into ``RunConfig``-shaped fields.

    A separate ``pydantic-settings`` object (not merged into ``RunConfig``
    itself) because ``RunConfig`` also has a non-settings use — parsing an
    arbitrary ``mylonite.yaml`` file — and ``extra="forbid"`` there must keep
    rejecting an unrecognised YAML key without also trying to interpret it as
    an env var name.
    """

    model_config = SettingsConfigDict(env_prefix="MYLONITE_", extra="ignore")

    model: str | None = None
    provider: str | None = None
    planner_model: str | None = None
    customiser_model: str | None = None
    judge_model: str | None = None
    api_base: str | None = None
    max_tokens: int | None = None
    temperature: float | None = None
    timeout: float | None = None
    num_retries: int | None = None


def env_run_config() -> RunConfig:
    """The subset of :class:`RunConfig` fillable from flat ``MYLONITE_*`` env
    vars (``MYLONITE_MODEL``, ``MYLONITE_API_BASE``, ``MYLONITE_PLANNER_MODEL``,
    ...) — the lowest-precedence source in a command's resolution order, above
    only the command's own hardcoded default.

    Validates ``api_base`` the same way :class:`RunConfig` does (raises
    :class:`~mylonite.scan.llm_policy.CredentialedApiBaseError` on a
    credentialed value) — an env var is a less likely leak path than a
    committed ``mylonite.yaml``, but a shell history / CI job log can still
    persist it, so the same hard rejection applies.
    """
    env = _EnvRunConfig()
    validate_api_base(env.api_base)
    return RunConfig(
        model=env.model,
        provider=env.provider,
        planner_model=env.planner_model,
        customiser_model=env.customiser_model,
        judge_model=env.judge_model,
        api_base=env.api_base,
        max_tokens=env.max_tokens,
        temperature=env.temperature,
        timeout=env.timeout,
        num_retries=env.num_retries,
    )


class LLMNotConfiguredError(RuntimeError):
    """Raised by :func:`require_llm_configured` when no credential is
    resolvable for the effective provider.

    Mirrors the deleted ``MyloniteSettings.require_llm()``'s intent (CLAUDE.md:
    "There is no default provider ... `require_llm()` raises if one isn't
    set") as a REAL runtime check in the config-resolution path every live
    command actually goes through, rather than a class nothing called.
    """


def require_llm_configured(*, model: str, provider: str | None = None) -> None:
    """Raise :class:`LLMNotConfiguredError` when no credential is resolvable
    for ``model``'s effective provider.

    A local/self-hosted/proxy provider (ollama, vllm, a litellm-proxy — see
    ``scan.providers.PROVIDER_ENV_VARS``) needs no key and always passes. An
    unrecognised model/provider also passes (nothing to check) — deliberately
    permissive there, since ``ModelRef``/LiteLLM itself is the source of
    truth for "is this a valid model", not this function; this only checks
    "is there evidently a credential for it", the narrower question the
    deleted ``require_llm()`` asked.

    Uses :func:`~mylonite.scan.providers.required_env_vars` (the key PLUS
    anything else LiteLLM needs to actually route a call, e.g. Azure's
    endpoint/API-version pair) and requires ALL of them to be set, not just
    one — ``env_vars_for`` alone plus an ``any()`` check would (a) pass a
    Bedrock setup with only ``AWS_ACCESS_KEY_ID`` set, silently missing the
    also-required ``AWS_SECRET_ACCESS_KEY`` (every current
    ``PROVIDER_ENV_VARS`` entry with more than one var means ALL of them are
    required together, never "any one of"), and (b) pass an Azure setup with
    only ``AZURE_API_KEY`` set, which still fails the live call this
    pre-flight exists to prevent because ``AZURE_API_BASE``/
    ``AZURE_API_VERSION`` are also unset.
    """
    from mylonite.scan.providers import provider_from_model, required_env_vars

    resolved = provider_from_model(model, declared=provider)
    needed = required_env_vars(resolved)
    if not needed:
        return
    missing = [var for var in needed if not os.environ.get(var)]
    if not missing:
        return
    msg = (
        f"no LLM credential configured for model {model!r} (resolved provider: "
        f"{resolved or 'unknown'}). Missing: {', '.join(missing)} "
        "-- via your shell env, --api-key-file, --env-file, or a CI secret -- "
        "or point --model/--provider (or mylonite.yaml's model:/provider:) at "
        "a provider that IS configured."
    )
    raise LLMNotConfiguredError(msg)
