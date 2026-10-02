"""The approved-provider table -- one row per LLM provider Mylonite backs.

Before this module, "which providers does Mylonite support" had no single
answer: Anthropic defaults were hardcoded across ``cli.py``/``scaffold.py``/
``gate/mitigation.py``, the credential table in
:mod:`mylonite.scan.providers` only covered a handful of providers by hand,
and CI templates, docs and error messages each repeated their own partial
list. A provider LiteLLM happily routes but that wasn't in the hand-written
table (xAI, Groq, Mistral, DeepSeek, OpenRouter, ...) silently skipped the
credential preflight and failed deep inside a live call instead, with a
traceback instead of one clear line naming the missing credential.

This table is the one place that answers it. ``tier`` distinguishes
providers Mylonite has run its own verification campaign against
(``measured``) from providers LiteLLM routes and Mylonite key-checks, but
without dedicated verification evidence yet (``supported``). Nothing here
is a *default* -- there is no default provider or model; a user always
chooses one (``--model``, ``mylonite.yaml``, or ``MYLONITE_MODEL``).

:data:`PROVIDERS` is the source of truth for provider identity and
credentials; :mod:`mylonite.scan.providers` derives its public
``PROVIDER_ENV_VARS``/``required_env_vars`` from it so existing importers
keep working unchanged. Model literals are allowed in this module only --
nowhere else in the codebase should hardcode a model id (a later PR in this
same track removes the ones that currently do).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProviderTier = Literal["measured", "supported"]


@dataclass(frozen=True)
class ProviderInfo:
    """One approved provider: how to route to it, what credentials it
    needs, and how much verification evidence backs it.

    ``key_env`` is the bare API-key variable(s) -- the ONLY thing
    :mod:`mylonite.scan.providers`'s ``PROVIDER_ENV_VARS`` (and the
    ``doctor`` key-shape sanity check that reads it) should ever see.
    ``extra_env`` is anything else LiteLLM needs to actually route a call
    beyond the key (Azure's endpoint + API version) -- never key-shaped, so
    kept in a separate field rather than folded into ``key_env``.
    ``extra_headers`` names any HTTP header (beyond a bare API key) a
    provider needs on every request, e.g. an Anthropic workspace id -- empty
    for every row here; wiring an actual ``--llm-header``/env-var path for
    one is a later PR in this track.

    ``key_env_alternatives`` lists OTHER sets of env vars that, on their own,
    are each independently sufficient proof of a credential for this
    provider -- every set (the canonical ``key_env`` plus each of these) is
    checked with ALL-of-its-own-vars-present, and the provider is considered
    configured if ANY one set is fully present. Bedrock is the motivating
    case: AWS's credential chain accepts a static access/secret keypair, OR
    a named ``AWS_PROFILE``, OR an AWS Bedrock API key/bearer token, OR an
    OIDC role (the env-detectable form: ``AWS_ROLE_ARN`` +
    ``AWS_WEB_IDENTITY_TOKEN_FILE``) -- requiring the static pair alone
    rejected every other legitimate form. Empty for every other row here
    (their one ``key_env`` set is the only form).
    """

    id: str
    tier: ProviderTier
    model_prefix: str
    key_env: tuple[str, ...]
    extra_env: tuple[str, ...] = ()
    extra_headers: tuple[str, ...] = ()
    example_model: str | None = None
    local: bool = False
    key_env_alternatives: tuple[tuple[str, ...], ...] = ()


PROVIDERS: dict[str, ProviderInfo] = {
    "anthropic": ProviderInfo(
        id="anthropic",
        tier="measured",
        model_prefix="anthropic/",
        key_env=("ANTHROPIC_API_KEY",),
        example_model="anthropic/claude-haiku-4-5-20251001",
    ),
    "ollama": ProviderInfo(
        id="ollama",
        tier="measured",
        model_prefix="ollama_chat/",
        key_env=(),
        local=True,
    ),
    "openai": ProviderInfo(
        id="openai",
        tier="supported",
        model_prefix="openai/",
        key_env=("OPENAI_API_KEY",),
        # Left unset pending a pricing check on the small tier -- see the
        # provider registry PR series.
        example_model=None,
    ),
    "google": ProviderInfo(
        id="google",
        tier="supported",
        model_prefix="gemini/",
        key_env=("GEMINI_API_KEY",),  # GOOGLE_API_KEY is also accepted by LiteLLM
    ),
    "azure": ProviderInfo(
        id="azure",
        tier="supported",
        model_prefix="azure/",
        key_env=("AZURE_API_KEY",),
        extra_env=("AZURE_API_BASE", "AZURE_API_VERSION"),
    ),
    "bedrock": ProviderInfo(
        id="bedrock",
        tier="supported",
        model_prefix="bedrock/",
        # The static keypair is kept as the CANONICAL set (what an error
        # message/the docs show as "the" credential) -- but see
        # `key_env_alternatives` below: any ONE of several AWS credential
        # forms satisfies this provider, not just the static pair.
        key_env=("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        key_env_alternatives=(
            ("AWS_PROFILE",),
            ("AWS_BEARER_TOKEN_BEDROCK",),
            ("AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"),
        ),
    ),
    "vllm": ProviderInfo(
        id="vllm",
        tier="supported",
        model_prefix="hosted_vllm/",
        key_env=(),
        local=True,
    ),
    "litellm-proxy": ProviderInfo(
        id="litellm-proxy",
        tier="supported",
        model_prefix="litellm_proxy/",
        key_env=(),
    ),
    "vertex_ai": ProviderInfo(
        id="vertex_ai",
        tier="supported",
        model_prefix="vertex_ai/",
        # No bearer key: Vertex authenticates via Application Default
        # Credentials (gcloud's own file/metadata-based auth, not an env
        # var Mylonite can check for), so `key_env` stays empty. The project
        # + location pair IS a hard precondition LiteLLM's own
        # `validate_environment` checks for this provider, so it goes in
        # `extra_env`, the same way Azure's endpoint + API version do.
        key_env=(),
        extra_env=("VERTEXAI_PROJECT", "VERTEXAI_LOCATION"),
    ),
}
