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
    ``extra_headers`` names any HTTP header (beyond a bare API key) some keys
    for this provider need on every request, e.g. the workspace id an
    unscoped Anthropic key needs. Mylonite never sends one on its own: the
    operator supplies the value with ``--llm-header NAME=VALUE`` or
    ``MYLONITE_LLM_HEADERS``, and the name here is what the "header
    required" error line tells them to pass.

    ``key_env_alternatives`` lists OTHER sets of env vars that, on their own,
    are each independently sufficient proof of a credential for this
    provider -- every set (the canonical ``key_env`` plus each of these) is
    checked with ALL-of-its-own-vars-present, and the provider is considered
    configured if ANY one set is fully present. Bedrock is the motivating
    case: AWS's credential chain accepts a static access/secret keypair, OR
    a named ``AWS_PROFILE``, OR an AWS Bedrock API key/bearer token, OR an
    OIDC role (the env-detectable form: ``AWS_ROLE_ARN`` +
    ``AWS_WEB_IDENTITY_TOKEN_FILE``), OR a container role (ECS/CodeBuild:
    ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` or ``_FULL_URI``) --
    requiring the static pair alone rejected every other legitimate form.
    Empty for every other row here (their one ``key_env`` set is the only
    form).

    ``optional_env`` names vars this provider's SDK/LiteLLM route reads but
    doesn't strictly require (Bedrock's region, an OpenAI-compatible base
    URL) -- recognised so ``--env-file``/``looks_like_provider_env_var``
    load them, but never a hard precondition the way ``key_env``/
    ``extra_env`` are.

    ``credential_best_effort`` marks a provider whose REAL credential chain
    has forms with NO environment-variable footprint at all -- Bedrock's
    default ``~/.aws`` profile (no ``AWS_PROFILE`` set), an active SSO
    session, and the EC2 instance-metadata role are all genuine, working
    credentials that no env-var check can ever see. For such a provider,
    none of ``key_env``/``key_env_alternatives`` matching is advisory, never
    a hard failure: the caller prints one line naming what WAS checked and
    proceeds, leaving the real failure (if there is one) to the provider's
    own auth preflight or first call. ``False`` for every other row, where
    the checked forms genuinely are the complete set of ways to configure
    the provider.
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
    optional_env: tuple[str, ...] = ()
    credential_best_effort: bool = False


PROVIDERS: dict[str, ProviderInfo] = {
    "anthropic": ProviderInfo(
        id="anthropic",
        tier="measured",
        model_prefix="anthropic/",
        key_env=("ANTHROPIC_API_KEY",),
        extra_headers=("anthropic-workspace-id",),
        example_model="anthropic/claude-haiku-4-5-20251001",
    ),
    "ollama": ProviderInfo(
        id="ollama",
        tier="measured",
        model_prefix="ollama_chat/",
        key_env=(),
        local=True,
        # The no-key workaround every other provider's missing-credential
        # message points at (``LOCAL_MODEL_HINT`` in scan/providers.py) --
        # kept here, not hardcoded at the call site, so it can't drift from
        # this row's own `model_prefix`.
        example_model="ollama_chat/llama3.2:3b",
    ),
    "openai": ProviderInfo(
        id="openai",
        tier="supported",
        model_prefix="openai/",
        key_env=("OPENAI_API_KEY",),
        # Left unset pending a pricing check on the small tier -- see the
        # provider registry PR series.
        example_model=None,
        # An OpenAI-compatible endpoint (a local vLLM/Ollama shim, a
        # gateway) -- recognised so --env-file loads it, never required.
        optional_env=("OPENAI_API_BASE",),
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
        # forms satisfies this provider, not just the static pair. AND see
        # `credential_best_effort=True`: AWS's credential chain also has
        # forms (a default ~/.aws profile with no AWS_PROFILE set, SSO, the
        # EC2/ECS/CodeBuild instance role) that leave NO env var at all to
        # check -- so even when none of these match, Mylonite warns and
        # proceeds rather than blocking a configuration it cannot see.
        key_env=("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        key_env_alternatives=(
            ("AWS_PROFILE",),
            ("AWS_BEARER_TOKEN_BEDROCK",),
            ("AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"),
            ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",),
            ("AWS_CONTAINER_CREDENTIALS_FULL_URI",),
        ),
        # LiteLLM defaults the region, so it's optional -- but it ships in
        # .env.example and --env-file used to reject it.
        optional_env=("AWS_REGION_NAME",),
        credential_best_effort=True,
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

#: LiteLLM provider-id spellings that route to an approved row here but
#: aren't that row's own ``model_prefix`` (confirmed against the installed
#: litellm package: ``azure_ai``/``bedrock_converse`` are documented
#: alternates, and ``ollama`` -- the legacy ``/api/generate`` route -- is
#: accepted alongside this registry's own ``ollama_chat/`` prefix). Exposed
#: here, as DATA, rather than re-derived or hand-copied, so both
#: :mod:`mylonite.scan.providers`'s alias table and
#: ``scripts/check_no_hardcoded_models.py``'s model-literal regex read the
#: SAME list instead of each keeping its own, independently incomplete one
#: -- the hand-maintained regex was missing ``ollama_chat/``, ``hosted_vllm/``,
#: ``gemini/``, ``azure/`` and ``vertex_ai/`` entirely before this existed.
EXTRA_ROUTING_ALIASES: dict[str, str] = {
    "azure_ai": "azure",
    "bedrock_converse": "bedrock",
    "ollama": "ollama",
}

#: Every provider-routing prefix a hardcoded model literal could use to
#: reach an approved provider: each row's own ``model_prefix`` plus the
#: aliases above, every one written with the trailing ``/`` it's prefixed
#: with (``"anthropic/"``, ``"ollama_chat/"``, ``"bedrock_converse/"``, ...).
ALL_MODEL_PREFIXES: tuple[str, ...] = tuple(
    info.model_prefix for info in PROVIDERS.values()
) + tuple(f"{alias}/" for alias in EXTRA_ROUTING_ALIASES)
