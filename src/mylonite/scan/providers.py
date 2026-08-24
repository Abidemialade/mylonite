"""Provider identity → API-key env var mapping (cross-LLM).

So error remedies name the RIGHT environment variable for whichever provider
is in use — not always ``ANTHROPIC_API_KEY``. Kept apart
from ``config.py`` (pure schema) and ``diagnostics.py`` to avoid import cycles;
both import from here.
"""

from __future__ import annotations

import re

import litellm

# Default API-key env var(s) per provider. Bedrock uses the AWS credential
# chain (two vars); local servers (ollama/vllm) and a litellm proxy need none.
# This is the "explicit map" layer: it stays a CLOSED, hand-maintained set
# deliberately (used by `doctor`'s key-SHAPE sanity check, which must only
# look at vars that are actually meant to hold a secret key -- see
# `required_env_vars` below for the broader "everything this provider needs"
# view, which is NOT scoped the same way). New providers not yet added here
# still get picked up by `looks_like_provider_env_var`'s pattern matching --
# see its docstring for why an allowlist alone silently drops keys.
PROVIDER_ENV_VARS: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "azure": ("AZURE_API_KEY",),
    "google": ("GEMINI_API_KEY",),  # GOOGLE_API_KEY is also accepted by LiteLLM
    "bedrock": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    "ollama": (),
    "vllm": (),
    "litellm-proxy": (),
    "stub": (),
}

# Vars a provider needs BEYOND the bare API key to actually route a call --
# e.g. Azure also needs its endpoint + API version (LiteLLM reads
# AZURE_API_BASE / AZURE_API_VERSION alongside AZURE_API_KEY). Kept separate
# from PROVIDER_ENV_VARS (rather than folded in) because that map also backs
# `doctor`'s "does this look like an API key" sanity check -- a URL or a
# version string never looks key-shaped, so checking it there would be a
# false-positive warning, not a real diagnostic.
_EXTRA_ENV_VARS: dict[str, tuple[str, ...]] = {
    "azure": ("AZURE_API_BASE", "AZURE_API_VERSION"),
}

# Pattern layer for `looks_like_provider_env_var` (the env-file/`--env-file`
# funnel): LiteLLM's own convention for a provider's credential var is
# `<PROVIDER>_API_KEY` (confirmed against the installed litellm package for
# Groq/Mistral/DeepSeek/OpenRouter, none of which are in PROVIDER_ENV_VARS
# above), plus the Azure family's `AZURE_*` vars (key/base/version/ad-token).
_RE_API_KEY_VAR: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_API_KEY$")
_RE_AZURE_VAR: re.Pattern[str] = re.compile(r"^AZURE_[A-Z0-9_]+$")

# LiteLLM's internal provider spellings differ from our config Literal
# (``gemini`` vs ``google``, ``litellm_proxy`` vs ``litellm-proxy``); normalise
# both into the keys of PROVIDER_ENV_VARS.
_ALIASES: dict[str, str] = {
    "gemini": "google",
    "vertex_ai": "google",
    "google": "google",
    "litellm_proxy": "litellm-proxy",
    "litellm-proxy": "litellm-proxy",
    "azure_ai": "azure",
}


def _normalise_provider(name: str | None) -> str | None:
    if not name:
        return None
    n = name.strip().lower()
    return _ALIASES.get(n, n)


def provider_from_model(model: str, declared: str | None = None) -> str | None:
    """Best-effort provider id for ``model``: declared flag → ``provider/`` prefix → LiteLLM.

    ``litellm.get_llm_provider`` RAISES (``BadRequestError``) on a truly-unknown
    model, so it is guarded — an unknown model yields ``None`` and callers fall
    back to a generic remedy.
    """
    if declared:
        return _normalise_provider(declared)
    if "/" in model:
        return _normalise_provider(model.split("/", 1)[0])
    try:
        provider = litellm.get_llm_provider(model=model)[1]
    except Exception:
        return None
    return _normalise_provider(provider)


def env_vars_for(provider: str | None, override: str | None = None) -> tuple[str, ...]:
    """Env var name(s) holding the API key for ``provider``.

    ``override`` (an explicit non-default credential env var name) wins when
    set; otherwise the map is consulted; an unknown provider yields ``()``.
    """
    if override:
        return (override,)
    p = _normalise_provider(provider)
    if p is None:
        return ()
    return PROVIDER_ENV_VARS.get(p, ())


def required_env_vars(provider: str | None, override: str | None = None) -> tuple[str, ...]:
    """Every env var ``provider`` needs to actually route a call -- the API
    key (:func:`env_vars_for`) plus anything else LiteLLM reads for it, e.g.
    Azure's endpoint + API version. This is what :meth:`ModelRef.env_vars`
    reports; ``doctor``'s key-shape check deliberately keeps using
    ``env_vars_for`` instead (see :data:`_EXTRA_ENV_VARS`'s docstring).
    """
    base = env_vars_for(provider, override)
    p = _normalise_provider(provider)
    if p is None:
        return base
    return base + _EXTRA_ENV_VARS.get(p, ())


def looks_like_provider_env_var(key: str) -> bool:
    """True if ``key`` is a recognised provider credential/config env var --
    pattern-based, not a closed allowlist.

    The env-file loader (``mylonite.cli._load_env_file``) used to accept ONLY
    names appearing somewhere in :data:`PROVIDER_ENV_VARS` -- a ~9-entry map
    covering just anthropic/openai/azure/google/bedrock/ollama/vllm/
    litellm-proxy/stub. Any other provider's key (Groq, Mistral, DeepSeek,
    OpenRouter, ...) was SILENTLY dropped, and Azure's ``AZURE_API_BASE`` /
    ``AZURE_API_VERSION`` were dropped too (only ``AZURE_API_KEY`` was in the
    map) -- the same closed-allowlist-that-cannot-fail-loudly shape as the
    ``NOT_TESTED_OUTCOMES`` bug.

    Recognises ``<PROVIDER>_API_KEY`` (LiteLLM's own convention -- confirmed
    against the installed package for Groq/Mistral/DeepSeek/OpenRouter) and
    the ``AZURE_*`` family, PLUS anything already in :data:`PROVIDER_ENV_VARS`
    (covers AWS's two-var Bedrock credential pair, which doesn't match either
    pattern). Callers that reject an unmatched key should still report it
    (never drop silently) -- this function only answers "known or not".

    Accepted tradeoff: the ``*_API_KEY`` pattern is intentionally broader
    than "known LLM provider" -- it also matches an unrelated credential
    that happens to be shaped the same way (e.g. ``STRIPE_API_KEY`` sitting
    in a ``.env`` reused from a wider project) and `_load_env_file` WILL load
    it. This trades the old allowlist's narrower false-negative surface
    (silently dropping a real, unlisted provider key) for a broader
    false-positive one; `_load_env_file` echoes every loaded key to stderr,
    so an interactive operator sees it happen, but a non-interactive/CI
    invocation may not have anyone reading that line.
    """
    if _RE_API_KEY_VAR.match(key) or _RE_AZURE_VAR.match(key):
        return True
    return any(key in variables for variables in PROVIDER_ENV_VARS.values())
