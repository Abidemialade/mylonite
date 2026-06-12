"""Provider identity → API-key env var mapping (cross-LLM).

So error remedies and ``mylonite doctor`` name the RIGHT environment variable
for whichever provider is in use — not always ``ANTHROPIC_API_KEY``. Kept apart
from ``config.py`` (pure schema) and ``diagnostics.py`` to avoid import cycles;
both import from here.
"""

from __future__ import annotations

import litellm

# Default API-key env var(s) per provider. Bedrock uses the AWS credential
# chain (two vars); local servers (ollama/vllm) and a litellm proxy need none.
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

    ``override`` (from ``LLMConfig.api_key_env_var``) wins when set; otherwise
    the map is consulted; an unknown provider yields ``()``.
    """
    if override:
        return (override,)
    p = _normalise_provider(provider)
    if p is None:
        return ()
    return PROVIDER_ENV_VARS.get(p, ())
