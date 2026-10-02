"""Provider identity → API-key env var mapping (cross-LLM).

So error remedies name the RIGHT environment variable for whichever provider
is in use — not always ``ANTHROPIC_API_KEY``. Kept apart
from ``config.py`` (pure schema) and ``diagnostics.py`` to avoid import cycles;
both import from here.
"""

from __future__ import annotations

import re
import sys

from mylonite.providers.registry import PROVIDERS

# Bare API-key env var(s) per provider, read from the approved-provider
# registry (:mod:`mylonite.providers.registry`) -- that module is now the
# single source of truth; this name and shape stay the same so every
# existing importer (``doctor``'s key-SHAPE sanity check among them, which
# must only look at vars that are actually meant to hold a secret key --
# see `required_env_vars` below for the broader "everything this provider
# needs" view, which is NOT scoped the same way) keeps working unchanged.
# ``stub`` is a test-only sentinel provider (no real credential, ever) and
# isn't part of the approved registry, so it's added here explicitly.
PROVIDER_ENV_VARS: dict[str, tuple[str, ...]] = {
    provider_id: info.key_env for provider_id, info in PROVIDERS.items()
} | {"stub": ()}

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

#: OPTIONAL provider vars: recognised by :func:`looks_like_provider_env_var` so
#: ``--env-file`` will load them, but NOT required to route a call.
#:
#: Kept separate from :data:`_EXTRA_ENV_VARS` because that map feeds
#: :func:`required_env_vars`, and anything listed there becomes a HARD
#: precondition -- putting an optional var in it makes a working configuration
#: report as missing credentials. "Loadable" and "required" are different
#: questions and need different lists.
_OPTIONAL_ENV_VARS: tuple[str, ...] = (
    # Bedrock's region. LiteLLM defaults it, so it is optional -- but it ships
    # in .env.example and `--env-file` used to reject it.
    "AWS_REGION_NAME",
    # An OpenAI-compatible endpoint (a local vLLM/Ollama shim, a gateway). The
    # AZURE_* family got recognition for free from its own regex; OpenAI's
    # equivalent matched nothing.
    "OPENAI_API_BASE",
)

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
    # LiteLLM routes the same local server under two spellings: "ollama" (the
    # legacy /api/generate route) and "ollama_chat" (the /api/chat one we use).
    # Only the first matches our config id, so deriving a provider from an
    # `ollama_chat/...` model reported the route as if it were the provider —
    # visible in `demo --live`, which printed `live (ollama_chat/...)` for a run
    # whose provider is `ollama`, and stamped that into ScanReport.provider.
    "ollama_chat": "ollama",
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
    import litellm  # deferred: several seconds to import, needed only here

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
    key plus anything else LiteLLM reads for it, e.g. Azure's endpoint +
    API version. This is what :meth:`ModelRef.env_vars` reports; ``doctor``'s
    key-shape check deliberately keeps using ``env_vars_for`` instead (see
    :data:`_EXTRA_ENV_VARS`'s docstring).

    A recognised provider (anything in :data:`PROVIDER_ENV_VARS`, which is
    derived from the approved-provider registry) reads its key plus extra
    vars straight from there. A provider id LiteLLM itself would route but
    that isn't in the registry (xAI, Groq, Mistral, DeepSeek, OpenRouter, a
    newer OpenAI-compatible host, ...) used to silently return no required
    vars here, so the credential preflight passed and the run failed later,
    deep inside the live call, with a traceback instead of a clear "missing
    FOO_API_KEY". It now falls back to LiteLLM's own ``<PROVIDER>_API_KEY``
    naming convention (the same pattern :func:`looks_like_provider_env_var`
    already recognises) and prints one warning line to stderr -- the
    preflight still fires, just without registry-backed extra vars.
    """
    if override:
        return (override,)
    p = _normalise_provider(provider)
    if p is None:
        return ()
    if p in PROVIDER_ENV_VARS:
        return PROVIDER_ENV_VARS[p] + _EXTRA_ENV_VARS.get(p, ())
    fallback = f"{p.upper().replace('-', '_')}_API_KEY"
    print(
        f"mylonite: provider {p!r} is not in the approved registry; checking "
        f"for {fallback} (LiteLLM's own key-variable naming convention). "
        "Results from an unlisted provider are unverified.",
        file=sys.stderr,
    )
    return (fallback,)


def model_is_routable(model: str, *, api_base: str | None = None) -> bool:
    """True if LiteLLM's OWN resolver, ``litellm.get_llm_provider``, can route
    ``model`` at all -- called on the FULL string, unlike
    :func:`provider_from_model`'s cheap ``<word>/<word>`` prefix-trust
    shortcut (used elsewhere for lightweight provider derivation), which
    treats ANY slash-shaped string as a valid provider prefix and never
    catches a typo like ``not-a-real/model`` (#207).

    ``api_base`` mirrors the kwarg :class:`~mylonite.scan.llm_policy.LLMPolicy`
    sends to the real ``litellm.completion`` call, so a self-hosted/gateway
    model that only resolves with an ``api_base`` set (e.g. a bare OpenAI-
    compatible model id behind a local proxy) is not rejected here either.

    LiteLLM prints a "Provider List: <url>" banner to STDOUT on every
    rejection -- regardless of whether the caller catches the raised
    exception -- which is exactly the noise this pre-flight exists to
    replace with one clean line (#207). Suppressed here via
    ``litellm.suppress_debug_info``, restored afterwards so the flag never
    leaks into an unrelated later call.
    """
    import litellm  # deferred: several seconds to import, needed only here

    previous = litellm.suppress_debug_info
    litellm.suppress_debug_info = True
    try:
        litellm.get_llm_provider(model=model, api_base=api_base)
    except Exception:
        return False
    else:
        return True
    finally:
        litellm.suppress_debug_info = previous


def preflight_model_or_exit(*models: str, api_base: str | None = None) -> None:
    """Resolve every distinct model in ``models`` against LiteLLM's provider
    registry ONCE, before any seed/live call runs -- exits ``EXIT_CONFIG``
    with ONE message naming the first unroutable value if LiteLLM itself
    would reject it.

    Before this pre-flight, a bad ``--model`` shaped like ``provider/model``
    (so it passed ``ModelRef.parse``'s cheap prefix check) only failed deep
    inside the scan/gate/validate/ablate loop, inside
    ``mylonite.scan._llm._classify_or_swallow`` -- once per seed, per role,
    each repeating LiteLLM's own "Provider List" banner and a traceback
    (~12 KB before the one useful line for a 3-call scan). Calling this once,
    for every role model a command resolved, turns that into a single clean
    failure at CLI-argument time.
    """
    import typer

    from mylonite._cli_io import echo_err
    from mylonite.exit_codes import EXIT_CONFIG
    from mylonite.scan.diagnostics import _BAD_REQUEST_REMEDY

    seen: set[str] = set()
    for model in models:
        if not model or model in seen:
            continue
        seen.add(model)
        if model_is_routable(model, api_base=api_base):
            continue
        echo_err(f"invalid --model {model!r}: {_BAD_REQUEST_REMEDY}")
        raise typer.Exit(code=EXIT_CONFIG)


LOCAL_MODEL_HINT = (  # keep in sync with docs/self-hosted-models.md
    "No key? Run a local model instead: --model ollama_chat/llama3.2:3b "
    "(needs Ollama running; see docs/self-hosted-models.md)."
)
_DRY_RUN_HINT = "Or preview what would run, with no LLM calls: add --dry-run."


def require_llm_configured_or_exit(
    *models: str,
    provider: str | None = None,
    dry_run_flag: bool = False,
    api_base: str | None = None,
) -> None:
    """Pre-flight every resolved model a live run will call, exiting
    ``EXIT_CONFIG`` before any adapter/subprocess/engine/seed work starts.
    The ONE place BOTH ``require_llm_configured`` (credential presence --
    the deleted ``MyloniteSettings.require_llm()`` invariant) and
    :func:`preflight_model_or_exit` (#207: can LiteLLM actually route this
    model?) run, shared by scan/validate/gate/ablate.

    Moved here from ``mylonite.cli`` (to keep cli.py under its size cap): cli.py imports
    it back under its original name (``_require_llm_configured_or_exit``)
    so every existing call site and the one test that imports it directly
    keep working unchanged.
    """
    import typer

    from mylonite._cli_io import echo_err
    from mylonite.config import LLMNotConfiguredError, require_llm_configured
    from mylonite.exit_codes import EXIT_CONFIG

    seen: set[str] = set()
    for m in models:
        if m in seen:
            continue
        seen.add(m)
        try:
            require_llm_configured(model=m, provider=provider)
        except LLMNotConfiguredError as exc:
            echo_err(f"{exc}\n{LOCAL_MODEL_HINT}" + (f"\n{_DRY_RUN_HINT}" if dry_run_flag else ""))
            raise typer.Exit(code=EXIT_CONFIG) from exc
    preflight_model_or_exit(*models, api_base=api_base)


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
    if any(key in variables for variables in PROVIDER_ENV_VARS.values()):
        return True
    # ...plus the non-key vars a provider needs to route a call, and the
    # optional ones. Neither map was consulted here, so AWS_REGION_NAME and
    # OPENAI_API_BASE were dropped from `--env-file` while Azure's equivalents
    # passed only by accident of the AZURE_* regex.
    if any(key in variables for variables in _EXTRA_ENV_VARS.values()):
        return True
    return key in _OPTIONAL_ENV_VARS
