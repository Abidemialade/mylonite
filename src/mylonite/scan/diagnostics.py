"""Classify provider-call failures into actionable, provider-correct categories.

LiteLLM wraps provider errors opaquely — a corporate-proxy TLS failure surfaces
as ``AnthropicException - [SSL: CERTIFICATE_VERIFY_FAILED]``, which reads like a
bad API key. This module maps the exception to a category + a concrete remedy so
a live ``scan``/``gate``/``validate`` run can tell auth from TLS from network
from rate-limit — across providers. Classification is **typed-exception-first**
(LiteLLM raises typed exceptions), with substring matching as a robust fallback
for non-LiteLLM exceptions or future type renames.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Literal

from mylonite.scan.providers import env_vars_for, provider_info_for

DiagnosisCategory = Literal[
    "tls",
    "auth",
    "rate_limit",
    "network",
    "context_window",
    # The provider rejected the request itself (unknown model id, unsupported
    # response_format). Deterministic, so it is non-recoverable -- see
    # `_llm._NON_RECOVERABLE_CATEGORIES`. Previously filed under "unknown",
    # which is retried.
    "bad_request",
    "unknown",
]


@dataclass(frozen=True)
class Diagnosis:
    """A classified provider failure: what kind, the raw detail, and what to do."""

    category: DiagnosisCategory
    detail: str
    remedy: str


def _detail(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _isinstance_litellm(exc: BaseException, *names: str) -> bool:
    """isinstance against LiteLLM exception types, tolerant of missing names.

    Reads LiteLLM from ``sys.modules`` rather than importing it: if LiteLLM was
    never loaded, nothing could have raised one of its exceptions, and importing
    it here would cost every caller several seconds.
    """
    litellm = sys.modules.get("litellm")
    if litellm is None:
        return False
    for name in names:
        cls = getattr(litellm, name, None)
        if isinstance(cls, type) and isinstance(exc, cls):
            return True
    return False


#: Text that says the key itself was missing, rather than refused.
_MISSING_KEY_TOKENS = ("no api key", "api key is required", "header is required")


def _auth_remedy(provider: str | None, env_var_override: str | None, low: str = "") -> str:
    """The remedy for a refused or missing key, naming the key variable.

    A refused key (HTTP 401) reads "invalid or expired"; a key the request
    never carried reads "no API key". Neither ever points at
    ``--llm-header``: that is the remedy for a missing extra header, see
    :func:`_header_remedy`.
    """
    env_vars = env_vars_for(provider, env_var_override)
    missing = any(t in low for t in _MISSING_KEY_TOKENS) or ("missing" in low and "key" in low)
    cause = "no API key was sent" if missing else "HTTP 401: the key is invalid or expired"
    if env_vars:
        suffix = f" for provider {provider!r}" if provider else ""
        return (
            f"Authentication failed ({cause}) -- set a valid key in "
            f"{' or '.join(env_vars)}{suffix}."
        )
    return (
        f"Authentication failed ({cause}) -- set the API key env var for your provider "
        "(e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or the AWS "  # allow-literal: example
        "credentials for Bedrock)."
    )


#: Names of the key itself: a "header required" error naming one of these is a
#: missing key, not a missing extra header.
_KEY_HEADER_TOKENS = ("x-api-key", "api key", "api-key", "api_key", "authorization")


def _looks_header_required(exc: BaseException, low: str) -> bool:
    """True for a 400 saying the request lacks a required extra header.

    The common case is an unscoped key used without its workspace header. Only
    a rejected request (a LiteLLM ``BadRequestError`` or a "400" in the text)
    qualifies, never a 401, and never one that names the key itself.
    """
    if _isinstance_litellm(exc, "AuthenticationError") or "401" in low:
        return False
    if not (_isinstance_litellm(exc, "BadRequestError") or "400" in low):
        return False
    needed = any(t in low for t in ("required", "missing", "must be provided", "must specify"))
    if not needed:
        return False
    if "workspace" in low:
        return True
    return "header" in low and not any(t in low for t in _KEY_HEADER_TOKENS)


def _header_remedy(provider: str | None) -> str:
    """The remedy for a missing extra header, naming ``--llm-header`` and the
    env var, plus the provider's own header name when the registry knows it."""
    from mylonite.scan.llm_headers import LLM_HEADERS_ENV

    info = provider_info_for(provider)
    names = info.extra_headers if info is not None else ()
    header = names[0] if names else "NAME"
    what = f"the {names[0]} header" if names else "an extra request header"
    return (
        f"The provider needs {what} with this key (HTTP 400) -- pass "
        f"--llm-header {header}=<value> or set {LLM_HEADERS_ENV}."
    )


_TLS_TOKENS = (
    "certificate_verify_failed",
    "unable to get local issuer",
    "self-signed certificate",
)
_AUTH_TOKENS = ("authentication", "401", "invalid api key", "invalid x-api-key", "no api key")
_RATE_TOKENS = ("ratelimit", "rate limit", "429")
_NETWORK_TOKENS = (
    "timeout",
    "timed out",
    "connection",
    "getaddrinfo",
    "name or service not known",
    "temporary failure in name resolution",
    "network is unreachable",
    "dns",
)
#: Deliberately narrow: only unambiguous markers of "the provider rejected THIS
#: request". No bare "400" — that digit string turns up in unrelated detail text
#: (ids, sizes, timings) and would misfile a recoverable error as terminal.
_BAD_REQUEST_TOKENS = ("badrequesterror", "bad request", "llm provider not provided")

_BAD_REQUEST_REMEDY = (
    "The provider rejected the request — often an unknown model id or a "
    "response_format the provider doesn't support. Check --model."
)

_RATE_REMEDY = (
    "Rate limited (HTTP 429) — reduce --max-concurrent, slow the run, or check "
    "your provider plan limits."
)
_NETWORK_REMEDY = (
    "Network error reaching the provider — check connectivity, DNS, and any HTTP(S)_PROXY settings."
)


def classify_provider_error(
    exc: BaseException,
    *,
    provider: str | None = None,
    env_var_override: str | None = None,
) -> Diagnosis:
    """Map a provider/LiteLLM exception to a category + provider-correct remedy.

    ``provider`` (and an optional ``env_var_override`` naming a non-default
    credential env var) make the auth remedy name the right env var. Both
    default to ``None`` (back-compatible; falls back to a generic remedy).
    """
    detail = _detail(exc)
    low = detail.lower()

    # 1. TLS FIRST — TLS failures arrive wrapped as APIConnectionError/APIError,
    #    so the isinstance ladder below would mislabel them "network". The
    #    truststore remedy is the one that actually helps.
    if any(t in low for t in _TLS_TOKENS) or ("ssl" in low and "cert" in low):
        return Diagnosis(
            "tls",
            detail,
            "TLS certificate verification failed — typically a corporate "
            "TLS-inspecting proxy whose CA is in the OS trust store but not "
            "Python's certifi bundle. Install the OS-trust-store helper with "
            '`pip install "mylonite[enterprise]"` (auto-enabled), or point '
            "SSL_CERT_FILE at your corporate CA bundle.",
        )

    # 2. A request missing a required extra header (e.g. an unscoped key's
    #    workspace id). Arrives as a 400, so it must be caught before the
    #    BadRequestError branch below would file it as "check --model". Filed
    #    under "auth": like a bad key, it is a credential setup problem that
    #    no retry fixes.
    if _looks_header_required(exc, low):
        return Diagnosis("auth", detail, _header_remedy(provider))

    # 3. LiteLLM typed exceptions (most reliable cross-provider signal).
    if _isinstance_litellm(exc, "AuthenticationError"):
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override, low))
    if _isinstance_litellm(exc, "RateLimitError"):
        return Diagnosis("rate_limit", detail, _RATE_REMEDY)
    if _isinstance_litellm(exc, "Timeout", "APIConnectionError", "ServiceUnavailableError"):
        return Diagnosis("network", detail, _NETWORK_REMEDY)
    if _isinstance_litellm(exc, "ContextWindowExceededError"):
        return Diagnosis(
            "context_window",
            detail,
            "Context window exceeded — shorten the input, lower the payload "
            "size, or pick a model with a larger context window.",
        )
    if _isinstance_litellm(exc, "BadRequestError"):
        # Its own category, and a NON-RECOVERABLE one: the provider rejected the
        # request itself, so the identical request will be rejected identically
        # on every retry. Filed under "unknown" this was the one error whose
        # remedy names the fix ("Check --model") while still being retried for
        # every caller of every seed.
        return Diagnosis("bad_request", detail, _BAD_REQUEST_REMEDY)

    # 4. Substring fallback for non-LiteLLM exceptions (raw ssl/httpx, stubs) or
    #    a future LiteLLM type rename.
    if any(t in low for t in _AUTH_TOKENS) or ("missing" in low and "key" in low):
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override, low))
    if any(t in low for t in _RATE_TOKENS):
        return Diagnosis("rate_limit", detail, _RATE_REMEDY)
    if any(t in low for t in _NETWORK_TOKENS):
        return Diagnosis("network", detail, _NETWORK_REMEDY)
    if any(t in low for t in _BAD_REQUEST_TOKENS):
        return Diagnosis("bad_request", detail, _BAD_REQUEST_REMEDY)
    return Diagnosis(
        "unknown",
        detail,
        "Unrecognised provider error. See the detail above; re-run with "
        "logging at INFO for the full traceback.",
    )
