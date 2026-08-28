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

from dataclasses import dataclass
from typing import Literal

import litellm

from mylonite.scan.providers import env_vars_for

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
    """isinstance against LiteLLM exception types, tolerant of missing names."""
    for name in names:
        cls = getattr(litellm, name, None)
        if isinstance(cls, type) and isinstance(exc, cls):
            return True
    return False


def _auth_remedy(provider: str | None, env_var_override: str | None) -> str:
    env_vars = env_vars_for(provider, env_var_override)
    if env_vars:
        suffix = f" for provider {provider!r}" if provider else ""
        return f"Authentication failed — set/verify {', '.join(env_vars)}{suffix} is set and valid."
    return (
        "Authentication failed — set the API key env var for your provider "
        "(e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or the AWS "
        "credentials for Bedrock)."
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

    # 2. LiteLLM typed exceptions (most reliable cross-provider signal).
    if _isinstance_litellm(exc, "AuthenticationError"):
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override))
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

    # 3. Substring fallback for non-LiteLLM exceptions (raw ssl/httpx, stubs) or
    #    a future LiteLLM type rename.
    if any(t in low for t in _AUTH_TOKENS) or ("missing" in low and "key" in low):
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override))
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
