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

import re
import sys
from dataclasses import dataclass
from typing import Literal

from mylonite._redaction import mask_secret_values
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
    """``Type: message``, with registered secret values (``--llm-header``
    values) masked: the detail reaches exception messages and reports."""
    return mask_secret_values(f"{type(exc).__name__}: {exc}")


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

#: A status code written into an error's text ("Error code: 400", "HTTP 401",
#: "status 400"), for exceptions that carry no ``status_code`` attribute.
_LABELLED_STATUS_RE = re.compile(r"\b(?:error code|status(?: code)?|http)\W{0,3}(\d{3})\b")
#: Last resort: a bare 400 or 401 standing alone as a word, so a request id or
#: a token count that merely contains the digits doesn't count.
_BARE_STATUS_RE = re.compile(r"(?<![\w.-])(40[01])(?![\w-]|\.\d)")


def _status_code(exc: BaseException, low: str) -> int | None:
    """The HTTP status of a provider failure, or ``None`` when unknown.

    LiteLLM's exceptions carry ``status_code``; that wins. Otherwise the typed
    class implies it, then a labelled code in the text, then a bare 400/401.
    """
    code = getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    if _isinstance_litellm(exc, "AuthenticationError"):
        return 401
    if _isinstance_litellm(exc, "BadRequestError"):
        return 400
    labelled = _LABELLED_STATUS_RE.search(low)
    if labelled:
        return int(labelled.group(1))
    bare = _BARE_STATUS_RE.search(low)
    return int(bare.group(1)) if bare else None


def _auth_remedy(
    provider: str | None, env_var_override: str | None, low: str = "", status: int | None = None
) -> str:
    """The remedy for a refused or missing key, naming the key variable.

    A key the request never carried reads "no API key"; a refused key reads
    "invalid or expired", with "HTTP 401" only when the status really was 401.
    Neither ever points at ``--llm-header``: that is the remedy for a missing
    extra header, see :func:`_header_remedy`.
    """
    env_vars = env_vars_for(provider, env_var_override)
    missing = any(t in low for t in _MISSING_KEY_TOKENS) or ("missing" in low and "key" in low)
    if missing:
        cause = "no API key was sent"
    elif status == 401:
        cause = "HTTP 401: the key is invalid or expired"
    else:
        cause = "the provider refused the key: invalid or expired"
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
_NEEDED_TOKENS = ("required", "missing", "must be provided", "must specify")
#: A hyphenated header name written next to the word "header", either side:
#: "anthropic-version header is required", "missing header: x-route-id".
_NAMED_HEADER_RE = re.compile(
    r"\b([a-z][a-z0-9]*(?:-[a-z0-9]+)+)['\"`]?\s+header\b"
    r"|\bheader\W{1,3}([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\b"
)


def _known_header_names() -> tuple[str, ...]:
    from mylonite.providers.registry import PROVIDERS

    return tuple(name for info in PROVIDERS.values() for name in info.extra_headers)


def _named_header(low: str) -> str | None:
    """The header the error text names: a registry header first, else a
    hyphenated name written beside the word "header", else ``None``."""
    for name in _known_header_names():
        if name in low:
            return name
    match = _NAMED_HEADER_RE.search(low)
    if match:
        return match.group(1) or match.group(2)
    return None


def _looks_header_required(status: int | None, low: str) -> bool:
    """True for a 400 saying the request lacks a required extra header.

    The common case is an unscoped key used without its workspace header. It
    needs all of: status 400; "required"/"missing"/...; and a real header
    signal (the word "header", or a registry header name). A 400 that only
    mentions a workspace (a spend limit, a billing tier) does not qualify,
    and neither does one naming the key itself.
    """
    if status != 400:
        return False
    if not any(t in low for t in _NEEDED_TOKENS):
        return False
    if any(name in low for name in _known_header_names()):
        return True
    return "header" in low and not any(t in low for t in _KEY_HEADER_TOKENS)


def _header_remedy(low: str) -> str:
    """The remedy for a missing extra header: ``--llm-header`` and the env var,
    naming the header the error itself names (never a guessed default)."""
    from mylonite.scan.llm_headers import LLM_HEADERS_ENV

    name = _named_header(low)
    what = f"the {name} header" if name else "a required request header"
    # The header name comes from the provider's text, so mask it at source.
    return mask_secret_values(
        f"The provider needs {what} with this key (HTTP 400) -- pass "
        f"--llm-header {name or 'NAME'}=<value> or set {LLM_HEADERS_ENV}."
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
    status = _status_code(exc, low)
    if _looks_header_required(status, low):
        return Diagnosis("auth", detail, _header_remedy(low))

    # 3. LiteLLM typed exceptions (most reliable cross-provider signal).
    if _isinstance_litellm(exc, "AuthenticationError"):
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override, low, status))
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
        return Diagnosis("auth", detail, _auth_remedy(provider, env_var_override, low, status))
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
