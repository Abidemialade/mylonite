"""Provider-error classifier tests (#11/#12)."""

from __future__ import annotations

import pytest

from mylonite.scan.diagnostics import classify_provider_error


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("AnthropicException - [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer", "tls"),
        ("APIError: unable to get local issuer certificate", "tls"),
        ("AuthenticationError: invalid x-api-key", "auth"),
        ("Error code: 401 - invalid api key", "auth"),
        ("RateLimitError: 429 Too Many Requests", "rate_limit"),
        ("APIConnectionError: Connection timed out", "network"),
        ("gaierror: [Errno 11001] getaddrinfo failed", "network"),
        ("ValueError: something totally unexpected", "unknown"),
    ],
)
def test_classify_provider_error(message: str, expected: str) -> None:
    diag = classify_provider_error(RuntimeError(message))
    assert diag.category == expected
    assert diag.detail  # raw detail always preserved
    assert diag.remedy  # always actionable


def test_a_rejected_request_is_non_recoverable() -> None:
    """A provider REJECTING the request will never succeed on retry.

    The classifier already told the operator to "Check --model" for this case,
    but filed it under the catch-all "unknown" category, which is treated as
    recoverable. So the one error whose own remedy names the fix was retried on
    every caller for every seed, logging a full traceback each time -- hundreds
    of lines before any usable summary, from a single typo in --model.
    """
    from mylonite.scan._llm import _NON_RECOVERABLE_CATEGORIES

    diag = classify_provider_error(
        RuntimeError("BadRequestError: LLM Provider NOT provided. model=gpt-4o-typo")
    )
    assert diag.category == "bad_request"
    assert diag.category in _NON_RECOVERABLE_CATEGORIES
    assert "--model" in diag.remedy


def test_a_genuinely_unrecognised_error_stays_recoverable() -> None:
    """The non-recoverable set must stay narrow: unclassified errors still retry."""
    from mylonite.scan._llm import _NON_RECOVERABLE_CATEGORIES

    diag = classify_provider_error(RuntimeError("ValueError: something totally unexpected"))
    assert diag.category == "unknown"
    assert diag.category not in _NON_RECOVERABLE_CATEGORIES


def test_tls_remedy_mentions_truststore_and_ssl_cert_file() -> None:
    diag = classify_provider_error(RuntimeError("SSL: CERTIFICATE_VERIFY_FAILED"))
    assert "truststore" in diag.remedy.lower() or "ssl_cert_file" in diag.remedy.lower()


def test_auth_remedy_names_the_env_var() -> None:
    diag = classify_provider_error(RuntimeError("AuthenticationError: 401"))
    assert "ANTHROPIC_API_KEY" in diag.remedy


# --- an invalid key (401) versus a missing required header (400) -------------

#: A 400 the way LiteLLM surfaces an unscoped key used without its workspace
#: header. The wording is not pinned to one provider's exact text: the
#: classifier keys on "workspace"/"header" plus "required"/"missing".
_HEADER_REQUIRED_400 = (
    "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
    "'message': 'anthropic-workspace-id header is required for this API key'}}"
)


def _litellm_error(kind: str, message: str):
    import litellm

    if kind == "401":
        return litellm.AuthenticationError(
            message=message, llm_provider="anthropic", model="anthropic/m"
        )
    return litellm.BadRequestError(message=message, model="anthropic/m", llm_provider="anthropic")


def test_a_401_says_invalid_or_expired_and_names_the_key_variable() -> None:
    from mylonite.providers.registry import PROVIDERS

    diag = classify_provider_error(_litellm_error("401", "invalid x-api-key"), provider="anthropic")
    assert diag.category == "auth"
    assert "invalid or expired" in diag.remedy
    assert PROVIDERS["anthropic"].key_env[0] in diag.remedy
    assert "--llm-header" not in diag.remedy


def test_a_400_header_required_names_the_header_option_and_env_var() -> None:
    from mylonite.providers.registry import PROVIDERS
    from mylonite.scan._llm import _NON_RECOVERABLE_CATEGORIES
    from mylonite.scan.llm_headers import LLM_HEADERS_ENV

    diag = classify_provider_error(
        _litellm_error("400", _HEADER_REQUIRED_400), provider="anthropic"
    )
    assert diag.category == "auth"
    assert diag.category in _NON_RECOVERABLE_CATEGORIES
    assert "--llm-header" in diag.remedy
    assert LLM_HEADERS_ENV in diag.remedy
    assert PROVIDERS["anthropic"].extra_headers[0] in diag.remedy
    assert "invalid or expired" not in diag.remedy


def test_a_400_header_required_from_a_plain_exception_is_still_recognised() -> None:
    diag = classify_provider_error(RuntimeError(_HEADER_REQUIRED_400))
    assert diag.category == "auth"
    assert "--llm-header" in diag.remedy


def test_a_missing_key_header_is_a_key_problem_not_an_extra_header() -> None:
    """'x-api-key header is required' is the key itself missing: the remedy is
    the key variable, never --llm-header."""
    diag = classify_provider_error(
        RuntimeError("Error code: 401 - x-api-key header is required"), provider="anthropic"
    )
    assert diag.category == "auth"
    assert "--llm-header" not in diag.remedy


def test_an_unrelated_400_stays_a_bad_request() -> None:
    diag = classify_provider_error(
        _litellm_error("400", "model: unknown-model not found"), provider="anthropic"
    )
    assert diag.category == "bad_request"
