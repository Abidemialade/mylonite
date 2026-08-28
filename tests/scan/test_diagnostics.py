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
