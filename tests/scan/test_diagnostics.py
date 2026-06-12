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


def test_tls_remedy_mentions_truststore_and_ssl_cert_file() -> None:
    diag = classify_provider_error(RuntimeError("SSL: CERTIFICATE_VERIFY_FAILED"))
    assert "truststore" in diag.remedy.lower() or "ssl_cert_file" in diag.remedy.lower()


def test_auth_remedy_names_the_env_var() -> None:
    diag = classify_provider_error(RuntimeError("AuthenticationError: 401"))
    assert "ANTHROPIC_API_KEY" in diag.remedy
