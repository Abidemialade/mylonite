"""LLMPolicy tests — the per-call kwargs the differential oracle depends on
(T14/H2), and the credentialed-``api_base`` rejection (T14/CEO §3)."""

from __future__ import annotations

import pytest

from mylonite.scan.llm_policy import CredentialedApiBaseError, LLMPolicy, validate_api_base


def test_defaults_match_the_documented_values() -> None:
    policy = LLMPolicy()
    assert policy.temperature == 0.0
    assert policy.max_tokens == 2048
    assert policy.timeout == 120.0
    assert policy.num_retries == 2
    assert policy.drop_params is True
    assert policy.seed == 0
    assert policy.api_base is None
    assert policy.api_key is None
    assert policy.api_version is None


def test_kwargs_carries_every_documented_default() -> None:
    kwargs = LLMPolicy().kwargs()
    assert kwargs == {
        "max_tokens": 2048,
        "temperature": 0.0,
        "timeout": 120.0,
        "num_retries": 2,
        "drop_params": True,
        "seed": 0,
    }


def test_kwargs_omits_none_optional_fields() -> None:
    kwargs = LLMPolicy().kwargs()
    assert "api_base" not in kwargs
    assert "api_key" not in kwargs
    assert "api_version" not in kwargs


def test_kwargs_includes_optional_fields_when_set() -> None:
    policy = LLMPolicy(
        api_base="https://my-proxy.internal/v1",
        api_key="sk-test",
        api_version="2024-01-01",
    )
    kwargs = policy.kwargs()
    assert kwargs["api_base"] == "https://my-proxy.internal/v1"
    assert kwargs["api_key"] == "sk-test"
    assert kwargs["api_version"] == "2024-01-01"


def test_kwargs_omits_seed_when_none() -> None:
    policy = LLMPolicy(seed=None)
    assert "seed" not in policy.kwargs()


def test_custom_values_round_trip() -> None:
    policy = LLMPolicy(max_tokens=512, temperature=0.7, timeout=30.0, num_retries=0)
    kwargs = policy.kwargs()
    assert kwargs["max_tokens"] == 512
    assert kwargs["temperature"] == 0.7
    assert kwargs["timeout"] == 30.0
    assert kwargs["num_retries"] == 0


# --- credentialed api_base rejection (CEO §3) --------------------------------


def test_validate_api_base_allows_none_and_plain_urls() -> None:
    validate_api_base(None)
    validate_api_base("")
    validate_api_base("https://my-proxy.internal/v1")
    validate_api_base("http://localhost:11434")


@pytest.mark.parametrize(
    "api_base",
    [
        "https://user:pass@my-proxy.internal/v1",
        "https://my-proxy.internal/v1?api_key=sk-abc123",
        "https://my-proxy.internal/v1?apikey=sk-abc123",
        "https://my-proxy.internal/v1?token=abc",
        "http://key:sk-ant-abc123@localhost:8000",
    ],
)
def test_validate_api_base_rejects_realistic_leak_shapes(api_base: str) -> None:
    with pytest.raises(CredentialedApiBaseError) as excinfo:
        validate_api_base(api_base)
    # The message must not just say "invalid" -- it must name an alternative.
    assert "env var" in str(excinfo.value)


def test_llm_policy_construction_rejects_credentialed_api_base() -> None:
    """Defense in depth: LLMPolicy() itself refuses a credentialed api_base,
    not just RunConfig's own field validator -- the leak must be IMPOSSIBLE at
    the one chokepoint every source (CLI flag/mylonite.yaml/env var) funnels
    through, not merely checked at one of several possible entry points."""
    with pytest.raises(CredentialedApiBaseError):
        LLMPolicy(api_base="https://user:pass@my-proxy.internal/v1")
    with pytest.raises(CredentialedApiBaseError):
        LLMPolicy(api_base="https://my-proxy.internal/v1?api_key=sk-abc123")
