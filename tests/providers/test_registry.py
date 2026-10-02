"""The approved-provider registry: the one table every provider-aware code
path (credential preflight, CI template emission, CLI defaults, docs) is
meant to read instead of hand-rolling its own provider list.
"""

from __future__ import annotations

import dataclasses

import pytest

from mylonite.providers.registry import PROVIDERS


def test_registry_has_exactly_the_approved_providers() -> None:
    assert set(PROVIDERS) == {
        "anthropic",
        "ollama",
        "openai",
        "google",
        "azure",
        "bedrock",
        "vllm",
        "litellm-proxy",
        "vertex_ai",
    }


@pytest.mark.parametrize("provider_id", ["anthropic", "ollama"])
def test_measured_providers_are_tagged_measured(provider_id: str) -> None:
    assert PROVIDERS[provider_id].tier == "measured"


@pytest.mark.parametrize(
    "provider_id",
    ["openai", "google", "azure", "bedrock", "vllm", "litellm-proxy", "vertex_ai"],
)
def test_the_rest_are_tagged_supported(provider_id: str) -> None:
    assert PROVIDERS[provider_id].tier == "supported"


def test_every_row_agrees_with_its_own_id_key() -> None:
    for provider_id, info in PROVIDERS.items():
        assert info.id == provider_id


def test_local_providers_are_flagged_local() -> None:
    assert PROVIDERS["ollama"].local is True
    assert PROVIDERS["vllm"].local is True
    assert PROVIDERS["anthropic"].local is False
    assert PROVIDERS["litellm-proxy"].local is False


def test_azure_carries_its_extra_env_separately_from_the_key() -> None:
    """Azure needs its endpoint + API version alongside the key, but those
    must stay out of `key_env` -- `doctor`'s key-shape check and
    `PROVIDER_ENV_VARS` both read `key_env` alone and would misfire on a URL
    or a date string."""
    azure = PROVIDERS["azure"]
    assert azure.key_env == ("AZURE_API_KEY",)
    assert azure.extra_env == ("AZURE_API_BASE", "AZURE_API_VERSION")


def test_local_providers_need_no_key_env() -> None:
    assert PROVIDERS["ollama"].key_env == ()
    assert PROVIDERS["vllm"].key_env == ()
    assert PROVIDERS["litellm-proxy"].key_env == ()


def test_anthropic_example_model_is_the_small_tier() -> None:
    assert PROVIDERS["anthropic"].example_model == "anthropic/claude-haiku-4-5-20251001"


def test_openai_example_model_is_left_unset_pending_a_pricing_check() -> None:
    assert PROVIDERS["openai"].example_model is None


def test_vertex_authenticates_via_adc_not_a_bearer_key() -> None:
    """Vertex has no API-key env var at all (Application Default
    Credentials -- file/metadata-based, not something to check for in
    `os.environ`); its project + location pair is the hard precondition
    instead, in `extra_env` the same way Azure's endpoint + API version
    are."""
    vertex = PROVIDERS["vertex_ai"]
    assert vertex.key_env == ()
    assert vertex.extra_env == ("VERTEXAI_PROJECT", "VERTEXAI_LOCATION")


def test_extra_headers_defaults_to_empty_for_every_row() -> None:
    for info in PROVIDERS.values():
        assert info.extra_headers == ()


def test_provider_info_is_frozen() -> None:
    info = PROVIDERS["anthropic"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.tier = "supported"  # type: ignore[misc]
