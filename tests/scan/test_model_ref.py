"""Tests for :class:`mylonite.scan.model_ref.ModelRef` (T13/H1).

``ModelRef`` replaces the "derive provider from a model string, but keep a
separate --provider flag caller must remember to combine" shape that let
`mylonite validate` skip provider derivation entirely (it never called
`_route_model`/`_validate_model_string`). One field (`raw`, what LiteLLM
actually sees) with the provider DERIVED from it -- not two independently
settable pieces of state that can drift apart.
"""

from __future__ import annotations

import pytest

from mylonite.scan.model_ref import ModelRef, route_model
from mylonite.scan.providers import PROVIDER_ENV_VARS, required_env_vars


def test_model_ref_parse_provider_prefixed_string() -> None:
    """A LiteLLM-style ``provider/model`` string needs no hint at all."""
    ref = ModelRef.parse("anthropic/claude-haiku-4-5")
    assert ref.raw == "anthropic/claude-haiku-4-5"
    assert ref.provider == "anthropic"


def test_model_ref_parse_bare_model_with_explicit_hint() -> None:
    """A bare model + --provider (the deprecated flag) still routes/derives."""
    ref = ModelRef.parse("claude-3-5-haiku-latest", provider_hint="anthropic")
    # LiteLLM doesn't auto-route this alias -- the hint must get baked into
    # `.raw` (mirrors the pre-existing `_route_model` prefixing behaviour) so
    # the string actually sent to LiteLLM routes correctly.
    assert ref.raw == "anthropic/claude-3-5-haiku-latest"
    assert ref.provider == "anthropic"


def test_model_ref_parse_bare_model_no_hint_but_litellm_recognises_it() -> None:
    """A bare model LiteLLM's own registry knows (no prefix needed) resolves
    without a hint -- this is the common case (bundled default models)."""
    ref = ModelRef.parse("claude-sonnet-4-6")
    assert ref.raw == "claude-sonnet-4-6"
    assert ref.provider == "anthropic"


def test_model_ref_parse_openai_prefixed() -> None:
    ref = ModelRef.parse("openai/gpt-4o")
    assert ref.raw == "openai/gpt-4o"
    assert ref.provider == "openai"


def test_model_ref_parse_ollama_self_hosted_prefix() -> None:
    ref = ModelRef.parse("ollama/llama3")
    assert ref.raw == "ollama/llama3"
    assert ref.provider == "ollama"


def test_model_ref_parse_unparseable_bare_model_with_no_hint_raises() -> None:
    """The whole point of ModelRef is removing the silent 'assume anthropic'
    default -- a model LiteLLM can't route and no --provider/prefix to
    disambiguate it MUST fail loudly, not silently default to any provider."""
    with pytest.raises(ValueError, match="not-a-real-model-xyz123"):
        ModelRef.parse("not-a-real-model-xyz123")


def test_model_ref_parse_rejects_blank_model() -> None:
    with pytest.raises(ValueError):
        ModelRef.parse("   ")


def test_model_ref_env_vars_anthropic() -> None:
    assert ModelRef.parse("anthropic/claude-haiku-4-5").env_vars() == ("ANTHROPIC_API_KEY",)


def test_model_ref_env_vars_azure_returns_all_three() -> None:
    """Azure needs 3 vars (key/base/version), not just the API key -- the bug
    T13 closes on the load-side (`_load_env_file`'s allowlist) is mirrored
    here on the read-side: `.env_vars()` must report the FULL requirement."""
    ref = ModelRef.parse("azure/my-deployment")
    assert ref.env_vars() == ("AZURE_API_KEY", "AZURE_API_BASE", "AZURE_API_VERSION")


def test_model_ref_env_vars_matches_required_env_vars_helper() -> None:
    ref = ModelRef.parse("openai/gpt-4o")
    assert ref.env_vars() == required_env_vars("openai")


def test_route_model_helper_matches_model_ref_raw() -> None:
    """`route_model` (the single source of truth `mylonite.cli._route_model`
    now delegates to) must agree with what `ModelRef.parse` bakes into `.raw`."""
    assert (
        route_model("anthropic", "claude-3-5-haiku-latest") == "anthropic/claude-3-5-haiku-latest"
    )
    assert route_model(None, "claude-sonnet-4-6") == "claude-sonnet-4-6"
    assert route_model("anthropic", "openai/gpt-4o") == "openai/gpt-4o"


def test_model_ref_is_frozen() -> None:
    ref = ModelRef.parse("anthropic/claude-haiku-4-5")
    with pytest.raises(AttributeError):
        ref.raw = "something-else"  # type: ignore[misc]


def test_provider_env_vars_map_unchanged_for_doctor_key_shape_check() -> None:
    """PROVIDER_ENV_VARS itself must stay scoped to just the secret-key var(s)
    -- doctor's "does this look like an API key" check reads it directly, and
    AZURE_API_BASE/AZURE_API_VERSION are never key-shaped (they're a URL and
    a date string), so folding them in here would make doctor warn on a
    correctly-configured Azure setup."""
    assert PROVIDER_ENV_VARS["azure"] == ("AZURE_API_KEY",)
