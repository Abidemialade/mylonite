"""`_ALIASES`/`required_env_vars` for providers outside -- or at the edges
of -- the approved registry.

Three tiers, each needing a different check:

1. A registry row's OWN `model_prefix` (``hosted_vllm`` for the ``vllm``
   row, ``ollama_chat`` for ``ollama``, ...) must resolve back to that row,
   not fall through to a guess. A missing alias here is exactly how the
   `vllm` row stopped covering the documented `hosted_vllm/<model>` prefix
   when this map was hand-maintained.
2. A known-keyless local/OpenAI-compatible route with no registry row of
   its own (LM Studio, llamafile, the generic "openai_like" prefix) needs
   nothing.
3. Anything else: LiteLLM itself may still know it (xAI, Groq, Mistral,
   DeepSeek, OpenRouter, Cohere's chat route, ...), in which case its own
   key-presence check wins; only when LiteLLM knows NOTHING about the
   provider either does this fall back to a guessed credential var, with a
   warning.
"""

from __future__ import annotations

import pytest

from mylonite.providers.registry import PROVIDERS
from mylonite.scan.providers import provider_from_model, required_env_vars


@pytest.mark.parametrize("provider_id", list(PROVIDERS))
def test_every_registry_row_s_own_model_prefix_resolves_back_to_it(provider_id: str) -> None:
    """The regression test the review asked for: pin EVERY row's own
    `model_prefix` as an accepted alias, so adding a row without also
    covering its routing prefix (the `vllm`/`hosted_vllm` bug) fails here
    instead of shipping silently."""
    info = PROVIDERS[provider_id]
    probe_model = f"{info.model_prefix}x"

    assert provider_from_model(probe_model) == provider_id
    assert required_env_vars(provider_id) == info.key_env + info.extra_env


@pytest.mark.parametrize("provider_id", list(PROVIDERS))
def test_known_rows_never_warn(provider_id: str, capsys: pytest.CaptureFixture[str]) -> None:
    required_env_vars(provider_id)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "alias,resolved",
    [
        ("hosted_vllm", "vllm"),
        ("ollama_chat", "ollama"),
        ("ollama", "ollama"),
        ("gemini", "google"),
        ("azure_ai", "azure"),
        ("bedrock_converse", "bedrock"),
        ("litellm_proxy", "litellm-proxy"),
    ],
)
def test_known_aliases_resolve_to_the_right_registry_row(
    alias: str, resolved: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert required_env_vars(alias) == (PROVIDERS[resolved].key_env + PROVIDERS[resolved].extra_env)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("provider_id", ["lm_studio", "llamafile", "openai_like"])
def test_known_keyless_local_routes_need_nothing(
    provider_id: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert required_env_vars(provider_id) == ()
    assert capsys.readouterr().err == ""


def test_a_provider_litellm_knows_but_the_registry_does_not_uses_litellms_own_key_var(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """xAI isn't an approved-registry row, but LiteLLM itself routes it and
    knows its real credential var -- that must win over a guess, and
    without a warning (LiteLLM genuinely knows this one)."""
    assert required_env_vars("xai") == ("XAI_API_KEY",)
    assert capsys.readouterr().err == ""


def test_a_provider_litellm_knows_nothing_about_falls_back_and_warns_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert required_env_vars("zzz-definitely-not-a-real-provider") == (
        "ZZZ_DEFINITELY_NOT_A_REAL_PROVIDER_API_KEY",
    )
    first_err = capsys.readouterr().err
    assert "ZZZ_DEFINITELY_NOT_A_REAL_PROVIDER_API_KEY" in first_err

    # A second call for the SAME provider id warns no further.
    required_env_vars("zzz-definitely-not-a-real-provider")
    assert capsys.readouterr().err == ""


def test_stub_sentinel_provider_still_needs_no_key_and_warns_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert required_env_vars("stub") == ()
    assert capsys.readouterr().err == ""


def test_an_explicit_override_wins_over_the_fallback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert required_env_vars("xai", override="MY_CUSTOM_KEY") == ("MY_CUSTOM_KEY",)
    assert capsys.readouterr().err == ""


def test_no_provider_resolved_still_requires_nothing() -> None:
    assert required_env_vars(None) == ()
