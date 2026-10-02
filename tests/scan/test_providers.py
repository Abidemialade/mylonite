"""`required_env_vars`'s fallback for a provider outside the approved
registry -- LiteLLM would still route it (xAI, Groq, Mistral, DeepSeek,
OpenRouter, a newer OpenAI-compatible host, ...), but nothing here checked
its key before, so the credential preflight silently passed and the run
failed later, deep inside the live call.
"""

from __future__ import annotations

import pytest

from mylonite.scan.providers import required_env_vars


def test_unlisted_provider_falls_back_to_the_litellm_key_convention(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert required_env_vars("xai") == ("XAI_API_KEY",)
    assert "XAI_API_KEY" in capsys.readouterr().err


def test_unlisted_provider_with_a_hyphen_still_builds_a_plausible_var_name() -> None:
    assert required_env_vars("open-router") == ("OPEN_ROUTER_API_KEY",)


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
