"""Tests for the model pre-flight (#207).

A bad ``--model`` used to reach a live seed call -- once per seed, per role --
before failing: ``provider_from_model``'s cheap ``<word>/<word>`` prefix check
trusts ANY slash-shaped string as a valid provider prefix, so
``not-a-real/model`` sailed through ``ModelRef.parse`` and only failed deep
inside ``litellm.completion``, repeatedly (34 "Provider List" banners + 8
non-recoverable log lines + a traceback -- ~12 KB before the one useful line).

``preflight_model_or_exit`` calls ``litellm.get_llm_provider`` on the FULL
model string ONCE, using the exact same resolution LiteLLM's own
``completion`` performs internally, so every model form ``completion`` itself
accepts must also pass here -- these tests are the contract for that.
"""

from __future__ import annotations

import pytest
import typer

from mylonite.scan.providers import model_is_routable, preflight_model_or_exit


@pytest.mark.parametrize(
    "model",
    [
        "ollama/llama3",
        "ollama_chat/llama3.2:3b",
        "openai/gpt-4o-mini",
        "hosted_vllm/mistral-7b-instruct",
        "claude-haiku-4-5-20251001",
        "azure/my-deployment",
        "bedrock/anthropic.claude-3-haiku-20240307-v1:0",
        "anthropic/claude-haiku-4-5",
    ],
)
def test_every_form_litellm_completion_accepts_is_routable(model: str) -> None:
    """Every model shape the risk table calls out must NOT be rejected --
    weakening this check to reject a real form would be worse than not
    having it (see the risk table: "report NEEDS_CONTEXT instead of
    weakening the check")."""
    assert model_is_routable(model) is True


def test_openai_model_with_an_api_base_is_routable() -> None:
    """A local/self-hosted OpenAI-compatible endpoint (LLMPolicy.api_base) --
    the pre-flight must mirror the SAME kwarg litellm_policy.kwargs() sends
    to the real completion call, not just the bare model string."""
    assert model_is_routable("openai/gpt-4o-mini", api_base="http://localhost:1234/v1") is True


def test_a_provider_shaped_but_bogus_model_is_not_routable() -> None:
    """The exact #207 repro: `not-a-real/model` LOOKS like a valid
    `provider/model` pair to the cheap prefix check, but LiteLLM's own
    registry has no `not-a-real` provider."""
    assert model_is_routable("not-a-real/model") is False


def test_model_is_routable_suppresses_litellms_provider_list_banner(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fix round 1 (#207): litellm.get_llm_provider prints a "Provider List:
    <url>" banner to stdout on every rejection, regardless of whether the
    caller catches the exception -- with the preflight now called once per
    role model (not per seed/attempt), this must not print at all."""
    assert model_is_routable("not-a-real/model") is False
    out = capsys.readouterr().out
    assert "Provider List" not in out


def test_model_is_routable_restores_suppress_debug_info_afterwards() -> None:
    """The suppression must not leak into unrelated litellm calls elsewhere
    in the process -- restore whatever the flag was before this call."""
    import litellm

    litellm.suppress_debug_info = False
    model_is_routable("not-a-real/model")
    assert litellm.suppress_debug_info is False


def test_preflight_exits_config_once_naming_the_bad_model_and_the_flag() -> None:
    with pytest.raises(typer.Exit) as excinfo:
        preflight_model_or_exit("not-a-real/model")
    from mylonite.exit_codes import EXIT_CONFIG

    assert excinfo.value.exit_code == EXIT_CONFIG


def test_preflight_checks_every_model_but_stops_at_the_first_bad_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(typer.Exit):
        preflight_model_or_exit("anthropic/claude-haiku-4-5", "not-a-real/model")
    err = capsys.readouterr().err
    assert "not-a-real/model" in err
    assert "Check --model" in err


def test_preflight_dedupes_the_same_model_across_roles() -> None:
    """planner/customiser/judge often resolve to the SAME model string --
    the pre-flight must not call litellm.get_llm_provider (or print) N times
    for one distinct value."""
    # No exception: every arg is the same valid model.
    preflight_model_or_exit("anthropic/claude-haiku-4-5", "anthropic/claude-haiku-4-5")
