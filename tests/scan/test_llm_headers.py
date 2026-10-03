"""Extra LLM request headers: parsing, precedence, policy wiring and redaction.

Some keys need a header beyond the key itself on every request (an Anthropic
workspace id for an unscoped key, a gateway's routing header). The values are
treated as secrets: they reach the provider call and nothing else.
"""

from __future__ import annotations

import pytest

from mylonite._redaction import REDACTION_PLACEHOLDER, redact
from mylonite._replay import _stable_key_v2
from mylonite.scan.llm_headers import (
    LLM_HEADERS_ENV,
    InvalidLLMHeaderError,
    configure_llm_headers,
    configured_llm_headers,
    parse_llm_headers,
    reset_llm_headers,
)
from mylonite.scan.llm_policy import LLMPolicy

_SENTINEL = "wrkspc-sentinel-7f3a9"


@pytest.fixture(autouse=True)
def _clean_headers(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(LLM_HEADERS_ENV, raising=False)
    reset_llm_headers()
    yield
    reset_llm_headers()


def test_parse_cli_values_into_name_value_pairs() -> None:
    headers = parse_llm_headers(["anthropic-workspace-id=abc", "X-Route = eu "], None)
    assert headers == (("anthropic-workspace-id", "abc"), ("X-Route", "eu"))


def test_value_may_contain_equals_signs() -> None:
    assert parse_llm_headers(["x-token=a=b=c"], None) == (("x-token", "a=b=c"),)


def test_env_value_is_comma_separated() -> None:
    headers = parse_llm_headers(None, "a-one=1, b-two=2")
    assert headers == (("a-one", "1"), ("b-two", "2"))


def test_cli_wins_over_env_for_the_same_name_case_insensitively() -> None:
    headers = parse_llm_headers(["Anthropic-Workspace-Id=cli"], "anthropic-workspace-id=env,x-y=1")
    assert headers == (("x-y", "1"), ("Anthropic-Workspace-Id", "cli"))


@pytest.mark.parametrize("source", ["flag", "env"])
@pytest.mark.parametrize(
    "entry",
    [
        f"x-ws: {_SENTINEL}=pad",
        f"anthropic-workspace-id: {_SENTINEL}",
        f"Authorization: Bearer {_SENTINEL}==",
    ],
)
def test_a_curl_style_entry_never_echoes_any_part_of_itself(entry: str, source: str) -> None:
    """A 'Name: value' entry (the curl habit) is malformed; whatever sits
    before the first '=' may be the secret, so the error names the entry's
    position and the expected form, nothing from the entry itself."""
    with pytest.raises(InvalidLLMHeaderError) as info:
        if source == "flag":
            parse_llm_headers([entry], None)
        else:
            parse_llm_headers(None, entry)
    message = str(info.value)
    assert _SENTINEL not in message
    assert entry.split(":")[0] not in message
    assert "NAME=VALUE" in message


@pytest.mark.parametrize(
    "entry",
    [
        "no-equals-sign",
        "=value-without-name",
        "name=",
        "bad name=secretval",
        "x=line\nbreak",
        "x=a\rb",
    ],
)
def test_malformed_entry_is_refused_without_echoing_the_value(entry: str) -> None:
    with pytest.raises(InvalidLLMHeaderError) as info:
        parse_llm_headers([entry], None)
    value = entry.partition("=")[2]
    if value:
        assert value not in str(info.value)
    assert "NAME=VALUE" in str(info.value) or "line break" in str(info.value)


def test_configure_reads_env_and_registers_values_for_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(LLM_HEADERS_ENV, f"anthropic-workspace-id={_SENTINEL}")
    configure_llm_headers(None)
    assert configured_llm_headers() == (("anthropic-workspace-id", _SENTINEL),)
    assert _SENTINEL not in redact(f"request failed with header {_SENTINEL} attached")
    assert REDACTION_PLACEHOLDER in redact(f"value={_SENTINEL}")


def test_reset_forgets_headers_and_their_redaction() -> None:
    configure_llm_headers([f"x-a={_SENTINEL}"])
    reset_llm_headers()
    assert configured_llm_headers() == ()
    assert _SENTINEL in redact(_SENTINEL)


def test_policy_sends_extra_headers_as_a_dict() -> None:
    policy = LLMPolicy(extra_headers=(("anthropic-workspace-id", _SENTINEL),))
    assert policy.kwargs()["extra_headers"] == {"anthropic-workspace-id": _SENTINEL}


def test_policy_without_headers_sends_no_extra_headers_kwarg() -> None:
    assert "extra_headers" not in LLMPolicy().kwargs()


def test_policy_repr_never_shows_a_header_value() -> None:
    policy = LLMPolicy(extra_headers=(("anthropic-workspace-id", _SENTINEL),))
    assert _SENTINEL not in repr(policy)


def test_header_values_never_enter_the_replay_cache_key() -> None:
    messages = [{"role": "user", "content": "hi"}]
    plain = _stable_key_v2("m", messages)
    with_headers = _stable_key_v2(
        "m", messages, **LLMPolicy(extra_headers=(("x-a", _SENTINEL),)).kwargs()
    )
    assert plain == _stable_key_v2("m", messages, **LLMPolicy().kwargs())
    assert with_headers == plain


def test_a_policy_built_directly_registers_its_header_values() -> None:
    """A library caller that builds LLMPolicy itself, without the CLI, still
    gets its header values masked."""
    LLMPolicy(extra_headers=(("x-gateway-token", _SENTINEL),))
    assert _SENTINEL not in redact(f"echo {_SENTINEL}")
