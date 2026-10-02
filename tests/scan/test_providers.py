"""`_ALIASES`/`required_env_vars` for providers outside -- or at the edges
of -- the approved registry.

Three tiers, each needing a different check, and NONE of them may ever ask
LiteLLM anything (an earlier version of the fallback did, via
``litellm.get_llm_provider``/``litellm.validate_environment``, and that
turned out to both BLOCK -- ``chatgpt/`` and ``github_copilot/`` start an
interactive OAuth device-code sign-in -- and silently pass roughly 75 other
LiteLLM providers that have no explicit branch in ``validate_environment``.
Provider identification stays string-only: a ``provider/model`` string is
split on its first ``/``, never resolved by calling LiteLLM):

1. A registry row's OWN `model_prefix` (``hosted_vllm`` for the ``vllm``
   row, ``ollama_chat`` for ``ollama``, ...) must resolve back to that row,
   not fall through to a guess. A missing alias here is exactly how the
   `vllm` row stopped covering the documented `hosted_vllm/<model>` prefix
   when this map was hand-maintained.
2. A known-keyless local/OpenAI-compatible route with no registry row of
   its own (LM Studio, llamafile, the generic "openai_like" prefix) needs
   nothing.
3. Anything else: a guessed ``<PROVIDER>_API_KEY``-shaped var, with a
   warning the first time, silent on every repeat for that provider id.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mylonite.providers.registry import PROVIDERS
from mylonite.scan import providers as providers_module
from mylonite.scan.providers import (
    looks_like_provider_env_var,
    provider_from_model,
    required_env_vars,
)


@pytest.fixture(autouse=True)
def _clear_warned_providers_set() -> Iterator[None]:
    """The once-per-provider warning (`required_env_vars`'s unlisted-provider
    fallback) is tracked in a module-level set that persists across calls --
    deliberately, that's the point of "once per provider", but it makes
    tests order-fragile against each other without this reset."""
    providers_module._WARNED_UNLISTED_PROVIDERS.clear()
    yield
    providers_module._WARNED_UNLISTED_PROVIDERS.clear()


# Every env var any test below reasons about, so a real value sitting in
# this machine's/CI's shell -- plausible for ANTHROPIC_API_KEY, OPENAI_API_KEY
# etc. in a dev environment -- can never change what these assertions see.
# `required_env_vars` itself never reads `os.environ` today (it only names
# vars, never checks them), so none of this should matter yet, but these
# tests assert NAMES, and guarding against a future implementation change
# that starts reading the environment here is cheap and keeps the suite
# honest about what it depends on.
_ENV_VARS_TESTS_REASON_ABOUT = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_API_KEY",
    "AZURE_API_BASE",
    "AZURE_API_VERSION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "VERTEXAI_PROJECT",
    "VERTEXAI_LOCATION",
    "XAI_API_KEY",
    "CHATGPT_API_KEY",
    "GITHUB_COPILOT_API_KEY",
    "COHERE_CHAT_API_KEY",
    "DATABRICKS_API_KEY",
    "MY_CUSTOM_KEY",
    "ZZZ_DEFINITELY_NOT_A_REAL_PROVIDER_API_KEY",
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ENV_VARS_TESTS_REASON_ABOUT:
        monkeypatch.delenv(var, raising=False)


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


@pytest.mark.parametrize(
    "provider_id,expected_var",
    [
        ("xai", "XAI_API_KEY"),
        ("zzz-definitely-not-a-real-provider", "ZZZ_DEFINITELY_NOT_A_REAL_PROVIDER_API_KEY"),
    ],
)
def test_unlisted_provider_falls_back_to_a_guessed_var_and_warns_once(
    provider_id: str,
    expected_var: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Not in the registry, not in the keyless set: xAI is a real LiteLLM
    provider and the fabricated id is not, but BOTH get the same treatment
    now -- a guessed var, never a real LiteLLM lookup (see the module
    docstring for why asking LiteLLM was unsafe)."""
    assert required_env_vars(provider_id) == (expected_var,)
    first_err = capsys.readouterr().err
    assert expected_var in first_err

    # A second call for the SAME provider id warns no further.
    required_env_vars(provider_id)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "route,expected_var",
    [
        ("chatgpt", "CHATGPT_API_KEY"),
        ("github_copilot", "GITHUB_COPILOT_API_KEY"),
        ("xai", "XAI_API_KEY"),
        ("cohere_chat", "COHERE_CHAT_API_KEY"),
        ("databricks", "DATABRICKS_API_KEY"),
    ],
)
def test_unlisted_routes_never_touch_litellm(
    route: str, expected_var: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: `litellm.get_llm_provider` for a route like
    `chatgpt/` or `github_copilot/` starts an interactive OAuth device-code
    sign-in and blocks -- this is what broke when the fallback used to
    probe LiteLLM first. Patch both functions the old probe used to raise
    if called at all, so this test fails loudly (not hangs) if that probe
    ever comes back.

    Resolved through the NORMAL path (`provider_from_model` on a real
    `route/model` string, then `required_env_vars` on the provider id it
    returns) rather than handing `required_env_vars` the raw
    `"route/model"` string directly, so the asserted fallback variable is
    the real one a live run would check for (``CHATGPT_API_KEY``), not an
    artefact of a synthetic probe string (``CHATGPT/X_API_KEY``)."""

    def _raise_if_called(*args: object, **kwargs: object) -> object:
        raise AssertionError("must never call into litellm")

    import litellm

    monkeypatch.setattr(litellm, "get_llm_provider", _raise_if_called)
    monkeypatch.setattr(litellm, "validate_environment", _raise_if_called)

    provider = provider_from_model(f"{route}/some-model")
    assert required_env_vars(provider) == (expected_var,)


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


@pytest.mark.parametrize(
    "key",
    [
        "MYLONITE_API_KEY",  # the scaffolded workflows' own CI secret name
        "MYLONITE_MODEL",
        "MYLONITE_OFFLINE_E2E",
    ],
)
def test_mylonite_s_own_vars_never_look_like_a_provider_credential(key: str) -> None:
    """A Mylonite-namespaced var is never a THIRD-PARTY provider's
    credential, even one shaped like ``<X>_API_KEY`` -- the exact false
    positive the re-review caught (the hardcoded-models check flagged
    ``MYLONITE_API_KEY`` inside the scaffolded workflow templates, which
    are rendered verbatim into a user's own repo, as if it were a hardcoded
    provider default)."""
    assert looks_like_provider_env_var(key) is False


def test_a_real_provider_key_var_still_looks_like_one() -> None:
    """Guards against the fix above over-reaching: only the MYLONITE_*
    namespace is exempt -- an ordinary ``<PROVIDER>_API_KEY`` must still be
    recognised."""
    assert looks_like_provider_env_var("ANTHROPIC_API_KEY") is True


def test_approved_providers_help_text_never_over_claims_bedrock_s_key() -> None:
    """Bedrock never blocks on a missing env var (several credential forms
    are accepted -- see `ProviderInfo.credential_best_effort`), so the help
    text must not say it "needs AWS_ACCESS_KEY_ID": that's only the
    canonical `key_env[0]`, not a requirement, and claiming otherwise is
    exactly the over-claim the re-review caught."""
    text = providers_module.approved_providers_help_text()
    assert "AWS credentials" in text
    assert "AWS_ACCESS_KEY_ID" not in text


def test_approved_providers_help_text_names_every_provider_once() -> None:
    text = providers_module.approved_providers_help_text()
    for info in PROVIDERS.values():
        assert text.count(info.id) >= 1, f"{info.id!r} missing from: {text!r}"


def test_approved_providers_help_text_never_calls_vertex_self_hosted() -> None:
    """`vertex_ai` authenticates via Application Default Credentials, not a
    bare key -- it falls into the same keyless branch as a self-hosted
    LiteLLM proxy, but it is a hosted Google service, so its own clause must
    not describe it as self-hosted. (The doc page it points to is titled
    ``self-hosted-models.md``, so the substring legitimately appears
    elsewhere in the text -- only vertex_ai's OWN clause is checked here.)"""
    text = providers_module.approved_providers_help_text()
    assert "vertex_ai (" in text
    clause = text.split("vertex_ai (", 1)[1].split(")", 1)[0]
    # Strip the doc-link tail before checking: the page it points to is
    # named ``self-hosted-models.md``, so the substring is expected to
    # appear THERE -- only the credential description itself must avoid it.
    need_description = clause.split(" -- see docs", 1)[0]
    assert "self-hosted" not in need_description, need_description
