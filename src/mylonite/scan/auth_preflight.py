"""The key preflight: prove each role model's key works before the target starts.

A wrong or expired key, or a key that needs an extra header the run didn't
send, used to surface only after the target had launched: one raw LiteLLM
error per call, repeated across seeds and roles. This sends ONE tiny request
per distinct role model first and, when the provider refuses the credentials,
prints one line naming the key variable or the header option and exits 4.

Rules that keep it cheap and honest:

* one request per distinct model (``max_tokens`` 16, no retries), and a model
  already proven in this invocation is not asked again;
* it goes through the LLM chokepoint, so it counts against the hard request
  ceiling and carries the run's policy (``api_base``, extra headers);
* local, keyless providers (Ollama, vLLM) are skipped: there is no key to
  check, and a cold local model would only make the run wait;
* only a credential refusal stops the run. A timeout, a rate limit or an
  unreachable network passes through to the existing reachability handling,
  which reports those more precisely.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Final

from mylonite.scan.llm_policy import LLMPolicy
from mylonite.scan.llm_types import AsyncCompletionFn

#: The tiny request: enough tokens for a one-word reply, never retried.
_PREFLIGHT_MAX_TOKENS: Final = 16
_PREFLIGHT_TIMEOUT_S: Final = 30.0

#: ``(model, api_base)`` pairs already proven in this invocation. Reset by
#: :func:`mylonite.scan.llm_headers.configure_llm_headers` on every CLI run.
_proven: set[tuple[str, str | None]] = set()


def reset_auth_preflight() -> None:
    """Forget which models were proven (a new run, or a new header set)."""
    _proven.clear()


def _needs_key_check(model: str) -> bool:
    from mylonite.scan.providers import provider_from_model, provider_info_for

    info = provider_info_for(provider_from_model(model))
    return not (info is not None and info.local)


def preflight_policy(base: LLMPolicy, api_base: str | None = None) -> LLMPolicy:
    """``base`` narrowed to the tiny request: few tokens, no retries, a short
    timeout. Everything else (temperature, seed, ``drop_params``, the base
    URL, the extra headers) carries through, so the preflight asks the
    provider exactly the way the run will."""
    return replace(
        base,
        api_base=api_base if api_base is not None else base.api_base,
        max_tokens=min(base.max_tokens, _PREFLIGHT_MAX_TOKENS),
        num_retries=0,
        timeout=min(base.timeout, _PREFLIGHT_TIMEOUT_S),
        extra_headers=base.extra_headers or _configured_headers(),
    )


def _configured_headers() -> tuple[tuple[str, str], ...]:
    from mylonite.scan.llm_headers import configured_llm_headers

    return configured_llm_headers()


async def ping(
    model: str, *, completion_fn: AsyncCompletionFn | None = None
) -> BaseException | None:
    """Send the tiny request under the active policy; return the error, if any.

    The caller scopes :func:`preflight_policy` first (see
    :func:`auth_preflight_or_exit`). ``completion_fn`` exists for tests.
    """
    from mylonite.scan._llm import BudgetExceededError, litellm_tool_call_async

    try:
        await litellm_tool_call_async(
            model=model,
            messages=[{"role": "user", "content": "reply with the single word: ok"}],
            tools=[],
            caller="preflight",
            completion_fn=completion_fn,
        )
    except BudgetExceededError:
        raise  # the request ceiling is a decision, never a key problem
    except Exception as exc:
        return exc
    return None


def _quiet_ping(model: str, policy: LLMPolicy) -> BaseException | None:
    """:func:`ping` under ``policy``, with LiteLLM's own "Provider List"/
    feedback banner off, so a refused key prints Mylonite's one line and
    nothing else. The flag is restored afterwards."""
    import litellm  # deferred: seconds to import, needed only for a live check

    from mylonite.scan._llm import llm_scope

    previous = litellm.suppress_debug_info
    litellm.suppress_debug_info = True
    try:
        with llm_scope(policy=policy):
            return asyncio.run(ping(model))
    finally:
        litellm.suppress_debug_info = previous


def auth_preflight_or_exit(*models: str, api_base: str | None = None) -> None:
    """Send one tiny request per distinct model; exit 4 on a refused credential.

    Prints exactly one line (redacted, so no key or header value can appear)
    naming the key variable for a 401 or ``--llm-header`` for a missing
    header, then raises ``typer.Exit(4)``. Any other failure returns normally.
    """
    import typer

    from mylonite._cli_io import echo_err
    from mylonite._redaction import redact
    from mylonite.exit_codes import EXIT_PROVIDER
    from mylonite.scan._llm import active_policy
    from mylonite.scan.diagnostics import classify_provider_error
    from mylonite.scan.providers import provider_from_model

    # No policy is scoped yet when the CLI calls this, so ``active_policy()``
    # is the default one; ``api_base`` and the headers are passed in or read
    # from the run's configuration instead. A future policy field that changes
    # routing (an api_version, a key) must be passed through here as well.
    policy = preflight_policy(active_policy(), api_base)
    for model in dict.fromkeys(m for m in models if m):
        if (model, api_base) in _proven or not _needs_key_check(model):
            continue
        error = _quiet_ping(model, policy)
        if error is None:
            _proven.add((model, api_base))
            continue
        diagnosis = classify_provider_error(error, provider=provider_from_model(model))
        if diagnosis.category != "auth":
            continue
        echo_err(redact(f"error: --model {model}: {diagnosis.remedy}"))
        raise typer.Exit(code=EXIT_PROVIDER)
