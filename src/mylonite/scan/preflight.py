"""Provider reachability checks that ``validate`` runs before its live loop.

Both checks answer "is the provider reachable", and, when it is not, record
why (#191): a rate limit and an unreachable network each get their own
operator message, naming the provider and model and saying what to do, so a
429 no longer reads as a credentials problem.

Heavy imports (LiteLLM, the reference target) stay inside the functions, so
importing this module from the CLI costs nothing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Final

from mylonite.scan.coverage import provider_abort_message

#: Sane non-None default for ``validate --iteration-timeout`` (DCR-0010), and
#: the preflight's own bound: a single tiny completion per role model must
#: not be able to block a CI job indefinitely just because the flag was left
#: unset. 120s is generous for a one-token reply, even from a cold local
#: model's first inference; pass a larger value explicitly for a target
#: known to need more headroom. The CLI imports this one value, so the two
#: cannot drift.
DEFAULT_ITERATION_TIMEOUT_S: Final = 120.0


@dataclass
class PreflightFailure:
    """Why a failed preflight failed: the diagnosis category of the refused
    call (``rate_limit``, ``network``, ``auth`` ...), or ``None`` when unknown.

    ``model`` (V2/T7) is the role model that actually failed to answer --
    with three role models that can differ (planner/customiser/judge), the
    operator message must name the one that was actually unreachable, not
    just the run's primary ``--model``.
    """

    category: str | None = None
    model: str | None = None


def preflight_failure_message(
    failure: PreflightFailure | None, *, provider: str | None, model: str | None
) -> str | None:
    """The rate-limit or network message for a failed preflight, else ``None``
    (the caller keeps its credentials hint)."""
    return provider_abort_message(
        failure.category if failure is not None else None,
        provider=provider,
        model=model,
        slow_down="lower --iterations",
        stopped="validate stopped before it started.",
    )


def unreachable_hint(provider: str | None, model: str) -> str:
    """The fallback message when the preflight failed for any other reason.

    Names the API-key variable for the model's own provider when it is known,
    and stays neutral otherwise; never assumes one provider's key.
    """
    from mylonite._redaction import redact
    from mylonite.scan.providers import env_vars_for, provider_from_model

    env_vars = env_vars_for(provider_from_model(model) or provider)
    key = " or ".join(env_vars) if env_vars else "your provider's API key"
    return redact(
        f"no provider reachable for --model {model}: check that {key} is set and valid, "
        "or pass --model provider/modelname for another LiteLLM provider "
        "(e.g. --model openai/gpt-4o)."  # allow-literal: example
    )


def _ping_roles(
    *models: str,
    timeout_s: float,
    api_base: str | None,
    failure: PreflightFailure | None,
) -> bool:
    """One tiny completion per DISTINCT role model (planner/customiser/judge
    can differ) -- shared by :func:`provider_preflight_direct` and
    :func:`provider_preflight`, which differ only in what they're called for,
    never in how they ping.

    V1/T7: this used to be a full 9-seed reference scan for the reference
    path, capped at a timeout sized for a tiny call -- a slow-but-working
    model's SCAN (not a single completion) could outrun the bound, so it was
    misdiagnosed as unreachable and reported the credentials hint instead of
    a timeout. A tiny call per role finishes well inside any realistic
    timeout, even from a cold local model.

    ``api_base`` (T7) is applied to every ping via :func:`llm_scope` --
    previously neither preflight entered any scope at all, so
    ``active_policy()`` fell back to the default ``LLMPolicy()`` and a
    configured custom endpoint (a remote Ollama, a self-hosted vLLM, an
    OpenAI-compatible proxy) was never actually reached by the check: a
    perfectly reachable custom provider still read as unreachable and
    pointed the operator at the wrong credential variable instead.

    Stops at the first role that fails to answer; ``failure`` (if given)
    records that role's diagnosis category AND its model name, so the
    operator message can name the model that actually failed rather than
    just the run's primary ``--model``. Returns True iff every distinct role
    model answered.
    """
    from mylonite.scan._llm import (
        BudgetExceededError,
        active_policy,
        litellm_tool_call_async,
        llm_scope,
    )
    from mylonite.scan.auth_preflight import preflight_policy
    from mylonite.scan.diagnostics import classify_provider_error
    from mylonite.scan.providers import provider_from_model

    # The same tiny-request shape the key preflight already uses (few
    # tokens, no retries, a short per-call socket timeout) plus the run's
    # own api_base/headers -- a reachability check has no reason to ask for
    # anything bigger than the credential check does.
    policy = preflight_policy(active_policy(), api_base)

    async def _ping(model: str) -> bool:
        try:
            with llm_scope(policy=policy):
                # Uses the "planner" caller label: this IS a minimal
                # planner-shaped completion (a user message + empty tools),
                # and it routes through the same chokepoint so it inherits
                # budget-counting. Wrapped in its own wall-clock bound
                # (distinct from the policy's/call's own socket timeout)
                # because a stalled fake or a provider that accepts the
                # connection and never answers must not be able to hang the
                # CLI/CI job open-ended.
                await asyncio.wait_for(
                    litellm_tool_call_async(
                        model=model,
                        messages=[{"role": "user", "content": "reply with the single word: ok"}],
                        tools=[],
                        caller="planner",
                        timeout_s=timeout_s,
                    ),
                    timeout=timeout_s,
                )
        except BudgetExceededError:
            raise  # a spent budget is not an unreachable provider
        except TimeoutError:
            # A provider (or fake) that stalls is unreachable, not
            # misconfigured: say so rather than falling through to the
            # credentials hint.
            if failure is not None:
                failure.category = "network"
                failure.model = model
            return False
        except Exception as exc:
            if failure is not None:
                diagnosis = classify_provider_error(exc, provider=provider_from_model(model))
                failure.category = diagnosis.category
                failure.model = model
            return False
        return True

    async def _ping_each_distinct_role() -> bool:
        for model in dict.fromkeys(m for m in models if m):
            if not await _ping(model):
                return False
        return True

    try:
        return asyncio.run(_ping_each_distinct_role())
    except BudgetExceededError:
        raise
    except Exception:
        return False


def provider_preflight_direct(
    provider: str,
    *models: str,
    timeout_s: float,
    failure: PreflightFailure | None = None,
    api_base: str | None = None,
) -> bool:
    """Reachability probe that does NOT route through the bundled reference target.

    A custom-target validate has no reason to touch ``mcp_kitchen_sink`` — its
    re-drive uses the operator's own target. This checks reachability with a
    tiny LLM completion per distinct role model instead (see
    :func:`_ping_roles`). Returns True iff every one answered.
    """
    _ = provider  # provider routing is carried by the model string / active policy
    return _ping_roles(*models, timeout_s=timeout_s, api_base=api_base, failure=failure)


def provider_preflight(
    provider: str,
    *models: str,
    timeout_s: float = DEFAULT_ITERATION_TIMEOUT_S,
    failure: PreflightFailure | None = None,
    api_base: str | None = None,
) -> bool:
    """Cheap reachability probe before the (expensive) live reference-target
    validation loop. If any role model is unreachable, the validator's
    N-iteration loop would be too -- so we fail fast with a distinct exit 4
    rather than burning iterations and reporting a misleading non-discrim
    result.

    V1: this used to run ONE FULL vulnerable reference scan (9 seeds) under
    this same timeout, which a slow-but-reachable model could outrun even
    though it would have answered a single completion fine -- misdiagnosed
    as "provider unreachable" rather than "the scan is slow". It is now the
    same tiny per-role-model ping as :func:`provider_preflight_direct` (see
    :func:`_ping_roles`), kept as a separate name because the reference
    path calls it, mirroring the custom path's own naming. Returns True iff
    every distinct role model answered.
    """
    _ = provider
    return _ping_roles(*models, timeout_s=timeout_s, api_base=api_base, failure=failure)
