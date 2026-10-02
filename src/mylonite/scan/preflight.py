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
#: the preflight's own bound: a stuck/slow real custom target must not be able
#: to block a CI job indefinitely just because the flag was left unset. 120s
#: comfortably covers a real subprocess spawn + a multi-turn planner run; pass
#: a larger value explicitly for a target known to need more headroom. The CLI
#: imports this one value, so the two cannot drift.
DEFAULT_ITERATION_TIMEOUT_S: Final = 120.0


@dataclass
class PreflightFailure:
    """Why a failed preflight failed: the diagnosis category of the refused
    call (``rate_limit``, ``network``, ``auth`` ...), or ``None`` when unknown.
    """

    category: str | None = None


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


def provider_preflight_direct(
    provider: str,
    model: str,
    *,
    timeout_s: float,
    failure: PreflightFailure | None = None,
) -> bool:
    """Reachability probe that does NOT route through the bundled reference target.

    A custom-target validate has no reason to touch ``mcp_kitchen_sink`` — its
    re-drive uses the operator's own target. But the reference-scan preflight
    (below) imports and RUNS ``InProcessReferenceAdapter``, so a user validating
    THEIR app was forced to `pip install mcp-kitchen-sink` (a deliberately
    vulnerable demo) just to run an "is my provider reachable" check, and hit a
    hard exit 2 without it. This does the same reachability check with a single
    minimal LLM completion instead. Returns True iff the provider answered.
    """
    from mylonite.scan._llm import BudgetExceededError, litellm_tool_call_async
    from mylonite.scan.diagnostics import classify_provider_error
    from mylonite.scan.providers import provider_from_model

    _ = provider  # provider routing is carried by the model string / active policy

    async def _ping() -> bool:
        try:
            # Uses the "planner" caller label: this IS a minimal planner-shaped
            # completion (a user message + empty tools), and it routes through the
            # same chokepoint so it inherits budget-counting and the active policy.
            await litellm_tool_call_async(
                model=model,
                messages=[{"role": "user", "content": "reply with the single word: ok"}],
                tools=[],
                caller="planner",
                timeout_s=timeout_s,
            )
        except BudgetExceededError:
            raise  # a spent budget is not an unreachable provider
        except Exception as exc:
            if failure is not None:
                diagnosis = classify_provider_error(exc, provider=provider_from_model(model))
                failure.category = diagnosis.category
            return False
        return True

    try:
        return asyncio.run(_ping())
    except BudgetExceededError:
        raise
    except Exception:
        return False


def provider_preflight(
    provider: str,
    model: str,
    *,
    timeout_s: float = DEFAULT_ITERATION_TIMEOUT_S,
    failure: PreflightFailure | None = None,
) -> bool:
    """Cheap reachability probe before the (expensive) live validation loop.

    Runs ONE vulnerable reference scan. If it aborts ``provider_unreachable``,
    the validator's N-iteration loop would too — so we fail fast with a distinct
    exit 4 rather than burning iterations and reporting a misleading non-discrim
    result. Returns True iff the provider is reachable.

    For a CUSTOM target use :func:`provider_preflight_direct` instead — it does
    not pull in the bundled reference target (see its docstring).

    DCR-0008: bounded by ``timeout_s`` — this preflight exists specifically to
    fail fast rather than burn iterations, but had no bound of its own: a
    provider that accepts the connection and then stalls mid-response (rather
    than erroring outright) would hang ``asyncio.run(engine.run())``
    open-ended, hanging the CLI/CI job with no way out. A timeout is treated
    the same as any other unreachable-provider outcome (returns ``False``),
    not re-raised, so every caller's existing ``if not reachable: ...
    exit(EXIT_PROVIDER)`` handling already covers it.
    """
    from mylonite.scan.wiring import build_scan, note_id_counter

    engine = build_scan(
        "vulnerable",
        completion_fn=None,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
    )
    try:
        result = asyncio.run(asyncio.wait_for(engine.run(), timeout=timeout_s))
    except TimeoutError:
        # A provider that stalls is unreachable, not misconfigured: say so
        # rather than falling through to the credentials hint.
        if failure is not None:
            failure.category = "network"
        return False
    if result.report.aborted != "provider_unreachable":
        return True
    if failure is not None:
        failure.category = result.provider_failure_category
    return False
