"""LiteLLM call helper + process-wide call counter.

Closes the two issues the eng review surfaced:

* **A1 — budget leak.** Every LLM call in the scan loop (customiser, judge,
  in-process planner) routes through ``litellm_json_call`` /
  ``litellm_json_call_async``. The wrapper increments a single
  ``LiteLLMCallCounter`` so ``--max-llm-calls`` is a real cap, not just a
  count of orchestration calls.
* **C1 — DRY.** Customiser and Judge both did "LiteLLM call → expect JSON →
  ``try/except`` parse → fallback." Folded here into one helper with a sync
  and an async entry point.
* **T4 — don't swallow non-recoverable provider failures.** A raised
  completion-call exception is classified via
  ``diagnostics.classify_provider_error`` before falling back. auth/tls/
  context_window will never succeed on retry, so those re-raise as
  :class:`NonRecoverableProviderError` instead of quietly degrading to an
  "inconclusive" ``FALLBACK_CALL_RAISED`` verdict — a misconfigured provider
  should be a loud, actionable failure, not a silent one. Every other
  category (rate_limit, network, unknown) keeps the pre-existing
  swallow-into-fallback behaviour.

The counter is a context manager so callers can nest scopes (the
``ScanEngine`` wraps the whole run; individual calls increment via
the active context). If no context is active, calls still execute — useful for
ad-hoc tests — but no budget enforcement happens.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final

import litellm
from pydantic import BaseModel

from mylonite.scan.diagnostics import Diagnosis, classify_provider_error
from mylonite.scan.llm_parse import (
    _extract_json_candidate,
    _extract_text,
    _looks_truncated,
    _try_repair,
)
from mylonite.scan.llm_policy import LLMPolicy
from mylonite.scan.llm_types import AsyncCompletionFn, CompletionFn
from mylonite.scan.model_ref import ModelRef
from mylonite.scan.providers import provider_from_model
from mylonite.scan.schema_sanitise import SchemaDialect, dialect_for, sanitise_tool_schema

logger = logging.getLogger(__name__)

#: Default per-call bound (seconds) passed to LiteLLM's own ``timeout``
#: parameter (DCR-0011/DCR-0018). Distinct from — and a backstop under — any
#: OUTER ``asyncio.wait_for`` a caller wraps around a multi-call sequence (e.g.
#: the MCP adapter's ``planner_timeout_s`` bounds the whole multi-turn planner
#: run): a single stuck provider call inside that sequence should not be able
#: to silently eat the whole budget before the outer bound even gets a chance
#: to fire on a slow-but-technically-still-progressing series of calls.
DEFAULT_LLM_CALL_TIMEOUT_S: Final = 60.0


def fence(*parts: str) -> str:
    """A per-call delimiter tag for fencing target-controlled text in a prompt.

    Shared by the customiser (``customiser._build_prompt``) and the judge
    (``judge._build_judge_prompt``) — both build evaluator prompts that embed
    target-controlled text (tool descriptions, system prompt, the target's
    final response). Mylonite tests OTHER systems for exactly this class of
    weakness (prompt injection via unfenced/predictably-labelled untrusted
    text), so its own evaluator prompts should not be trivially splice-able by
    a target that embeds "ignore the above" style content. A per-call tag
    (rather than a fixed literal like ``TARGET TOOLS:``) is harder for a
    generic, pre-written injection payload to guess and close.

    Deliberately DETERMINISTIC (a hash of the call's own inputs), not
    ``secrets``/``random``/a timestamp: this is a pure function of stable
    identifiers (seed id, target id, ...), so the SAME seed run against the
    SAME target builds the byte-identical prompt on a re-run — useful for
    caching/debugging with zero security downside, since the fence's job is
    defeating a generic, non-targeted splicing attempt, not withstanding an
    adversary who already has source access to compute it. This also keeps
    the customiser's/judge's ``(model, messages)`` pair reproducible. (Neither
    is even called at all when a caller sets ``llm_assist=False`` — see
    ``wiring.build_scan`` — but staying deterministic costs nothing and
    avoids relying on that fact.)
    """
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"MYLONITE-FENCE-{digest}"


class BudgetExceededError(RuntimeError):
    """Raised when an LLM call would push the active counter over its cap."""


#: Diagnosis categories (see ``diagnostics.classify_provider_error``) that will
#: NEVER succeed on retry — a misconfigured API key, a TLS/cert failure, or a
#: prompt that exceeds the model's context window are all deterministic, not
#: transient. Swallowing these into ``FALLBACK_CALL_RAISED`` (the same bucket
#: as a one-off network blip) turns a loud, actionable misconfiguration into a
#: quiet "inconclusive" — the worst possible failure mode for a security tool.
#: Every OTHER category (rate_limit, network, unknown) keeps the existing
#: swallow-into-fallback behaviour unchanged: those genuinely can clear up on
#: their own or on a later run.
_NON_RECOVERABLE_CATEGORIES: Final = frozenset({"auth", "tls", "context_window"})


class NonRecoverableProviderError(RuntimeError):
    """A provider-call failure that will never succeed on retry — re-raised, not swallowed.

    Raised by ``litellm_json_call``/``litellm_json_call_async`` instead of
    returning ``fallback`` when :func:`classify_provider_error` puts the
    causing exception in :data:`_NON_RECOVERABLE_CATEGORIES`. Carries the
    :class:`~mylonite.scan.diagnostics.Diagnosis` so a caller (or an
    uncaught-exception handler further up) can report the category/remedy
    instead of a bare traceback. Chained via ``raise ... from exc`` so the
    original provider exception is still visible in the traceback.
    """

    def __init__(self, diagnosis: Diagnosis, *, caller: str) -> None:
        self.diagnosis = diagnosis
        self.caller = caller
        super().__init__(
            f"{caller}: non-recoverable provider error [{diagnosis.category}]: "
            f"{diagnosis.detail} — {diagnosis.remedy}"
        )


@dataclass
class LiteLLMCallCounter:
    """Process-wide LLM-call counter, scoped via ``contextvars``.

    Construct one per scan; activate via ``with counter.active(): ...``. Every
    call to ``litellm_json_call`` / ``litellm_json_call_async`` inside that
    scope increments the counter and raises ``BudgetExceededError`` once the
    cap is hit.

    DCR-0018: :attr:`consecutive_failures` is a SINGLE counter, mutated by
    :meth:`mark_success`/:meth:`mark_failure`, shared by every call this
    counter is active for — including every concurrently-running payload
    attempt and every concurrently-running flakiness pass (``ScanEngine``
    activates exactly ONE counter for the whole ``run()``, per the class
    docstring above). It is NOT one counter per logical connection/payload.
    Under concurrency (``max_concurrent > 1`` or ``runs > 1``) this makes
    "consecutive" a best-effort, PROCESS-WIDE notion, not a strict "this one
    connection failed N times in a row": an unrelated payload's success can
    interleave and reset the shared count (masking a genuinely-failing
    payload's own streak), and unrelated failures across several different
    payloads can cumulatively trip the threshold even though no single
    payload failed that many times itself. This is an accepted, deliberate
    trade-off — see ``ScanConfig.provider_failure_threshold``'s docstring for
    why a shared, best-effort "is the provider down" signal is still a
    reasonable check to run, just not a precise per-connection one. Giving
    this genuine per-connection semantics would need per-task failure
    tracking threaded through every call site that currently just reaches
    for the single process-wide active counter — a larger design change than
    this fix, not attempted here.
    """

    cap: int
    count: int = 0
    consecutive_failures: int = 0
    by_caller: dict[str, int] = field(default_factory=dict)
    #: How many tool schemas ``litellm_tool_call_async`` has actually
    #: rewritten via ``schema_sanitise.sanitise_tool_schema`` (T15/H4) --
    #: incremented only when sanitisation had a real effect, never on every
    #: call. ``ScanEngine`` folds this into ``fallback_breakdown`` under the
    #: ``"tool_schema_sanitised"`` key once the scan finishes, so operators
    #: can see how often a STRICT-dialect provider needed the rewrite.
    tool_schema_sanitised: int = 0

    #: Calls attributed to each seed, and the floor each seed may spend even
    #: once the shared pool is gone. Both empty until ``reserve_for`` runs, so a
    #: caller that never sets up reservations behaves exactly as before.
    by_seed: dict[str, int] = field(default_factory=dict)
    per_seed_floor: int = 0

    def reserve_for(self, seed_count: int, *, minimum: int = 2) -> None:
        """Guarantee every seed a floor of the budget before sharing the rest.

        Without this the counter is first-come-first-served, and payload tasks
        are all created up front: whichever seeds happen to start first drain the
        pool and the rest never make a single call. That was survivable while
        every probe was one call. It is not now that a probe can be a CHAIN of
        two or three -- a ~14-tool server can synthesise enough seeds to exhaust
        the default 50 before a single bundled seed runs.

        It also silently manufactures false cleans: a chain cut off after step
        one has called a tool but never reached the tool under test, which is
        exactly the shape ``judge.never_exercised_tool_under_test`` exists to
        catch. Starvation must be deterministic, not a race on provider latency.

        The floor is deliberately small. It buys each seed enough to be
        *attempted*; it does not promise completion, and the honest-coverage
        machinery reports the difference.
        """
        if seed_count <= 0:
            return
        self.per_seed_floor = max(minimum, self.cap // seed_count) if self.cap else 0

    def _may_spend(self, seed: str) -> bool:
        """True when ``seed`` still has room, either shared or reserved."""
        if self.count + 1 <= self.cap:
            return True
        if not seed or self.per_seed_floor <= 0:
            return False
        return self.by_seed.get(seed, 0) < self.per_seed_floor

    def record(self, caller: str) -> None:
        seed = _ACTIVE_SEED.get() or ""
        if not self._may_spend(seed):
            msg = (
                f"--max-llm-calls budget of {self.cap} exhausted "
                f"(by caller breakdown: {self.by_caller})"
            )
            raise BudgetExceededError(msg)
        self.count += 1
        self.by_caller[caller] = self.by_caller.get(caller, 0) + 1
        if seed:
            self.by_seed[seed] = self.by_seed.get(seed, 0) + 1

    def record_schema_sanitised(self) -> None:
        """Bump :attr:`tool_schema_sanitised`. Deliberately NOT routed through
        :meth:`record` -- a schema rewrite is not an LLM call, so it must
        never count against ``--max-llm-calls`` or raise
        ``BudgetExceededError``."""
        self.tool_schema_sanitised += 1

    def mark_success(self) -> None:
        self.consecutive_failures = 0

    def mark_failure(self) -> None:
        self.consecutive_failures += 1

    @contextmanager
    def active(self) -> Iterator[None]:
        token = _ACTIVE_COUNTER.set(self)
        try:
            yield
        finally:
            _ACTIVE_COUNTER.reset(token)


_ACTIVE_COUNTER: contextvars.ContextVar[LiteLLMCallCounter | None] = contextvars.ContextVar(
    "mylonite_active_call_counter", default=None
)

#: The seed whose work the current task is doing, so the counter can attribute a
#: call without every call site having to thread an id down to it. A contextvar
#: rather than an argument for the same reason the counter itself is one: the
#: chokepoints are several layers below the engine, and `asyncio` tasks each get
#: their own copy of the context, so concurrent payloads cannot cross-attribute.
_ACTIVE_SEED: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mylonite_active_seed", default=None
)


@contextmanager
def seed_scope(seed_id: str) -> Iterator[None]:
    """Attribute every LLM call made inside this block to ``seed_id``."""
    token = _ACTIVE_SEED.set(seed_id)
    try:
        yield
    finally:
        _ACTIVE_SEED.reset(token)


def active_counter() -> LiteLLMCallCounter | None:
    """Return the currently-active counter (or ``None`` if no scope is active)."""
    return _ACTIVE_COUNTER.get()


#: Scoped the same way as ``_ACTIVE_COUNTER`` (contextvars, nestable, opt-in) —
#: see ``llm_scope``. Unlike the counter, ``active_policy`` never returns
#: ``None``: a call site that never scopes a policy at all still gets the
#: load-bearing defaults (``LLMPolicy()`` — temperature=0.0, drop_params=True,
#: ...) documented on ``LLMPolicy`` itself, rather than silently falling back
#: to a provider's own (oracle-breaking) defaults.
_ACTIVE_POLICY: contextvars.ContextVar[LLMPolicy | None] = contextvars.ContextVar(
    "mylonite_active_llm_policy", default=None
)


def active_policy() -> LLMPolicy:
    """The currently-active :class:`LLMPolicy`, or ``LLMPolicy()`` (the
    documented defaults) when nothing is scoped via :func:`llm_scope`."""
    return _ACTIVE_POLICY.get() or LLMPolicy()


@contextmanager
def llm_scope(
    *, counter: LiteLLMCallCounter | None = None, policy: LLMPolicy | None = None
) -> Iterator[None]:
    """Activate a budget counter and/or a call-kwargs policy for every LiteLLM
    call made inside the ``with`` block.

    This is THE chokepoint (H2): ``litellm_json_call``/``_async``,
    ``litellm_tool_call_async`` (the planner), and ``litellm_text_call`` (gate's
    mitigation enrichment) all read ``active_counter()``/``active_policy()``
    unconditionally, with no parallel "skip the policy" path — a new call site
    that wants budget-counting or the policy kwargs applied has nowhere else to
    plug into LiteLLM's completion API except one of those three functions, so
    it cannot silently opt out the way the pre-T14 planner call site did.

    Either argument may be omitted; omitting one leaves that contextvar
    untouched (so e.g. a caller that only wants to change the policy inside an
    already-``counter.active()``-scoped block can do so without re-passing the
    counter). Nestable — a caller can layer a narrower policy inside a wider
    one (e.g. per-command override inside a per-run default).
    """
    counter_token = _ACTIVE_COUNTER.set(counter) if counter is not None else None
    policy_token = _ACTIVE_POLICY.set(policy) if policy is not None else None
    try:
        yield
    finally:
        if policy_token is not None:
            _ACTIVE_POLICY.reset(policy_token)
        if counter_token is not None:
            _ACTIVE_COUNTER.reset(counter_token)


def _bump(caller: str) -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.record(caller)


def _mark_success() -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.mark_success()


def _mark_failure() -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.mark_failure()


def _bump_schema_sanitised() -> None:
    counter = _ACTIVE_COUNTER.get()
    if counter is not None:
        counter.record_schema_sanitised()


def _sanitised_tools(tools: list[dict[str, Any]], model: str) -> list[dict[str, Any]]:
    """Sanitise each tool's ``function.parameters`` schema for the dialect
    ``model``'s provider needs (T15/H4), before it is ever sent to LiteLLM.

    A no-op passthrough under :data:`SchemaDialect.PERMISSIVE` (OpenAI,
    Anthropic, an unrecognised provider — see ``dialect_for``'s docstring for
    why unknown defaults to permissive). Under :data:`SchemaDialect.STRICT`
    (Gemini/Vertex/Bedrock), rewrites ``$ref``/``anyOf``/``const``/
    ``additionalProperties`` into a shape those providers' function-calling
    APIs actually accept.

    Deliberately builds and returns a NEW list of (possibly new) dicts rather
    than mutating ``tools`` in place — this is the planner's OWN copy of the
    tool schema headed to the LLM, not the adapter's ``TargetDescriptor``
    (attack modules must keep reasoning over the target's real, unsanitised
    tool surface; see the module docstring on ``schema_sanitise``).

    Bumps the active counter's ``tool_schema_sanitised`` once per tool whose
    schema sanitisation actually changed (never on a no-op call, and never
    for a tool with no ``function.parameters`` at all).
    """
    # ModelRef's own provider-derivation (provider_from_model) never raises —
    # it degrades to `None` for an unroutable model (see providers.py) — so
    # constructing directly here (bypassing ModelRef.parse's raising
    # validation) is safe: `model` has already been used for the real
    # completion call by this point, so it is a non-empty string.
    ref = ModelRef(raw=model, provider=provider_from_model(model))
    dialect = dialect_for(ref)
    if dialect is SchemaDialect.PERMISSIVE:
        return tools
    sanitised: list[dict[str, Any]] = []
    for tool in tools:
        # Separate `if ... : continue` narrowing (rather than a ternary) so
        # mypy --strict actually tracks `function` as a dict from here on —
        # a ternary's isinstance check doesn't narrow the assigned name.
        if not isinstance(tool, dict):
            sanitised.append(tool)
            continue
        function = tool.get("function")
        if not isinstance(function, dict):
            sanitised.append(tool)
            continue
        parameters = function.get("parameters")
        if not isinstance(parameters, dict):
            sanitised.append(tool)
            continue
        new_parameters = sanitise_tool_schema(parameters, dialect)
        if new_parameters == parameters:
            sanitised.append(tool)
            continue
        _bump_schema_sanitised()
        new_function = dict(function)
        new_function["parameters"] = new_parameters
        new_tool = dict(tool)
        new_tool["function"] = new_function
        sanitised.append(new_tool)
    return sanitised


# Reserved, collision-proof keys stamped onto a returned fallback dict so the
# caller (judge/customiser) can distinguish *why* it got a fallback. The
# ``_mylonite_`` prefix guarantees no clash with any ``expected_keys``
# (``body`` / ``success`` / ``confidence`` / ``reason``). Callers MUST
# ``pop_fallback_cause`` so the sentinels never leak into a verdict or payload.
_FALLBACK_CAUSE_KEY: Final = "_mylonite_fallback_cause"
_FALLBACK_DETAIL_KEY: Final = "_mylonite_fallback_detail"

#: Fallback because the LiteLLM call itself raised (network / auth / TLS).
FALLBACK_CALL_RAISED: Final = "call_raised"
#: Fallback because the call returned but its text was not usable JSON.
FALLBACK_UNPARSEABLE: Final = "unparseable_output"


def _snippet(text: str, limit: int = 160) -> str:
    """A short single-line excerpt of raw model output for diagnostics."""
    return " ".join(text.split())[:limit]


def _exc_detail(exc: BaseException, limit: int = 200) -> str:
    """A short ``Type: message`` rendering of an exception for the verdict reason."""
    return f"{type(exc).__name__}: {exc}"[:limit]


def _classify_or_swallow(
    exc: Exception, *, model: str, caller: str, fallback: Mapping[str, Any]
) -> dict[str, Any]:
    """Classify a raised completion-call exception; re-raise if non-recoverable.

    auth/tls/context_window (see ``_NON_RECOVERABLE_CATEGORIES``) will never
    succeed on retry, so this raises :class:`NonRecoverableProviderError`
    instead of returning a fallback. Every other category (rate_limit,
    network, unknown) preserves the pre-existing swallow-into-fallback
    behaviour exactly — same fallback value, same log line, same
    ``FALLBACK_CALL_RAISED`` cause.
    """
    diagnosis = classify_provider_error(exc, provider=provider_from_model(model))
    if diagnosis.category in _NON_RECOVERABLE_CATEGORIES:
        logger.error(
            "%s: LiteLLM completion raised a non-recoverable [%s] error: %s",
            caller,
            diagnosis.category,
            diagnosis.detail,
        )
        _mark_failure()
        raise NonRecoverableProviderError(diagnosis, caller=caller) from exc
    logger.exception("%s: LiteLLM completion raised", caller)
    _mark_failure()
    return _with_cause(fallback, FALLBACK_CALL_RAISED, _exc_detail(exc))


def _with_cause(fallback: Mapping[str, Any], cause: str, detail: str) -> dict[str, Any]:
    """Return a copy of ``fallback`` stamped with the fallback-cause sentinels."""
    out = dict(fallback)
    out[_FALLBACK_CAUSE_KEY] = cause
    out[_FALLBACK_DETAIL_KEY] = detail
    return out


def pop_fallback_cause(result: dict[str, Any]) -> tuple[str | None, str | None]:
    """Remove and return ``(cause, detail)`` from a helper result.

    Returns ``(None, None)`` for a genuinely-parsed result. Callers should
    always call this so the reserved sentinel keys never reach a ``Verdict``,
    a ``Payload.metadata``, or downstream ``expected_keys`` validation.
    """
    cause = result.pop(_FALLBACK_CAUSE_KEY, None)
    detail = result.pop(_FALLBACK_DETAIL_KEY, None)
    return cause, detail


def _parse_or_fallback(
    response: Any,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
) -> dict[str, Any]:
    """Provider-tolerant JSON parse of a completion response; fall back on failure.

    Robust across LLMs: reads JSON from ``message.content`` (handling code
    fences + surrounding prose) OR a tool call's ``arguments``; parses strict
    JSON first, then rescues near-miss non-strict JSON with ``json-repair``;
    rejects truncated output rather than letting repair fabricate values. On any
    output-side failure the returned dict carries the ``FALLBACK_UNPARSEABLE``
    cause sentinel (see ``pop_fallback_cause``).
    """
    expected = set(expected_keys)
    raw = _extract_text(response)
    candidate = _extract_json_candidate(response)
    if candidate is None:
        if _looks_truncated(response):
            detail = "looks truncated: unbalanced '{' (provider likely hit a token limit)"
            logger.info("%s: LLM JSON looks truncated; using fallback", caller)
        else:
            detail = _snippet(raw)
            logger.info("%s: LLM returned no JSON object; using fallback", caller)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, detail)
    try:
        parsed: Any = json.loads(candidate)
    except json.JSONDecodeError:
        # Strict parse failed — try a repair pass for non-strict JSON. The
        # candidate is brace-balanced (truncation was handled above), so repair
        # rescues formatting near-misses without fabricating a missing close.
        parsed = _try_repair(candidate)
        if parsed is None:
            logger.info("%s: LLM JSON did not parse (repair failed); using fallback", caller)
            return _with_cause(fallback, FALLBACK_UNPARSEABLE, _snippet(raw))
        logger.info("%s: LLM JSON rescued by json-repair (non-strict output)", caller)
    if not isinstance(parsed, dict):
        logger.info("%s: LLM JSON was not an object; using fallback", caller)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, _snippet(raw))
    if not expected.issubset(parsed):
        missing = sorted(expected - parsed.keys())
        logger.info("%s: LLM JSON missing required keys (%s); using fallback", caller, missing)
        return _with_cause(fallback, FALLBACK_UNPARSEABLE, f"missing keys: {missing}")
    return parsed


def _supported_response_mode(model: str) -> str | None:
    """Strongest structured-output mode LiteLLM reports for ``model``, or ``None``.

    Every introspection call is guarded: an unknown/custom/proxy model (or a
    renamed LiteLLM helper in a future version) degrades to ``None`` — prose-only
    — never an error. The prompt already asks for JSON, and the tolerant parser
    still runs, so degrading is safe.
    """
    try:
        if litellm.supports_response_schema(model=model):
            return "json_schema"
    except Exception:
        logger.info("%s: supports_response_schema introspection failed; degrading", model)
    try:
        params = litellm.get_supported_openai_params(model=model) or []
        if "response_format" in params:
            return "json_object"
    except Exception:
        logger.info("%s: get_supported_openai_params introspection failed; degrading", model)
    return None


def build_response_format(model: str, schema_model: type[BaseModel] | None) -> Any | None:
    """Pick the strongest supported ``response_format`` for ``model``.

    Returns the Pydantic class for json_schema (LiteLLM translates it per
    provider, including Anthropic's tool-mode emulation), ``{"type":
    "json_object"}`` for a syntactic-JSON guarantee, or ``None`` to omit the
    parameter entirely (prose-only).
    """
    mode = _supported_response_mode(model)
    if mode == "json_schema" and schema_model is not None:
        return schema_model
    if mode in ("json_schema", "json_object"):
        return {"type": "json_object"}
    return None


def litellm_json_call(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: CompletionFn | None = None,
    schema_model: type[BaseModel] | None = None,
    timeout_s: float = DEFAULT_LLM_CALL_TIMEOUT_S,
) -> dict[str, Any]:
    """Sync wrapper around ``litellm.completion`` that returns parsed JSON.

    On a parse failure, or a call exception classified as a transient
    provider issue (rate_limit/network/unknown), returns ``fallback``. A call
    exception classified as auth/tls/context_window (see
    ``diagnostics.classify_provider_error`` — none of these will ever succeed
    on retry) raises :class:`NonRecoverableProviderError` instead. Increments
    the active call counter; raises ``BudgetExceededError`` if the cap is hit
    before the call is made.

    ``completion_fn`` exists for tests — pass a stub instead of patching the
    module. Defaults to ``litellm.completion``. Every call passes an explicit
    ``timeout`` (DCR-0018) so a single stuck provider call can't block
    indefinitely; a caller under its own outer timeout can still override
    ``timeout_s`` tighter.
    """
    _bump(caller)
    fn = completion_fn or litellm.completion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    # The active policy's kwargs (temperature/max_tokens/drop_params/seed/
    # api_base/...) first, so this call's own model/messages/timeout always win
    # on a name collision — timeout_s stays the caller-facing knob (unchanged
    # default/behaviour); the policy only ever ADDS kwargs this call never set
    # explicitly before T14 (see llm_policy.py's module docstring for why each
    # one is load-bearing for the oracle, not tuning).
    call_kwargs: dict[str, Any] = {
        **active_policy().kwargs(),
        "model": model,
        "messages": messages,
        "timeout": timeout_s,
    }
    response_format = build_response_format(model, schema_model)
    if response_format is not None:
        call_kwargs["response_format"] = response_format
    try:
        response = fn(**call_kwargs)
    except Exception as exc:
        return _classify_or_swallow(exc, model=model, caller=caller, fallback=fallback)
    _mark_success()
    return _parse_or_fallback(response, expected_keys, fallback, caller)


async def litellm_json_call_async(
    *,
    model: str,
    prompt: str,
    expected_keys: Iterable[str],
    fallback: Mapping[str, Any],
    caller: str,
    system: str | None = None,
    completion_fn: AsyncCompletionFn | None = None,
    schema_model: type[BaseModel] | None = None,
    timeout_s: float = DEFAULT_LLM_CALL_TIMEOUT_S,
) -> dict[str, Any]:
    """Async sibling of ``litellm_json_call`` using ``litellm.acompletion``.

    Passes an explicit ``timeout`` on every call (DCR-0018) — see
    ``litellm_json_call``'s docstring.
    """
    _bump(caller)
    fn = completion_fn or litellm.acompletion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    # See the sync sibling's comment: policy kwargs first, this call's own
    # model/messages/timeout always win on a name collision.
    call_kwargs: dict[str, Any] = {
        **active_policy().kwargs(),
        "model": model,
        "messages": messages,
        "timeout": timeout_s,
    }
    response_format = build_response_format(model, schema_model)
    if response_format is not None:
        call_kwargs["response_format"] = response_format
    try:
        response = await fn(**call_kwargs)
    except Exception as exc:
        return _classify_or_swallow(exc, model=model, caller=caller, fallback=fallback)
    _mark_success()
    return _parse_or_fallback(response, expected_keys, fallback, caller)


async def litellm_tool_call_async(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | None = None,
    caller: str = "planner",
    completion_fn: AsyncCompletionFn | None = None,
    timeout_s: float | None = None,
) -> Any:
    """The planner's chokepoint (H2/T14): owns budget-counting (``_bump`` +
    success/failure marking) and the active :class:`LLMPolicy`'s kwargs,
    exactly like ``litellm_json_call``/``_async`` — but returns the RAW
    LiteLLM response (``message.tool_calls`` lives there) instead of parsed
    JSON, since ``LLMPlanner``'s tool-calling loop needs the untouched
    response shape, not a verdict dict.

    Before T14 the planner called ``completion(**call_kwargs)`` directly
    (see ``llm_planner.py``'s git history), bypassing both the budget counter
    and every policy kwarg below — each adapter that drove ``LLMPlanner``
    (the in-process reference adapter, the MCP session adapter) had grown its
    own ad hoc ``_bump``-only wrapper around ``completion_fn`` to claw back
    JUST the budget-counting half. Routing ``LLMPlanner.run`` through this
    function instead is what let those wrappers be deleted — the planner now
    goes through the exact same chokepoint the customiser/judge always did.

    Exceptions propagate (marking a failure first, never swallowed into a
    fallback) — ``LLMPlanner.run``'s contract is that a completion exception
    aborts the whole run; the adapter above it decides whether that becomes
    an ``AdapterInvocationSkipped`` (single-shot ``invoke``) or a bare raise
    (a stateful ``AttackSession``'s ``drive_planner``).

    ``timeout_s=None`` (the default) defers entirely to the active policy's
    own ``timeout`` — unlike ``litellm_json_call``, which keeps its
    pre-existing ``DEFAULT_LLM_CALL_TIMEOUT_S`` default for backward
    compatibility. A caller that wants a tighter/looser per-call bound than
    the policy (e.g. ``LLMPlanner(completion_timeout_s=...)``) still overrides
    it explicitly.

    T15/H4: when ``tools`` is given, each tool's ``function.parameters``
    schema is run through ``schema_sanitise.sanitise_tool_schema`` (dialect
    resolved from ``model`` via ``schema_sanitise.dialect_for``) before it is
    handed to LiteLLM — this is the ONE place a tool schema is ever sent TO an
    LLM for tool-calling, so it's the one place that needs to close the
    STRICT-dialect-provider interop gap (Gemini/Vertex/Bedrock rejecting
    ``$ref``/``anyOf``/``const``/``additionalProperties``). The adapter's own
    ``TargetDescriptor`` (what attack modules reason over) is never touched —
    see ``_sanitised_tools``'s docstring.
    """
    _bump(caller)
    fn = completion_fn or litellm.acompletion
    policy = active_policy()
    call_kwargs: dict[str, Any] = {**policy.kwargs(), "model": model, "messages": messages}
    if timeout_s is not None:
        call_kwargs["timeout"] = timeout_s
    if tools:
        call_kwargs["tools"] = _sanitised_tools(tools, model)
        call_kwargs["tool_choice"] = tool_choice or "auto"
    try:
        response = await fn(**call_kwargs)
    except Exception:
        _mark_failure()
        raise
    _mark_success()
    return response


def litellm_text_call(
    *,
    model: str,
    prompt: str,
    caller: str,
    system: str | None = None,
    completion_fn: CompletionFn | None = None,
    timeout_s: float | None = None,
) -> str | None:
    """A free-text (not JSON) completion through the SAME chokepoint as
    ``litellm_json_call`` — budget-counted, policy-kwarg'd, provider-error
    classified — for a caller that wants prose rather than a structured
    verdict, e.g. ``gate.mitigation``'s best-effort fix suggestion (H2/T14:
    that call site used to hardcode ``litellm.completion(model="claude-
    haiku-4-5-20251001", ...)`` directly, with no budget counting, no policy
    kwargs, and — critically — no way to route through a self-hosted/proxy
    ``api_base`` at all).

    Unlike ``litellm_json_call``, ANY failure (a call exception of any
    classification, or an empty/whitespace-only response) returns ``None``
    rather than raising or falling back to a caller-supplied sentinel —
    mitigation enrichment is opportunistic and, per its own docstring, must
    never break PR-body assembly.
    """
    _bump(caller)
    fn = completion_fn or litellm.completion
    messages: list[dict[str, str]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    policy = active_policy()
    call_kwargs: dict[str, Any] = {**policy.kwargs(), "model": model, "messages": messages}
    if timeout_s is not None:
        call_kwargs["timeout"] = timeout_s
    try:
        response = fn(**call_kwargs)
    except Exception:
        logger.info("%s: LiteLLM completion raised; enrichment skipped", caller)
        _mark_failure()
        return None
    _mark_success()
    text = _extract_text(response).strip()
    return text or None
