"""Offline capability-contract suite (T16/H5) — the actual deliverable.

``tests/integration/test_provider_matrix.py`` proves the chokepoint FUNCTIONS
in ``scan/_llm.py`` work against real providers (once fixtures exist).
``tests/scan/test_llm_call_chokepoint.py`` (T14) proves — via an AST walk —
that nothing OUTSIDE those chokepoint functions calls
``litellm.completion``/``litellm.acompletion`` directly. Neither proves the
thing THIS suite proves: that every real production LLM call SITE
(customiser, judge, planner, gate-mitigation) actually reaches one of those
chokepoints with the active :class:`~mylonite.scan.llm_policy.LLMPolicy`'s
kwargs genuinely present in what gets sent — not just that the chokepoint
function ITSELF merges the policy correctly in isolation (``test_llm.py``
already covers that with a bare ``completion_fn`` stub), but that the CALL
SITE actually threads its own ``completion_fn``/``model`` through to the
chokepoint without silently dropping or shadowing anything along the way.

100% offline: every case below drives the real production class/function
(``PayloadCustomiser``, ``SuccessJudge``, ``LLMPlanner``, ``gate.mitigation.
_llm_suggestion``) with a stub ``completion_fn`` that just records the kwargs
it was called with — the same ``seen: list[dict]`` kwargs-capture pattern
``tests/scan/test_llm.py`` already uses on the chokepoint functions directly.

The plan's own framing: "a new call site added without the policy fails --
that is the structural test." Three things make that true here:

1. :func:`test_call_site_carries_active_llm_policy_kwargs` — parametrised
   over ``CASES`` below, one per real call site.
2. :func:`test_every_literal_caller_label_used_in_src_is_covered_by_this_suite`
   — an AST walk (mirroring T10/T14's own "class killer" style) over every
   literal ``caller=...`` string passed to a chokepoint function anywhere
   under ``src/mylonite``, cross-checked against ``CASES``' own caller
   labels. This is what makes an OMISSION from ``CASES`` visible: a future
   PR that adds a fifth, correctly-wired call site (so it passes T14's
   direct-litellm-call AST walk) but forgets to add a case here fails THIS
   test instead of silently shipping an uncovered call site.
3. :func:`test_capability_contract_has_teeth_against_a_policy_bypassing_call_site`
   — proves point 1's assertion actually has teeth, by replicating the exact
   pre-T14 bug shape (a call site invoking its stub directly, skipping the
   policy merge entirely) and confirming the SAME assertion helper the
   parametrised test uses catches it.
"""

from __future__ import annotations

import ast
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
    TargetDescriptor,
    ToolSpec,
)
from mylonite.gate.mitigation import _llm_suggestion
from mylonite.scan._llm import llm_scope
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.llm_planner import LLMPlanner
from mylonite.scan.llm_policy import LLMPolicy
from mylonite.scan.llm_types import ToolDescription
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern

_MODEL = "capability-contract-stub-model"

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "mylonite"

_CHOKEPOINT_FN_NAMES = frozenset(
    {
        "litellm_json_call",
        "litellm_json_call_async",
        "litellm_tool_call_async",
        "litellm_text_call",
    }
)


# --- response / stub builders -------------------------------------------------


def _stub_response(text: str, *, tool_calls: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=tool_calls))]
    )


def _make_async_stub(
    seen: list[dict[str, Any]], response: SimpleNamespace
) -> Callable[..., Awaitable[Any]]:
    async def stub(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return response

    return stub


def _make_sync_stub(seen: list[dict[str, Any]], response: SimpleNamespace) -> Callable[..., Any]:
    def stub(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return response

    return stub


# --- per-call-site fixtures ----------------------------------------------------


def _customiser_seed() -> SeedPattern:
    return SeedPattern(
        pattern_id="capability-contract-seed",
        weakness="W2",
        channel="tool-result",
        seed_body="SEED BODY",
        setup="seed_note",
        drive="read_note_for_summary",
        predicate="send_email_to_attacker",
        applicable_targets=["kitchen-sink"],
        compliance=ComplianceTags(owasp_llm=["LLM01"], owasp_asi=["ASI01"]),
    )


def _customiser_target() -> TargetDescriptor:
    return TargetDescriptor(
        target_id="capability-contract-target",
        kind="mcp",
        system_prompt="You are a helpful agent.",
        tools=[ToolSpec(name="read_note", description="read by id", json_schema={})],
    )


def _judge_payload() -> Payload:
    return Payload(
        pattern_id="capability-contract",
        channel="tool-result",
        body="ATTACK",
        metadata={
            "seed_id": "capability-contract",
            "weakness": "W2",
            "predicate": "send_email_to_attacker",
            "setup": "seed_note",
            "drive": "read_note_for_summary",
        },
    )


def _judge_response() -> AdapterResponse:
    # tool_calls non-empty but names no email tool -> "send_email_to_attacker"
    # returns None (inconclusive), which is what forces the LLM-judge
    # fallback path (the one that actually calls the chokepoint) to run.
    return AdapterResponse(
        payload_pattern_id="capability-contract",
        raw_response="",
        tool_calls=["read_note"],
        metadata={},
    )


class _FakePlannerServer:
    """No tools -> the planner's first (only) iteration gets a no-tool-calls
    response and returns; ``call_tool`` must never be invoked."""

    async def list_tools(self) -> list[ToolDescription]:
        return []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        raise AssertionError(f"call_tool({name!r}) should never be invoked in this contract test")


def _mitigation_exploit() -> ExploitRecord:
    seed = SEED_CATALOGUE[0]
    return ExploitRecord(
        target_id="capability-contract:target",
        pattern_id=seed.pattern_id,
        payload=Payload(pattern_id=seed.pattern_id, channel="user-message", body="x", metadata={}),
        response=AdapterResponse(
            payload_pattern_id=seed.pattern_id, raw_response="", tool_calls=[], metadata={}
        ),
        success_reason="capability contract probe",
        compliance=seed.compliance,
    )


# --- invoking each real call site ---------------------------------------------


async def _invoke_customiser(stub: Callable[..., Any]) -> None:
    cust = PayloadCustomiser(model=_MODEL, completion_fn=stub)
    await cust.customise(_customiser_seed(), _customiser_target())


async def _invoke_judge(stub: Callable[..., Any]) -> None:
    judge = SuccessJudge(model=_MODEL, completion_fn=stub)
    await judge.judge(_judge_payload(), _judge_response())


async def _invoke_planner(stub: Callable[..., Any]) -> None:
    planner = LLMPlanner(server=_FakePlannerServer(), model=_MODEL, completion_fn=stub)
    await planner.run("hello")


async def _invoke_mitigation(stub: Callable[..., Any]) -> None:
    # _llm_suggestion is SYNC (litellm_text_call is the sync chokepoint) --
    # wrapped in an async function only so every _CallSiteCase.invoke has a
    # uniform awaitable signature for the parametrised test below.
    _llm_suggestion(_mitigation_exploit(), completion_fn=stub, model=_MODEL)


@dataclass(frozen=True)
class _CallSiteCase:
    name: str
    #: The literal ``caller=...`` string this call site's chokepoint call
    #: uses — cross-referenced against every literal ``caller=...`` found
    #: under ``src/mylonite`` by the AST-walk test below.
    caller: str
    #: Whether this call site's ``completion_fn`` must be a coroutine
    #: function (customiser/judge/planner go through the async chokepoints;
    #: gate.mitigation goes through the sync ``litellm_text_call``).
    is_async_stub: bool
    response: SimpleNamespace
    invoke: Callable[[Callable[..., Any]], Awaitable[None]]


CASES: tuple[_CallSiteCase, ...] = (
    _CallSiteCase(
        name="customiser",
        caller="customiser",
        is_async_stub=True,
        response=_stub_response('{"body": "REFINED"}'),
        invoke=_invoke_customiser,
    ),
    _CallSiteCase(
        name="judge",
        caller="judge",
        is_async_stub=True,
        response=_stub_response('{"success": true, "confidence": 0.9, "reason": "y"}'),
        invoke=_invoke_judge,
    ),
    _CallSiteCase(
        name="planner",
        caller="planner",
        is_async_stub=True,
        response=_stub_response("done", tool_calls=None),
        invoke=_invoke_planner,
    ),
    _CallSiteCase(
        name="gate_mitigation",
        caller="gate_mitigation",
        is_async_stub=False,
        response=_stub_response("a mitigation suggestion"),
        invoke=_invoke_mitigation,
    ),
)

_KNOWN_CALLER_LABELS = frozenset(c.caller for c in CASES)


# --- the contract assertion -----------------------------------------------------


def _assert_policy_kwargs_present(kwargs: dict[str, Any], policy: LLMPolicy) -> None:
    """The 6 kwargs every ``scan._llm`` chokepoint function merges STRAIGHT
    from the active :class:`LLMPolicy` with no per-call override — see
    ``litellm_json_call``/``_async``/``litellm_tool_call_async``/
    ``litellm_text_call``'s own ``call_kwargs`` construction: none of them
    ever touch ``temperature``/``max_tokens``/``num_retries``/
    ``drop_params``/``seed``/``api_base``, only ``model``/``messages``/
    ``timeout``/``tools``/``response_format``.

    ``timeout`` is deliberately NOT asserted here: ``litellm_json_call``/
    ``_async`` (customiser/judge) always pass their OWN ``timeout_s``
    (defaulting to ``DEFAULT_LLM_CALL_TIMEOUT_S``), which wins over the
    policy's ``timeout`` on the exact name collision BY DESIGN (see
    ``litellm_json_call``'s docstring) — while ``litellm_tool_call_async``/
    ``litellm_text_call`` (planner/mitigation) default ``timeout_s=None`` and
    so DO defer to the policy's ``timeout``. Asserting timeout equality
    uniformly across all four call sites would be actively WRONG for two of
    them, not a stronger check.
    """
    assert kwargs.get("temperature") == policy.temperature, kwargs
    assert kwargs.get("max_tokens") == policy.max_tokens, kwargs
    assert kwargs.get("num_retries") == policy.num_retries, kwargs
    assert kwargs.get("drop_params") == policy.drop_params, kwargs
    assert kwargs.get("seed") == policy.seed, kwargs
    assert kwargs.get("api_base") == policy.api_base, kwargs


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
@pytest.mark.asyncio
async def test_call_site_carries_active_llm_policy_kwargs(case: _CallSiteCase) -> None:
    """The main deliverable: drive the REAL call site (not the chokepoint
    function directly) with a scoped, non-default policy and assert every
    load-bearing kwarg genuinely reached the stubbed completion."""
    seen: list[dict[str, Any]] = []
    stub = (
        _make_async_stub(seen, case.response)
        if case.is_async_stub
        else _make_sync_stub(seen, case.response)
    )
    policy = LLMPolicy(
        temperature=0.37,
        max_tokens=123,
        timeout=17.5,
        num_retries=4,
        drop_params=False,
        seed=99,
        api_base="https://policy-test.internal/v1",
    )
    with llm_scope(policy=policy):
        await case.invoke(stub)
    assert seen, f"{case.name}: completion_fn was never invoked"
    _assert_policy_kwargs_present(seen[0], policy)


# --- structural safety net: every literal caller= label is represented --------


def _iter_literal_caller_labels() -> set[str]:
    """AST-walk every ``src/mylonite/*.py`` file for a literal ``caller="..."``
    keyword argument passed to one of the chokepoint functions (mirrors
    ``test_llm_call_chokepoint.py``'s own AST-walk style)."""
    found: set[str] = set()
    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                fn_name: str | None = func.id
            elif isinstance(func, ast.Attribute):
                fn_name = func.attr
            else:
                fn_name = None
            if fn_name not in _CHOKEPOINT_FN_NAMES:
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "caller"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    found.add(kw.value.value)
    return found


def test_every_literal_caller_label_used_in_src_is_covered_by_this_suite() -> None:
    """Closes the gap a plain parametrised list cannot close on its own: if a
    NEW LLM call site is added, correctly routed through a ``scan._llm``
    chokepoint function (so it passes ``test_llm_call_chokepoint.py``'s own
    AST-walk), but its ``caller=...`` literal is not ALSO added to ``CASES``
    above, this test fails — forcing the omission into the PR diff instead of
    silently shipping a call site this suite never actually exercises.

    The complementary direction (a stale ``CASES`` entry whose caller label
    no longer appears anywhere) is checked too, so this suite can't silently
    drift out of sync with a call site that was removed or renamed.
    """
    literal_callers = _iter_literal_caller_labels()
    missing = literal_callers - _KNOWN_CALLER_LABELS
    stale = _KNOWN_CALLER_LABELS - literal_callers
    assert not missing, (
        f"found caller=... label(s) {sorted(missing)} passed to a scan._llm "
        "chokepoint function that are NOT represented in this suite's CASES "
        "parametrisation -- add a new _CallSiteCase (or extend an existing "
        "one) so the capability contract actually covers it."
    )
    assert not stale, (
        f"CASES declares caller label(s) {sorted(stale)} that no longer appear "
        "as a literal caller=... anywhere under src/mylonite -- this suite's "
        "parametrisation is stale and should be updated."
    )


# --- proving the contract test actually has teeth ------------------------------


@pytest.mark.asyncio
async def test_capability_contract_has_teeth_against_a_policy_bypassing_call_site(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves :func:`test_call_site_carries_active_llm_policy_kwargs` would
    actually catch a regression, by replicating the EXACT bug shape T14 fixed
    (see ``test_llm_call_chokepoint.py``'s docstring): before T14,
    ``LLMPlanner.run()`` called its ``completion_fn`` directly with NO
    ``LLMPolicy`` merge at all. Monkeypatch the name ``llm_planner.py``
    imports (``litellm_tool_call_async``) with a fake that reproduces exactly
    that bypass, drive the same planner invocation the "planner" case above
    uses, and confirm ``_assert_policy_kwargs_present`` — the SAME helper the
    parametrised test uses — raises. Auto-reverts via ``monkeypatch``.
    """
    seen: list[dict[str, Any]] = []

    async def bypassing_tool_call(
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: Any = None,
        tool_choice: Any = None,
        caller: str = "planner",
        completion_fn: Callable[..., Any] | None = None,
        timeout_s: float | None = None,
    ) -> Any:
        assert completion_fn is not None
        # The pre-T14 shape: call the raw completion_fn with model/messages
        # ONLY -- no active_policy().kwargs() merge whatsoever.
        return await completion_fn(model=model, messages=messages)

    monkeypatch.setattr("mylonite.scan.llm_planner.litellm_tool_call_async", bypassing_tool_call)

    policy = LLMPolicy(temperature=0.37, max_tokens=123, num_retries=4, drop_params=False, seed=99)
    stub = _make_async_stub(seen, _stub_response("done", tool_calls=None))
    with llm_scope(policy=policy):
        await _invoke_planner(stub)
    assert seen, "the bypassing stub must still have been invoked"
    with pytest.raises(AssertionError):
        _assert_policy_kwargs_present(seen[0], policy)
