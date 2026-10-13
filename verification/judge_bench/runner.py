"""Run benchmark cases through the real ``SuccessJudge``.

Every judge is built exactly as production builds it --
``SuccessJudge(model=model, completion_fn=fn)`` -- with no temperature or policy
override: the call's settings come from the active ``LLMPolicy``
(``scan/llm_policy.py``) through the same chokepoint a scan uses.

Each verdict is folded into one of four categories:

* ``landed`` / ``not_landed`` -- the LLM judge decided;
* ``abstain`` -- no verdict: ``fallback_cause`` set, ``evidence["no_adjudicator"]``
  set, or ``applicable`` False. Never read as a negative;
* ``routed_deterministic`` -- a predicate (not the LLM) decided. Excluded from
  every LLM-judge metric and counted separately;
* ``provider_error`` -- the judge call itself failed (rate limit, timeout,
  network, auth, a content-filter stop): the provider never answered, so this
  is neither a verdict nor an abstention. Counted separately; any one of them
  makes the run incomplete. A reply that arrived but is not parseable stays an
  ``abstain``.

The headline is repeat 1 only. Majority-of-3 and repeat agreement are
secondary figures (:func:`majority_of`, :func:`repeat_agreement`); repeats
never add to n.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Coroutine, Iterable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from mylonite._concurrency import gather_bounded
from mylonite.scan._llm import FALLBACK_CALL_RAISED, NonRecoverableProviderError
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.llm_types import AsyncCompletionFn
from verification.judge_bench.cases import BenchCase

Category = Literal["landed", "not_landed", "abstain", "routed_deterministic", "provider_error"]

#: ``fallback_cause`` set on an outcome whose judge call raised a non-recoverable
#: provider error (auth, TLS, a rejected request such as a content filter).
NON_RECOVERABLE = "non_recoverable_provider_error"
#: ``fallback_cause`` set when the provider stopped the reply for content filtering.
CONTENT_FILTERED = "content_filter"

REASON_LIMIT = 300

#: ``completion_fn_for(model, repeat)``: the completion function for one model
#: and one repeat. Repeats need their own function (with a recorder: their own
#: fixtures directory), because a recorder keys on (model, messages) and would
#: otherwise hand every repeat the first repeat's reply.
CompletionFnFor = Callable[[str, int], AsyncCompletionFn]


class CaseOutcome(BaseModel):
    """One judge call on one case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    model: str
    repeat: int
    mechanism: str
    category: Category
    confidence: float | None = None
    harmful_intent: bool | None = None
    reason: str = ""
    fallback_cause: str | None = None


class _ReplyCapture:
    """Wraps one completion function and keeps the raw reply text.

    Lets the outcome record ``harmful_intent_present`` from the judge's own
    reply on every branch (the verdict's evidence carries it only on the
    not-applicable branch) without touching the product judge.
    """

    def __init__(self, fn: AsyncCompletionFn) -> None:
        self._fn = fn
        self.content: str | None = None
        self.finish_reason: str | None = None

    async def __call__(self, **kwargs: Any) -> Any:
        response = await self._fn(**kwargs)
        try:
            choice = response.choices[0]
            self.content = str(choice.message.content or "")
            self.finish_reason = getattr(choice, "finish_reason", None)
        except (AttributeError, IndexError, KeyError, TypeError):
            self.content = None
        return response


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def _reply_flag(content: str | None, key: str) -> bool | None:
    """A strict boolean ``key`` from the judge's JSON reply, else ``None``."""
    if not content:
        return None
    match = _JSON_OBJECT.search(content)
    if match is None:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, bool) else None


def _as_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


async def judge_case(
    case: BenchCase,
    judge: SuccessJudge,
    *,
    model: str = "",
    repeat: int = 1,
    capture: _ReplyCapture | None = None,
) -> CaseOutcome:
    """Judge one case and categorise the verdict."""
    verdict = await judge.judge(case.to_payload(), case.to_response())
    evidence = verdict.evidence
    category: Category
    fallback_cause = verdict.fallback_cause
    filtered = capture is not None and capture.finish_reason == CONTENT_FILTERED
    if fallback_cause == FALLBACK_CALL_RAISED or (filtered and verdict.mechanism == "llm"):
        category = "provider_error"
        if fallback_cause != FALLBACK_CALL_RAISED:
            fallback_cause = CONTENT_FILTERED
    elif verdict.fallback_cause or evidence.get("no_adjudicator") or not verdict.applicable:
        category = "abstain"
    elif verdict.mechanism != "llm":
        category = "routed_deterministic"
    else:
        category = "landed" if verdict.success else "not_landed"
    harmful = evidence.get("harmful_intent_present")
    harmful_intent = harmful if isinstance(harmful, bool) else None
    if harmful_intent is None and capture is not None and verdict.mechanism == "llm":
        harmful_intent = _reply_flag(capture.content, "harmful_intent_present")
    return CaseOutcome(
        case_id=case.case_id,
        model=model,
        repeat=repeat,
        mechanism=verdict.mechanism,
        category=category,
        confidence=_as_float(evidence.get("confidence")),
        harmful_intent=harmful_intent,
        reason=verdict.reason[:REASON_LIMIT],
        fallback_cause=fallback_cause,
    )


async def _one(case: BenchCase, model: str, repeat: int, fn: AsyncCompletionFn) -> CaseOutcome:
    capture = _ReplyCapture(fn)
    judge = SuccessJudge(model=model, completion_fn=capture)
    try:
        return await judge_case(case, judge, model=model, repeat=repeat, capture=capture)
    except NonRecoverableProviderError as exc:
        # The chokepoint re-raises auth/TLS/bad-request failures. Record the case
        # as a provider error rather than aborting the run, so the summary can
        # say exactly how much of the run never got an answer.
        return CaseOutcome(
            case_id=case.case_id,
            model=model,
            repeat=repeat,
            mechanism="llm",
            category="provider_error",
            # The category only: the raw provider text can echo request details.
            reason=f"non-recoverable provider error [{exc.diagnosis.category}]",
            fallback_cause=NON_RECOVERABLE,
        )


async def run(
    cases: Sequence[BenchCase],
    models: Sequence[str],
    repeats: int,
    completion_fn_for: CompletionFnFor,
    *,
    limit: int | None = None,
) -> list[CaseOutcome]:
    """Judge every case for every model and repeat; bounded concurrency.

    Returns outcomes sorted by (model, repeat, case_id), so output files are
    byte-stable.
    """
    if repeats < 1:
        raise ValueError(f"repeats must be >= 1; got {repeats}")
    coros: list[Coroutine[Any, Any, CaseOutcome]] = []
    for model in models:
        for repeat in range(1, repeats + 1):
            fn = completion_fn_for(model, repeat)
            coros.extend(_one(case, model, repeat, fn) for case in cases)
    if limit is None:
        outcomes = await gather_bounded(coros)
    else:
        outcomes = await gather_bounded(coros, limit=limit)
    return sorted(outcomes, key=lambda o: (o.model, o.repeat, o.case_id))


def headline(outcomes: Iterable[CaseOutcome], model: str) -> list[CaseOutcome]:
    """The single-call headline outcomes for ``model``: repeat 1 only."""
    return [o for o in outcomes if o.model == model and o.repeat == 1]


def _by_case(outcomes: Iterable[CaseOutcome], model: str) -> dict[str, list[CaseOutcome]]:
    grouped: dict[str, list[CaseOutcome]] = defaultdict(list)
    for o in outcomes:
        if o.model == model:
            grouped[o.case_id].append(o)
    for rows in grouped.values():
        rows.sort(key=lambda o: o.repeat)
    return grouped


def majority_of(outcomes: Iterable[CaseOutcome], model: str, k: int = 3) -> list[CaseOutcome]:
    """Majority-of-``k`` per case (secondary figure only, never the bar).

    Uses repeats 1..k; a case with fewer than ``k`` repeats is skipped. The
    result is one synthetic outcome per case (``repeat=0``) whose category is
    the strict-majority category, or ``abstain`` when no category has one.
    """
    out: list[CaseOutcome] = []
    for _case_id, rows in sorted(_by_case(outcomes, model).items()):
        first = [o for o in rows if o.repeat <= k]
        if len(first) < k:
            continue
        top, count = Counter(o.category for o in first).most_common(1)[0]
        category: Category = top if count * 2 > k else "abstain"
        base = first[0]
        out.append(
            base.model_copy(
                update={
                    "repeat": 0,
                    "category": category,
                    "reason": f"majority of {k}: {count}/{k} {top}",
                }
            )
        )
    return out


def repeat_agreement(outcomes: Iterable[CaseOutcome], model: str) -> dict[str, Any]:
    """Share of cases (with at least two repeats) where every repeat agrees."""
    groups = [rows for rows in _by_case(outcomes, model).values() if len(rows) >= 2]
    agree = sum(1 for rows in groups if len({o.category for o in rows}) == 1)
    return {"cases": len(groups), "agree": agree, "rate": agree / len(groups) if groups else None}


def dump_outcomes(outcomes: Iterable[CaseOutcome]) -> str:
    """JSONL text for outcomes: key-sorted, one per line, stable across runs."""
    return "".join(
        json.dumps(o.model_dump(mode="json"), sort_keys=True, ensure_ascii=False) + "\n"
        for o in outcomes
    )


__all__ = [
    "REASON_LIMIT",
    "CaseOutcome",
    "Category",
    "CompletionFnFor",
    "dump_outcomes",
    "headline",
    "judge_case",
    "majority_of",
    "repeat_agreement",
    "run",
]
