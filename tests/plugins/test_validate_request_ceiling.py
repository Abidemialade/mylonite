"""Validation under the hard LLM request ceiling: it stops sending at the
limit and never returns a verdict built on what it saw before the stop.
Offline, scripted LLM."""

from __future__ import annotations

import asyncio
import functools
from typing import Any

import pytest
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _emit_test,
    _ScriptedCompletion,
)

from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)
from mylonite.scan._llm import (
    REQUEST_CEILING_ENV,
    BudgetExceededError,
    LLMRequestCeilingError,
    request_ceiling_hit,
    requests_sent,
    reset_request_ceiling,
)


def _validate() -> Any:
    validator = DifferentialValidator(iterations=3, completion_fn=_ScriptedCompletion())
    return validator.validate(
        _emit_test(_build_exploit()),
        ReferenceVulnerableOracle().adapter(),
        ReferenceVulnerableOracle(),
    )


@functools.cache
def _uncapped_requests() -> int:
    report = _validate()
    assert report.kept is True, report.notes
    total = requests_sent()
    reset_request_ceiling()
    return total


@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9, 0.99])
def test_validation_stopped_by_the_ceiling_returns_no_verdict(
    monkeypatch: pytest.MonkeyPatch, fraction: float
) -> None:
    """Any stop point, including late in the metamorphic stage (0.9 and later),
    where a refused request used to read as "never judged" and the finding
    came back kept."""
    total = _uncapped_requests()
    limit = max(1, int(total * fraction))
    assert limit < total
    monkeypatch.setenv(REQUEST_CEILING_ENV, str(limit))
    with pytest.raises(LLMRequestCeilingError):
        _validate()
    assert requests_sent() <= limit
    assert request_ceiling_hit() == limit


def test_reference_adapter_does_not_turn_a_budget_stop_into_a_skip() -> None:
    """A skipped attempt counts as tried; a budget stop must stay a stop."""

    async def refuse(**_kw: Any) -> Any:
        raise BudgetExceededError("spent")

    adapter = InProcessReferenceAdapter(variant="vulnerable", completion_fn=refuse)
    payload = _build_exploit().payload
    with pytest.raises(BudgetExceededError):
        asyncio.run(adapter.invoke(payload))


def test_a_scan_the_ceiling_cut_short_reads_budget_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a refused request was swallowed where the engine cannot see it, the
    scan still ends as a budget abort, never as a finished scan."""
    from mylonite.contracts import AbortReason
    from mylonite.scan import engine as engine_mod
    from mylonite.scan.wiring import build_scan, note_id_counter

    def _scan() -> Any:
        engine = build_scan(
            "vulnerable",
            completion_fn=_ScriptedCompletion(),
            note_id_factory=note_id_counter(),
            provider="anthropic",
            model="claude-haiku-4-5-20251001",
            pattern_id_filter=_build_exploit().pattern_id,
        )
        return asyncio.run(engine.run())

    assert _scan().report.aborted is None
    monkeypatch.setattr(engine_mod, "request_ceiling_hit", lambda: 7)
    assert _scan().report.aborted == AbortReason.BUDGET_EXCEEDED
