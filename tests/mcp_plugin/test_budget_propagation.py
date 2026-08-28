"""Budget exhaustion is a decision, not a fault, and must exit one way.

``BudgetExceededError`` used to produce three different exit codes depending on
which layer happened to see it first:

* 3 from the engine, which re-raises it so ``run()`` can flip
  ``aborted="budget_exceeded"``;
* 2 or 0 from the adapter, whose ``except Exception`` catch-all converted it
  into an ``AdapterInvocationSkipped`` and reported it as
  ``skipped_planner_failure`` -- the run then looked like it had merely skipped
  an attempt rather than run out of money;
* 1 from the validator's path, where it propagated correctly but no CLI handler
  existed, so it surfaced as an uncaught traceback.

The adapter's re-raise tuple is the control-flow allowlist: an exception that
represents a DECISION (stop, the budget is gone) belongs in it; only genuine
faults are allowed to collapse into a skipped attempt.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.scan._llm import BudgetExceededError
from mylonite.scan._types import AdapterInvocationSkipped


class _BudgetExhaustedSessionCM:
    async def __aenter__(self) -> Any:
        raise BudgetExceededError("LLM call budget exhausted (12/12)")

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


@pytest.mark.asyncio
async def test_budget_exhaustion_is_not_downgraded_to_a_skipped_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _BudgetExhaustedSessionCM())

    payload = Payload(pattern_id="p", channel="tool-result", body="x")

    # It must reach the caller intact so the engine can abort the run, NOT be
    # converted into a per-attempt skip that reads as "we tried and moved on".
    with pytest.raises(BudgetExceededError):
        await adapter.invoke(payload)


@pytest.mark.asyncio
async def test_a_genuine_fault_is_still_downgraded_to_a_skipped_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The allowlist must stay narrow: real faults still become skips."""

    class _FaultySessionCM:
        async def __aenter__(self) -> Any:
            raise ValueError("something genuinely broke")

        async def __aexit__(self, *exc_info: object) -> bool:
            return False

    adapter = MCPStdioAdapter(family="fetch", scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _FaultySessionCM())

    with pytest.raises(AdapterInvocationSkipped):
        await adapter.invoke(Payload(pattern_id="p", channel="tool-result", body="x"))
