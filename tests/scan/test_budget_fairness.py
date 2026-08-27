"""Per-seed budget reservation.

`LiteLLMCallCounter` was one first-come-first-served counter, and the engine
creates every payload task up front. Whichever seeds started first drained the
pool; the rest never made a single call. That was survivable while every probe
was one LLM call. It is not now that a probe can be a CHAIN of two or three: a
~14-tool server can synthesise enough seeds to exhaust the default 50 before a
single bundled seed runs.

Worse, it does not fail loudly. A chain cut off after step one HAS called a tool
-- just never the tool under test -- which is precisely the shape
`judge.never_exercised_tool_under_test` exists to catch. Budget starvation and
false cleans are the same mechanism seen from two ends, which is why the floor
lands alongside the chain probes rather than after them.
"""

from __future__ import annotations

import pytest

from mylonite.scan._llm import BudgetExceededError, LiteLLMCallCounter, seed_scope


def _spend(counter: LiteLLMCallCounter, seed: str, n: int) -> int:
    """Spend up to ``n`` calls as ``seed``; return how many succeeded."""
    spent = 0
    with seed_scope(seed):
        for _ in range(n):
            try:
                counter.record("planner")
            except BudgetExceededError:
                break
            spent += 1
    return spent


def test_a_greedy_seed_cannot_starve_the_others() -> None:
    """The regression this exists for.

    One seed tries to consume the whole budget before the others start --
    exactly what eager task creation plus a shared counter allows.
    """
    counter = LiteLLMCallCounter(cap=12)
    counter.reserve_for(4)

    _spend(counter, "greedy", 100)

    for seed in ("second", "third", "fourth"):
        assert _spend(counter, seed, 1) == 1, f"{seed} was starved by the first seed"


def test_every_seed_gets_at_least_the_floor() -> None:
    counter = LiteLLMCallCounter(cap=12)
    counter.reserve_for(4)  # floor = 3
    assert counter.per_seed_floor == 3

    _spend(counter, "greedy", 100)
    assert _spend(counter, "later", 3) == 3
    assert _spend(counter, "later", 1) == 0, "the floor is a floor, not a second budget"


def test_the_floor_never_drops_below_the_minimum() -> None:
    """A huge fan-out must still leave each seed enough to be attempted at all.

    `cap // seed_count` goes to zero long before the seed count does, and a floor
    of zero is the starvation this fixes.
    """
    counter = LiteLLMCallCounter(cap=10)
    counter.reserve_for(50)
    assert counter.per_seed_floor == 2
    _spend(counter, "greedy", 100)
    assert _spend(counter, "late", 2) == 2


def test_calls_are_attributed_per_seed() -> None:
    counter = LiteLLMCallCounter(cap=20)
    counter.reserve_for(2)
    _spend(counter, "seed-a", 3)
    _spend(counter, "seed-b", 1)
    assert counter.by_seed == {"seed-a": 3, "seed-b": 1}
    # The existing per-caller breakdown is unaffected.
    assert counter.by_caller == {"planner": 4}


def test_without_reservation_behaviour_is_unchanged() -> None:
    """Any caller that never reserves keeps the old shared-pool semantics.

    `testkit`'s bounded re-drive and every ad-hoc counter rely on this.
    """
    counter = LiteLLMCallCounter(cap=3)
    assert _spend(counter, "seed-a", 10) == 3
    assert _spend(counter, "seed-b", 1) == 0


def test_unattributed_calls_still_respect_the_cap() -> None:
    """Outside a seed scope there is no floor to fall back on."""
    counter = LiteLLMCallCounter(cap=2)
    counter.reserve_for(4)
    spent = 0
    for _ in range(10):
        try:
            counter.record("judge")
        except BudgetExceededError:
            break
        spent += 1
    assert spent == 2


def test_reserve_for_is_a_no_op_on_an_empty_scan() -> None:
    counter = LiteLLMCallCounter(cap=10)
    counter.reserve_for(0)
    assert counter.per_seed_floor == 0


def test_seed_scope_restores_the_previous_attribution() -> None:
    counter = LiteLLMCallCounter(cap=10)
    counter.reserve_for(2)
    with seed_scope("outer"):
        counter.record("planner")
        with seed_scope("inner"):
            counter.record("planner")
        counter.record("planner")
    assert counter.by_seed == {"outer": 2, "inner": 1}


@pytest.mark.asyncio
async def test_concurrent_seeds_do_not_cross_attribute() -> None:
    """Each asyncio task gets its own copy of the context, so two payloads
    running concurrently cannot be charged to each other."""
    import asyncio

    counter = LiteLLMCallCounter(cap=20)
    counter.reserve_for(2)

    async def work(seed: str, n: int) -> None:
        with seed_scope(seed):
            for _ in range(n):
                counter.record("planner")
                await asyncio.sleep(0)

    await asyncio.gather(work("a", 3), work("b", 5))
    assert counter.by_seed == {"a": 3, "b": 5}
