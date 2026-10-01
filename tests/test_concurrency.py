"""Tests for the shared concurrency helpers (``gather_bounded`` / ``run_twins``)."""

from __future__ import annotations

import asyncio

import pytest

from mylonite._concurrency import gather_bounded, run_twins


@pytest.mark.asyncio
async def test_gather_bounded_respects_the_limit() -> None:
    active, peak = 0, 0

    async def work() -> int:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return 1

    results = await gather_bounded([work() for _ in range(10)], limit=3)
    assert results == [1] * 10
    assert peak <= 3


@pytest.mark.asyncio
async def test_gather_bounded_preserves_input_order() -> None:
    async def work(n: int) -> int:
        await asyncio.sleep(0.01 * (5 - n))
        return n

    assert await gather_bounded([work(i) for i in range(5)], limit=5) == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_gather_bounded_rejects_a_sub_one_limit() -> None:
    async def work() -> int:
        return 1

    coro = work()
    try:
        with pytest.raises(ValueError, match="limit must be >= 1"):
            await gather_bounded([coro], limit=0)
    finally:
        coro.close()  # never awaited (rejected before the gather) — close explicitly


@pytest.mark.asyncio
async def test_gather_bounded_default_limit_is_four() -> None:
    active, peak = 0, 0

    async def work() -> int:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return 1

    results = await gather_bounded([work() for _ in range(12)])
    assert results == [1] * 12
    assert peak <= 4


@pytest.mark.asyncio
async def test_run_twins_runs_concurrently_and_preserves_order() -> None:
    order: list[str] = []

    async def slow_vulnerable() -> str:
        await asyncio.sleep(0.02)
        order.append("vulnerable")
        return "vuln-result"

    async def fast_guarded() -> str:
        await asyncio.sleep(0.0)
        order.append("guarded")
        return "guard-result"

    # The guarded coroutine finishes first (it's faster), but the RETURN TUPLE
    # must still be (vulnerable_result, guarded_result) regardless of finish
    # order — asyncio.gather preserves input order, not completion order.
    vuln_result, guard_result = await run_twins(slow_vulnerable(), fast_guarded())
    assert order == ["guarded", "vulnerable"]  # guarded genuinely finished first
    assert vuln_result == "vuln-result"
    assert guard_result == "guard-result"


@pytest.mark.asyncio
async def test_run_twins_is_concurrent_not_sequential() -> None:
    """``run_twins`` must run both coroutines concurrently, not one after the
    other -- proven by overlap evidence, not a wall-clock threshold.

    A wall-clock budget (e.g. "two 0.05s sleeps must finish in under 0.09s")
    is flaky under a loaded machine (parallel test workers): the two sleeps
    genuinely overlap but the elapsed wall time can still creep past a tight
    threshold on scheduling delay alone (#230). Instead, each coroutine
    records when it starts and stops on a shared timeline; concurrent
    execution means both are "in flight" at the same instant (B starts
    before A finishes), which a purely sequential ``await a; await b`` could
    never produce regardless of machine speed.
    """
    events: list[tuple[str, str]] = []

    async def sleep_a() -> None:
        events.append(("a", "start"))
        await asyncio.sleep(0.05)
        events.append(("a", "stop"))

    async def sleep_b() -> None:
        events.append(("b", "start"))
        await asyncio.sleep(0.05)
        events.append(("b", "stop"))

    await run_twins(sleep_a(), sleep_b())

    a_start, a_stop = events.index(("a", "start")), events.index(("a", "stop"))
    b_start, b_stop = events.index(("b", "start")), events.index(("b", "stop"))
    # Overlap means each one's start happened before the OTHER's stop. A
    # sequential run (a fully, then b fully) would put one start after the
    # other's stop instead.
    assert a_start < b_stop
    assert b_start < a_stop
