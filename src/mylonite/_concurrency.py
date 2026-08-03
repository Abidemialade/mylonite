"""Run independent async work concurrently — the convention this repo never had.

Every place that compares a vulnerable variant against a guarded twin awaited
them one after another, each inside its own blocking ``asyncio.run()``. Four
different chunk reviews found eight-plus instances across five files. The
commands this appears in (``validate``, ``gate``, ``demo --live``, the
verification scorer) all gate CI, and each pays roughly 2-3x its achievable wall
time for no correctness reason.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Sequence
from typing import Any, TypeVar

T = TypeVar("T")

#: Default fan-out for provider calls. Low enough to stay inside typical
#: per-minute rate limits; override per call site where the provider allows more.
DEFAULT_LIMIT = 4


async def gather_bounded(
    coros: Sequence[Coroutine[Any, Any, T]], *, limit: int = DEFAULT_LIMIT
) -> list[T]:
    """Await ``coros`` concurrently, at most ``limit`` at a time, in input order.

    Unlike a bare ``asyncio.gather`` this bounds fan-out, which matters because
    every caller here is issuing live provider calls under a rate limit.
    """
    if limit < 1:
        msg = f"limit must be >= 1; got {limit}"
        raise ValueError(msg)
    sem = asyncio.Semaphore(limit)

    async def _run(coro: Coroutine[Any, Any, T]) -> T:
        async with sem:
            return await coro

    return list(await asyncio.gather(*(_run(c) for c in coros)))


async def run_twins(
    vulnerable: Coroutine[Any, Any, T], guarded: Coroutine[Any, Any, T]
) -> tuple[T, T]:
    """Drive a vulnerable/guarded twin pair concurrently.

    The two are independent by construction — the differential compares their
    results, neither feeds the other — so the sequential form was pure latency.
    """
    result = await asyncio.gather(vulnerable, guarded)
    return result[0], result[1]


__all__ = ["DEFAULT_LIMIT", "gather_bounded", "run_twins"]
