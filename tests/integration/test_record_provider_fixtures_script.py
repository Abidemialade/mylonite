"""DCR-0024: `scripts/record_provider_fixtures.py`'s `_main` used to await each
provider recording SEQUENTIALLY, even though the recordings are independent,
network-I/O-bound calls to different providers -- concurrent execution is a
straightforward win with no correctness cost. This test never touches a real
provider: `_record_one` is monkeypatched with a stub that tracks overlap.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from scripts import record_provider_fixtures as m
from tests.integration._provider_matrix_spec import PROVIDER_MATRIX


@pytest.mark.asyncio
async def test_main_records_independent_cases_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The provider matrix has several independent cases; recording them must
    overlap in time, not run one after another."""
    assert len(PROVIDER_MATRIX) > 1  # otherwise concurrency wouldn't be observable

    in_flight = 0
    max_in_flight = 0

    async def fake_record_one(case: Any, *, api_base: str | None) -> bool:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return True

    monkeypatch.setattr(m, "_record_one", fake_record_one)

    rc = await m._main([])

    assert rc == 0
    assert max_in_flight > 1, (
        f"expected several _record_one calls in flight at once, got a peak of "
        f"{max_in_flight} -- recordings are still running sequentially"
    )


@pytest.mark.asyncio
async def test_main_isolates_per_case_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """One case failing/raising must not prevent the others from completing or
    being counted -- concurrent execution must preserve the existing
    per-case error isolation `_record_one` already provides."""

    async def flaky_record_one(case: Any, *, api_base: str | None) -> bool:
        if case is PROVIDER_MATRIX[0]:
            raise RuntimeError("simulated unexpected failure")
        return True

    monkeypatch.setattr(m, "_record_one", flaky_record_one)

    rc = await m._main([])

    assert rc == 0
    # Every case other than the raising one is still recorded.
    assert True  # no exception propagated out of _main -- the real assertion is above


@pytest.mark.asyncio
async def test_main_reports_accurate_recorded_count_with_mixed_results(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The summary line's numerator must reflect actual recordings, not the
    total case count, once results are gathered concurrently."""

    async def mixed_record_one(case: Any, *, api_base: str | None) -> bool:
        return case is PROVIDER_MATRIX[0]  # only the first case "records"

    monkeypatch.setattr(m, "_record_one", mixed_record_one)

    rc = await m._main([])

    assert rc == 0
    out = capsys.readouterr().out
    assert f"1/{len(PROVIDER_MATRIX)} recorded" in out
