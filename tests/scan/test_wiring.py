"""Tests for the promoted neutral scan-wiring home (Phase 2, PR 1).

``build_scan`` / ``note_id_counter`` were moved verbatim out of
``mylonite.demo.runner`` into ``mylonite.scan.wiring`` so non-demo consumers
(``mylonite.testkit`` in PR 2, the validator in PR 5) can depend on a stable,
demo-independent module. These tests assert:

* the neutral helpers are importable and callable;
* the back-compat aliases on ``mylonite.demo.runner`` are the *same objects*
  (identity), so existing importers and the monkeypatch seam keep working;
* the deterministic note-id factory yields ``n_demo_0001``, ``n_demo_0002`` and
  a fresh factory resets to ``0001``;
* the load-bearing no-drift guard: the offline demo replay still works with
  **0 cache misses** (proving the moved wiring didn't change message hashing),
  with the vulnerable scan showing findings and the guarded scan showing none.
"""

from __future__ import annotations

from mylonite.demo import runner as runner_mod
from mylonite.demo.runner import run_demo
from mylonite.scan import wiring


def test_neutral_helpers_importable_and_callable() -> None:
    """The promoted helpers exist under ``mylonite.scan.wiring`` and are callable."""
    assert callable(wiring.build_scan)
    assert callable(wiring.note_id_counter)


def test_back_compat_aliases_are_identical() -> None:
    """``runner._build_scan`` / ``_note_id_counter`` re-export the neutral helpers."""
    assert runner_mod._build_scan is wiring.build_scan
    assert runner_mod._note_id_counter is wiring.note_id_counter


def test_note_id_counter_is_deterministic_and_resets() -> None:
    """Each ``note_id_counter()`` is an independent 0001-based sequence."""
    first = wiring.note_id_counter()
    assert first() == "n_demo_0001"
    assert first() == "n_demo_0002"
    # A fresh counter restarts at 0001 — what makes per-variant reset work.
    second = wiring.note_id_counter()
    assert second() == "n_demo_0001"


def test_build_scan_threads_pattern_id_filter() -> None:
    """``build_scan(..., pattern_id_filter=X)`` → engine config carries the filter."""
    engine = wiring.build_scan(
        "guarded",
        completion_fn=None,
        note_id_factory=None,
        provider="anthropic",
        model="stub-model",
        pattern_id_filter="foo",
    )
    assert engine._config.pattern_id_filter == "foo"


def test_build_scan_defaults_pattern_id_filter_none() -> None:
    """Omitting ``pattern_id_filter`` → full scan (None), preserving back-compat."""
    engine = wiring.build_scan(
        "guarded",
        completion_fn=None,
        note_id_factory=None,
        provider="anthropic",
        model="stub-model",
    )
    assert engine._config.pattern_id_filter is None


async def test_offline_replay_has_no_drift() -> None:
    """No-drift guard: the packaged-fixture replay still resolves cleanly.

    Replaying the committed fixtures through the *moved* wiring must produce
    the vulnerable findings and a clean guarded scan with zero cache misses.
    ``run_demo(live=False)`` raises ``DemoFixtureError`` on any cache miss or
    recorded error, so reaching this assertion already proves 0 cache misses;
    the findings-count assertions pin the differential outcome.
    """
    result = await run_demo(live=False)

    assert result.mode == "replay (offline)"
    assert result.vulnerable.report.findings_count >= 1
    assert result.guarded.report.findings_count == 0
