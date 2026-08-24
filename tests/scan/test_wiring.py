"""Tests for the neutral scan-wiring home (Phase 2, PR 1).

``build_scan`` / ``note_id_counter`` live in ``mylonite.scan.wiring`` so
non-demo consumers (``mylonite.testkit``, the validator) can depend on a
stable module with no relationship to any onboarding/demo surface. These
tests assert:

* the neutral helpers are importable and callable;
* the deterministic note-id factory yields ``n_demo_0001``, ``n_demo_0002`` and
  a fresh factory resets to ``0001``;
* ``build_scan`` threads its config knobs (pattern_id_filter, per-role models)
  correctly into the engine it builds.

Historical note: this module originally also guarded a code move (these
helpers relocating out of the since-removed ``mylonite.demo.runner``, with a
back-compat alias and a no-drift replay check) — both retired once that
onboarding surface was removed; the wiring itself is unaffected.
"""

from __future__ import annotations

from mylonite.scan import wiring


def test_neutral_helpers_importable_and_callable() -> None:
    """The promoted helpers exist under ``mylonite.scan.wiring`` and are callable."""
    assert callable(wiring.build_scan)
    assert callable(wiring.note_id_counter)


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


def test_build_scan_threads_role_models() -> None:
    """``build_scan`` routes per-role models to the planner adapter / customiser /
    judge, each defaulting to ``model`` when unset."""
    engine = wiring.build_scan(
        "vulnerable",
        completion_fn=None,
        note_id_factory=None,
        provider="anthropic",
        model="base-model",
        planner_model="planner-x",
        judge_model="judge-y",
    )
    # The adapter (planner) and judge carry their overrides; customiser defaults.
    assert engine._adapter._model == "planner-x"
    assert engine._judge._model == "judge-y"
    assert engine._customiser._model == "base-model"
    # ScanConfig records the explicit overrides (None where unset).
    assert engine._config.resolved_planner_model == "planner-x"
    assert engine._config.resolved_judge_model == "judge-y"
    assert engine._config.resolved_customiser_model == "base-model"


def test_scan_config_resolved_models_default_to_model() -> None:
    """Each resolved_* model falls back to ``model`` when its override is unset."""
    from mylonite.scan.engine import ScanConfig

    cfg = ScanConfig(target_id="t", provider="anthropic", model="m", planner_model="p")
    assert cfg.resolved_planner_model == "p"
    assert cfg.resolved_customiser_model == "m"
    assert cfg.resolved_judge_model == "m"
