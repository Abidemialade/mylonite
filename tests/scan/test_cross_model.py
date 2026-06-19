"""T2: cross-model durability summary."""

from __future__ import annotations

from types import SimpleNamespace

from mylonite.scan.cross_model import CrossModelRow, row_from_report, summarize_cross_model


def _report(*, kept: bool, vuln: int, guard: int, iters: int = 5) -> SimpleNamespace:
    return SimpleNamespace(
        kept=kept,
        reproducibility=SimpleNamespace(iterations=iters, vuln_fired=vuln, guard_resisted=guard),
    )


def test_row_from_report_pulls_counts() -> None:
    row = row_from_report("claude-haiku-4-5", _report(kept=True, vuln=5, guard=5))
    assert row.model == "claude-haiku-4-5"
    assert row.kept and row.vuln_fired == 5 and row.guard_resisted == 5 and row.iterations == 5


def test_summary_all_models_durable() -> None:
    rows = [
        CrossModelRow("m1", kept=True, vuln_fired=5, guard_resisted=5, iterations=5),
        CrossModelRow("m2", kept=True, vuln_fired=4, guard_resisted=5, iterations=5),
    ]
    all_durable, text = summarize_cross_model(rows)
    assert all_durable is True
    assert "m1" in text and "m2" in text
    assert "holds across all" in text.lower()
    assert "re-emerg" not in text.lower()


def test_summary_flags_a_model_where_the_weakness_re_emerges() -> None:
    rows = [
        CrossModelRow("m1", kept=True, vuln_fired=5, guard_resisted=5, iterations=5),
        CrossModelRow("m2-newer", kept=False, vuln_fired=5, guard_resisted=1, iterations=5),
    ]
    all_durable, text = summarize_cross_model(rows)
    assert all_durable is False
    assert "m2-newer" in text
    assert "re-emerg" in text.lower() or "does not hold" in text.lower()
    assert "durability gap" in text.lower()
    # the durable model is NOT flagged as failing
    assert "m1: " in text


def test_summary_empty() -> None:
    all_durable, text = summarize_cross_model([])
    assert all_durable is True  # vacuously; caller guards against empty models
    assert text
