"""Tests for the offline precision/recall corpus (PR5).

Deterministic and offline: drives the kitchen-sink twins, no LLM. Asserts the
oracle perfectly separates the seeded twins AND that the confusion-matrix math
is real (not a hardcoded 1.0) by feeding it synthetic FP/FN rows.
"""

from __future__ import annotations

from mylonite.corpus import CaseResult, ConfusionMatrix, confusion_matrix, run_corpus


def test_corpus_perfectly_separates_the_twins() -> None:
    results, cm = run_corpus()
    # Two rows per weakness (vulnerable + guarded), four weaknesses.
    assert len(results) == 8
    assert {r.weakness for r in results} == {"W1", "W2", "W3", "W4"}
    # Every vulnerable twin is detected; every guarded twin is cleared.
    assert all(r.correct for r in results), [r for r in results if not r.correct]
    assert cm.tp == 4 and cm.tn == 4
    assert cm.fp == 0 and cm.fn == 0
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.false_positive_rate == 0.0
    assert cm.f1 == 1.0


def test_corpus_each_variant_label_is_grounded() -> None:
    results, _ = run_corpus()
    for r in results:
        # Ground truth: vulnerable variants are positives, guarded are negatives.
        assert r.expected_exploited == (r.variant == "vulnerable")


def test_confusion_matrix_math_is_real() -> None:
    """A synthetic corpus with a false positive + false negative — proves the
    numbers move (the perfect-separation result above isn't hardcoded)."""
    rows = [
        # 3 true positives
        CaseResult("W2", "vulnerable", True, True, "tp"),
        CaseResult("W3", "vulnerable", True, True, "tp"),
        CaseResult("W4", "vulnerable", True, True, "tp"),
        # 1 false negative (a real weakness missed)
        CaseResult("W1", "vulnerable", True, False, "fn"),
        # 1 false positive (a guarded twin wrongly flagged)
        CaseResult("W2", "guarded", False, True, "fp"),
        # 3 true negatives
        CaseResult("W1", "guarded", False, False, "tn"),
        CaseResult("W3", "guarded", False, False, "tn"),
        CaseResult("W4", "guarded", False, False, "tn"),
    ]
    cm = confusion_matrix(rows)
    assert (cm.tp, cm.fp, cm.fn, cm.tn) == (3, 1, 1, 3)
    assert cm.precision == 3 / 4  # 3 TP / (3 TP + 1 FP)
    assert cm.recall == 3 / 4  # 3 TP / (3 TP + 1 FN)
    assert cm.false_positive_rate == 1 / 4  # 1 FP / (1 FP + 3 TN)


def test_confusion_matrix_empty_is_well_defined() -> None:
    cm = ConfusionMatrix(tp=0, fp=0, fn=0, tn=0)
    # No predictions / no positives → vacuously perfect, zero false alarms.
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.false_positive_rate == 0.0
