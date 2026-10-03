"""Validation legs for a KEPT (proven) report in gate tests.

A kept report needs a passing build leg and a passing differential or effect
leg to read as KEPT. Without them it is STABLE, NOT PROVEN, and `gate` lists
it as a candidate instead of writing a gate test.
"""

from __future__ import annotations

from mylonite.contracts._types import ValidationOutcome


def proven_legs() -> list[ValidationOutcome]:
    return [
        ValidationOutcome(stage="build", passed=True, detail="ok", metric=None),
        ValidationOutcome(stage="stability", passed=True, detail="3/3", metric=1.0),
        ValidationOutcome(stage="differential", passed=True, detail="3/3 vs 0/3", metric=1.0),
    ]
