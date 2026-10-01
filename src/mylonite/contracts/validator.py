"""Validator extension point — Mylonite's validation engine moat.

This module defines the Protocol and ships a ``NullValidator`` reference plugin.
The real differential-oracle pipeline (build -> differential-seeded check
-> 5-run flakiness filter -> metamorphic robustness) is implemented in
``ROADMAP.md``.

A vulnerable oracle is a deliberately-unguarded variant of the target. A
generated test is "meaningful" iff:

* it FAILs against the vulnerable oracle (the weakness exists, the test
  catches it),
* it PASSes against the guarded target (the guard holds),
* it does both reliably across at least five runs,
* it survives metamorphic perturbations of the payload.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Protocol, runtime_checkable

from mylonite.contracts._types import GeneratedTest, ValidationReport
from mylonite.contracts.target_adapter import TargetAdapter

# 0.2.0 -> 0.3.0: additive — ValidationOutcome.stage gained "stability",
# "effect", "consensus" legs for custom-target validation (re-driving the real
# target instead of the bundled twin). Existing consumers/legs unchanged.
# 0.3.0 -> 0.4.0: additive — ValidationReport gained structured evidence fields
# (gating_formula, gating_legs, reproducibility, mutation_matrix) lifted out of
# the free-text ``notes`` so surfaces can render the differential oracle's
# discrimination. All optional/defaulted; existing reports stay valid.
# 0.4.0 -> 0.5.0: additive — ReproducibilityEvidence gained guard_fired and
# rate_gap, the statistical differential's leak count + success-rate gap. The
# oracle now gates on the success-RATE gap between the twins rather than a
# count threshold (keeps probabilistic LLM-mediated exploits). Both fields are
# optional/defaulted; existing reports stay valid.
CONTRACT_VERSION: str = "0.5.0"


class VulnerableOracle(Protocol):
    """A deliberately-unguarded variant of a target.

    The Protocol is defined here so the Validator
    signature is stable from v0.1.0.
    """

    def adapter(self) -> TargetAdapter: ...


@runtime_checkable
class Validator(Protocol):
    """Structural type for validators."""

    contract_version: ClassVar[str]

    def validate(
        self,
        test: GeneratedTest,
        target: TargetAdapter,
        oracle: VulnerableOracle,
    ) -> ValidationReport: ...


class ValidatorBase(ABC):
    """ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def validate(
        self,
        test: GeneratedTest,
        target: TargetAdapter,
        oracle: VulnerableOracle,
    ) -> ValidationReport: ...
