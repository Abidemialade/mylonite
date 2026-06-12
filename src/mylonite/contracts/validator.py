"""Validator extension point — Mylonite's validation engine moat.

Phase 0 ships only the Protocol and a ``NullValidator`` reference plugin.
The real differential-oracle pipeline (build -> differential-seeded check
-> 5-run flakiness filter -> metamorphic robustness) arrives in Phase 2 of
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
CONTRACT_VERSION: str = "0.3.0"


class VulnerableOracle(Protocol):
    """A deliberately-unguarded variant of a target.

    Phase 2 will flesh this out. The Protocol is here so the Validator
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
