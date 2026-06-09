"""Reference validator — NullValidator.

Phase 0 only proves the Validator contract loads. The differential-oracle
pipeline (build -> differential-seeded check -> 5-run flakiness filter ->
metamorphic robustness) lands in Phase 2 of PLAN.md.
"""

from __future__ import annotations

from typing import ClassVar

from mylonite.contracts import (
    GeneratedTest,
    ValidationOutcome,
    ValidationReport,
    ValidatorBase,
)
from mylonite.contracts.target_adapter import TargetAdapter
from mylonite.contracts.validator import CONTRACT_VERSION, VulnerableOracle


class NullValidator(ValidatorBase):
    """Returns a 'not implemented' report. Useful as a default."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def validate(
        self,
        test: GeneratedTest,
        target: TargetAdapter,
        oracle: VulnerableOracle,
    ) -> ValidationReport:
        del target, oracle
        return ValidationReport(
            test_filename=test.filename,
            outcomes=[
                ValidationOutcome(
                    stage="build",
                    passed=False,
                    detail="NullValidator: real validation engine arrives in Phase 2.",
                ),
            ],
            kept=False,
            notes="reference plugin — does not validate",
        )
