"""Each reference plugin must satisfy its contract's runtime-checkable ABC."""

from __future__ import annotations

from mylonite.contracts import (
    AsyncTargetAdapter,
    AttackModule,
    ComplianceMapper,
    Validator,
)
from mylonite.contracts import TestGenerator as _TestGenerator

# Aliased: pytest's default class-discovery rule treats names starting with
# "Test" as test classes, which the Protocol is not.
from mylonite.plugins._reference.reference_attack_module import ReferenceAttackModule
from mylonite.plugins._reference.reference_compliance_mapper import (
    ReferenceComplianceMapper,
)
from mylonite.plugins._reference.reference_pytest_generator import (
    ReferencePytestGenerator,
)
from mylonite.plugins._reference.reference_target_adapter import (
    InProcessGuardedReferenceAdapter,
    InProcessVulnerableReferenceAdapter,
)
from mylonite.plugins._reference.reference_validator import NullValidator


def test_reference_attack_module_is_attack_module() -> None:
    assert isinstance(ReferenceAttackModule(), AttackModule)


def test_inprocess_vulnerable_adapter_is_async_target_adapter() -> None:
    assert isinstance(InProcessVulnerableReferenceAdapter(), AsyncTargetAdapter)


def test_inprocess_guarded_adapter_is_async_target_adapter() -> None:
    assert isinstance(InProcessGuardedReferenceAdapter(), AsyncTargetAdapter)


def test_reference_pytest_generator_is_test_generator() -> None:
    assert isinstance(ReferencePytestGenerator(), _TestGenerator)


def test_null_validator_is_validator() -> None:
    assert isinstance(NullValidator(), Validator)


def test_reference_compliance_mapper_is_compliance_mapper() -> None:
    assert isinstance(ReferenceComplianceMapper(), ComplianceMapper)
