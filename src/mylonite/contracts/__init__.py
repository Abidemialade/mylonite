"""Versioned extension-point contracts.

Five Protocols + ABCs, each with a ``CONTRACT_VERSION``. See ``CONTRIBUTING.md``
and ``GOVERNANCE.md`` for the contract-change process.
"""

from __future__ import annotations

from mylonite.contracts._types import (
    AdapterResponse,
    AttackPattern,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    TargetDescriptor,
    ToolSpec,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.contracts.attack_module import AttackModule, AttackModuleBase
from mylonite.contracts.compliance_mapper import (
    ComplianceMapper,
    ComplianceMapperBase,
)
from mylonite.contracts.target_adapter import (
    AsyncTargetAdapter,
    AsyncTargetAdapterBase,
    TargetAdapter,
    TargetAdapterBase,
)
from mylonite.contracts.test_generator import TestGenerator, TestGeneratorBase
from mylonite.contracts.validator import (
    Validator,
    ValidatorBase,
    VulnerableOracle,
)

__all__ = [
    "AdapterResponse",
    "AsyncTargetAdapter",
    "AsyncTargetAdapterBase",
    "AttackModule",
    "AttackModuleBase",
    "AttackPattern",
    "ComplianceMapper",
    "ComplianceMapperBase",
    "ComplianceTags",
    "ExploitRecord",
    "GeneratedTest",
    "Payload",
    "TargetAdapter",
    "TargetAdapterBase",
    "TargetDescriptor",
    "TestGenerator",
    "TestGeneratorBase",
    "ToolSpec",
    "ValidationOutcome",
    "ValidationReport",
    "Validator",
    "ValidatorBase",
    "VulnerableOracle",
]
