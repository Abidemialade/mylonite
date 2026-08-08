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
    ReproducibilityEvidence,
    SeedKill,
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
from mylonite.contracts.exec_context import (
    ALLOWED_METADATA_KEYS,
    METADATA_PREFIX,
    ExecContext,
)
from mylonite.contracts.target_adapter import (
    AsyncTargetAdapter,
    AsyncTargetAdapterBase,
    AttackSession,
    SupportsAttackSession,
    TargetAdapter,
    TargetAdapterBase,
    ToolCallOutcome,
)
from mylonite.contracts.test_generator import TestGenerator, TestGeneratorBase
from mylonite.contracts.validator import (
    Validator,
    ValidatorBase,
    VulnerableOracle,
)

__all__ = [
    "ALLOWED_METADATA_KEYS",
    "METADATA_PREFIX",
    "AdapterResponse",
    "AsyncTargetAdapter",
    "AsyncTargetAdapterBase",
    "AttackModule",
    "AttackModuleBase",
    "AttackPattern",
    "AttackSession",
    "ComplianceMapper",
    "ComplianceMapperBase",
    "ComplianceTags",
    "ExecContext",
    "ExploitRecord",
    "GeneratedTest",
    "Payload",
    "ReproducibilityEvidence",
    "SeedKill",
    "SupportsAttackSession",
    "TargetAdapter",
    "TargetAdapterBase",
    "TargetDescriptor",
    "TestGenerator",
    "TestGeneratorBase",
    "ToolCallOutcome",
    "ToolSpec",
    "ValidationOutcome",
    "ValidationReport",
    "Validator",
    "ValidatorBase",
    "VulnerableOracle",
]
