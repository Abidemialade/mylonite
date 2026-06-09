"""Reference compliance mapper — naive pass-through."""

from __future__ import annotations

from typing import ClassVar

from mylonite.contracts import (
    ComplianceMapperBase,
    ComplianceTags,
    ExploitRecord,
)
from mylonite.contracts.compliance_mapper import CONTRACT_VERSION


class ReferenceComplianceMapper(ComplianceMapperBase):
    """Returns the compliance tags already present on the exploit record.

    Real mappers consult the bundled taxonomy and infer additional tags from
    the attack pattern. This stub just passes through whatever upstream set.
    """

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def map(self, exploit: ExploitRecord) -> ComplianceTags:
        return exploit.compliance
