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
    """Enriches a finding's tags using the bundled taxonomy.

    Consults the bundled NIST AI RMF cross-references to derive NIST subcategory
    ids from the finding's OWASP LLM/ASI tags (no per-seed NIST tagging). Other
    frameworks pass through unchanged.
    """

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def map(self, exploit: ExploitRecord) -> ComplianceTags:
        from mylonite.taxonomy.compliance import enrich_with_nist

        return enrich_with_nist(exploit.compliance)
