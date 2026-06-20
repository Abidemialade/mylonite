"""ComplianceMapper extension point.

Tags an :class:`ExploitRecord` with OWASP LLM Top 10, OWASP Agentic Security
Initiative, MITRE ATLAS, and NIST AI RMF identifiers. This is the basis for
audit-evidence reporting.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Protocol, runtime_checkable

from mylonite.contracts._types import ComplianceTags, ExploitRecord

CONTRACT_VERSION: str = "0.1.0"


@runtime_checkable
class ComplianceMapper(Protocol):
    """Structural type for compliance mappers."""

    contract_version: ClassVar[str]

    def map(self, exploit: ExploitRecord) -> ComplianceTags: ...


class ComplianceMapperBase(ABC):
    """ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def map(self, exploit: ExploitRecord) -> ComplianceTags: ...
