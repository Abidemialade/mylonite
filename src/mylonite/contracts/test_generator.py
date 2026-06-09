"""TestGenerator extension point.

Given a confirmed :class:`ExploitRecord`, emit a regression test that
reproduces the weakness as an assertion. v0.1.0 ships a pytest reference
implementation; jest follows in Phase 5.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Literal, Protocol, runtime_checkable

from mylonite.contracts._types import ExploitRecord, GeneratedTest

CONTRACT_VERSION: str = "0.1.0"


@runtime_checkable
class TestGenerator(Protocol):
    """Structural type for test generators."""

    contract_version: ClassVar[str]

    def framework(self) -> Literal["pytest", "jest"]: ...

    def emit(self, exploit: ExploitRecord) -> GeneratedTest: ...


class TestGeneratorBase(ABC):
    """ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def framework(self) -> Literal["pytest", "jest"]: ...

    @abstractmethod
    def emit(self, exploit: ExploitRecord) -> GeneratedTest: ...
