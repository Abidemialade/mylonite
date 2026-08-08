"""TestGenerator extension point.

Given a confirmed :class:`ExploitRecord`, emit a regression test that
reproduces the weakness as an assertion. v0.1.0 shipped a pytest reference
implementation; other frameworks can follow via the plugin.

**0.2.0 (0.7.10)**: ``emit`` gained an optional ``context: ExecContext | None
= None`` keyword parameter -- the promotion of the T12 ``Payload.metadata``
shim (``mylonite.exec.*``, reserved via issue #78) into a real, typed
parameter. A generator that doesn't care about the model/provider that
discovered an exploit can ignore it; ``ReferencePytestGenerator`` uses it to
render explicit ``model=``/``provider=`` literals into the emitted test
instead of falling back to a hardcoded default. See CHANGELOG.md for the
third-party plugin-author migration path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Literal, Protocol, runtime_checkable

from mylonite.contracts._types import ExploitRecord, GeneratedTest
from mylonite.contracts.exec_context import ExecContext

CONTRACT_VERSION: str = "0.2.0"


@runtime_checkable
class TestGenerator(Protocol):
    """Structural type for test generators."""

    contract_version: ClassVar[str]

    def framework(self) -> Literal["pytest", "jest"]: ...

    def emit(self, exploit: ExploitRecord, context: ExecContext | None = None) -> GeneratedTest: ...


class TestGeneratorBase(ABC):
    """ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def framework(self) -> Literal["pytest", "jest"]: ...

    @abstractmethod
    def emit(self, exploit: ExploitRecord, context: ExecContext | None = None) -> GeneratedTest: ...
