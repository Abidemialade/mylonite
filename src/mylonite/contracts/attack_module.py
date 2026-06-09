"""AttackModule extension point.

An attack module declares static metadata (an :class:`AttackPattern`) and a
streaming method that produces payloads tailored to a specific target. The
Phase 1 exploit-finding agent will iterate over registered attack modules,
ask each to generate candidates against the current target descriptor, and
score the responses.

Bumping :data:`CONTRACT_VERSION`:

* major — breaking change to the Protocol shape (rename, removed method,
  changed argument type).
* minor — add an optional method or argument with a default.
* patch — docstring or clarification only.

See ``CONTRIBUTING.md`` and ``GOVERNANCE.md`` for the contract-change process.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar, Protocol, runtime_checkable

from mylonite.contracts._types import AttackPattern, Payload, TargetDescriptor

CONTRACT_VERSION: str = "0.1.0"


@runtime_checkable
class AttackModule(Protocol):
    """Structural type for attack modules."""

    contract_version: ClassVar[str]

    def attack_metadata(self) -> AttackPattern:
        """Return the static metadata for this attack module."""
        ...

    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:
        """Yield concrete payloads tailored to ``target``.

        Implementations should be deterministic given the same target — any
        LLM-driven randomness should be threaded through an explicit seed
        argument on a subclass-specific config object, not via global state.
        """
        ...


class AttackModuleBase(ABC):
    """ABC counterpart of :class:`AttackModule` for ``isinstance`` checks."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def attack_metadata(self) -> AttackPattern: ...

    @abstractmethod
    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]: ...
