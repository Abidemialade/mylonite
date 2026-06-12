"""TargetAdapter extension point.

An adapter speaks to a specific kind of target — an MCP/tool-using agent, a
RAG pipeline, a custom HTTP agent. It can:

* describe itself as a :class:`TargetDescriptor`,
* invoke a single :class:`Payload` and return the :class:`AdapterResponse`,
* clean up resources on close.

Adapters MUST refuse to operate against targets the user has not explicitly
authorized — see ``mylonite.config.AuthorizationConfig`` and ``SECURITY.md``.
The check belongs in the adapter, not somewhere upstream, so misconfigured
plugins still fail safely.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Protocol, runtime_checkable

from mylonite.contracts._types import AdapterResponse, Payload, TargetDescriptor

# 0.1.0 -> 0.2.0: additive, backward-compatible — TargetDescriptor gained the
# optional ``weakness_classes`` field so a target can declare which attack
# classes it exposes (descriptor-driven seed selection). Existing adapters and
# consumers are unaffected; minor bump per GOVERNANCE.md.
# 0.2.0 -> 0.3.0: additive — the scan report's ``ScanAttemptOutcome`` enum gained
# ``skipped_payload_not_delivered`` (an indirect payload that was never retrieved
# is reported as not-delivered rather than silently clean). Backward-compatible
# for adapters; report readers that switch exhaustively on the outcome see one
# new value. Minor bump per GOVERNANCE.md.
CONTRACT_VERSION: str = "0.3.0"


@runtime_checkable
class TargetAdapter(Protocol):
    """Synchronous target adapter."""

    contract_version: ClassVar[str]

    def describe(self) -> TargetDescriptor: ...

    def invoke(self, payload: Payload) -> AdapterResponse: ...

    def close(self) -> None: ...


@runtime_checkable
class AsyncTargetAdapter(Protocol):
    """Async variant for adapters that need an event loop (e.g. MCP)."""

    contract_version: ClassVar[str]

    async def describe(self) -> TargetDescriptor: ...

    async def invoke(self, payload: Payload) -> AdapterResponse: ...

    async def close(self) -> None: ...


class TargetAdapterBase(ABC):
    """Sync ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    def describe(self) -> TargetDescriptor: ...

    @abstractmethod
    def invoke(self, payload: Payload) -> AdapterResponse: ...

    @abstractmethod
    def close(self) -> None: ...


class AsyncTargetAdapterBase(ABC):
    """Async ABC counterpart."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    @abstractmethod
    async def describe(self) -> TargetDescriptor: ...

    @abstractmethod
    async def invoke(self, payload: Payload) -> AdapterResponse: ...

    @abstractmethod
    async def close(self) -> None: ...
