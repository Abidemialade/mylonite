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

from pydantic import BaseModel, ConfigDict

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
# 0.3.0 -> 0.4.0: additive — optional multi-step ``AttackSession`` capability
# (``SupportsAttackSession.open_session`` → ``AttackSession`` with raw
# ``call_tool`` + ``drive_planner`` + ``close``). Lets an attack loop carry
# target state across steps. Single-shot adapters that only implement
# ``invoke`` are unaffected; the loop detects support via isinstance and falls
# back to ``invoke``. Backward-compatible; minor bump per GOVERNANCE.md.
# 0.4.0 -> 0.5.0: additive — ``AttackSession.drive_planner`` gained an optional
# keyword ``pattern_id`` so a multi-step driver can stamp the originating seed's
# id onto the returned ``AdapterResponse`` (replacing the ``"session-drive"``
# sentinel) and findings retain provenance. Defaulted, so existing callers and
# implementations are unaffected. Backward-compatible; minor bump per GOVERNANCE.md.
# 0.5.0 -> 0.6.0: additive, four related fields that let an attempt say "this
# could never have landed here" instead of "this did not land":
#   * ``ScanAttemptOutcome`` gained ``"not_applicable"`` — the seed attacks a
#     capability the target does not expose. Classified NOT_TESTED, never
#     EXERCISED_RESISTED. Report readers switching exhaustively on the outcome
#     see one new value (same shape as the 0.2.0 -> 0.3.0 bump above).
#   * ``ScanAttempt.not_applicable_reason`` — which capability was missing.
#   * ``ToolSpec.annotations`` — the tool's MCP ``ToolAnnotations`` verbatim, so
#     classification can read the protocol's own risk vocabulary rather than
#     guess from the tool's name.
#   * ``TargetDescriptor.can_plant_untrusted_content`` — whether the adapter can
#     actually plant for an indirect-injection seed. Seed selection needs the
#     capability; it previously had only the target's family NAME to go on.
# All optional with defaults preserving current behaviour; adapters that set
# none are unaffected. Backward-compatible; minor bump per GOVERNANCE.md.
CONTRACT_VERSION: str = "0.6.0"


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


# --- Multi-step attack session (capability, added 0.4.0) ---------------------


class ToolCallOutcome(BaseModel):
    """Result of one attacker-issued raw tool call inside an AttackSession.

    Distinct from ``AdapterResponse`` (which is planner-shaped): this is a
    single, direct tool invocation the loop makes itself — e.g. planting a
    canary or probing a retrieval path — not a planner turn.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    result: str
    is_error: bool = False


@runtime_checkable
class AttackSession(Protocol):
    """A stateful session against one target instance.

    The store/subprocess persists for the session's lifetime, so the loop can
    plant, probe, and drive the planner against the SAME state across steps.
    """

    async def call_tool(self, name: str, arguments: dict[str, object]) -> ToolCallOutcome: ...

    async def drive_planner(
        self, user_message: str, *, pattern_id: str = "session-drive"
    ) -> AdapterResponse: ...

    async def close(self) -> None: ...


@runtime_checkable
class SupportsAttackSession(Protocol):
    """Optional adapter capability: open a stateful :class:`AttackSession`."""

    async def open_session(self) -> AttackSession: ...
