"""Contract 0.4.0: optional multi-step AttackSession capability.

Additive, backward-compatible: existing single-shot adapters are unaffected.
The capability is a runtime-checkable Protocol so the attack loop can detect
support and fall back to invoke() when absent.
"""

from __future__ import annotations

from mylonite.contracts import target_adapter
from mylonite.contracts.target_adapter import (
    AttackSession,
    SupportsAttackSession,
    ToolCallOutcome,
)


def test_contract_version_bumped_to_0_4_0() -> None:
    # 0.3.0 -> 0.4.0: additive AttackSession / SupportsAttackSession capability.
    assert target_adapter.CONTRACT_VERSION == "0.4.0"


def test_tool_call_outcome_round_trips_and_defaults() -> None:
    outcome = ToolCallOutcome(tool="read_note", result="CANARY")
    assert outcome.is_error is False
    assert ToolCallOutcome.model_validate_json(outcome.model_dump_json()) == outcome


def test_supports_attack_session_is_structural() -> None:
    class _Supported:
        async def open_session(self) -> object: ...

    class _NotSupported:
        async def invoke(self) -> object: ...

    assert isinstance(_Supported(), SupportsAttackSession)
    assert not isinstance(_NotSupported(), SupportsAttackSession)


def test_attack_session_protocol_is_structural() -> None:
    class _Session:
        async def call_tool(self, name: str, arguments: dict[str, object]) -> object: ...
        async def drive_planner(self, user_message: str) -> object: ...
        async def close(self) -> None: ...

    class _PartialSession:
        # Missing close() — must NOT satisfy the structural Protocol.
        async def call_tool(self, name: str, arguments: dict[str, object]) -> object: ...
        async def drive_planner(self, user_message: str) -> object: ...

    assert isinstance(_Session(), AttackSession)
    assert not isinstance(_PartialSession(), AttackSession)
