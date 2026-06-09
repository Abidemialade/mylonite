"""Reference target adapter — echoes payloads back, no LLM involved.

Useful for unit-testing the rest of the pipeline without spending tokens.
"""

from __future__ import annotations

from typing import ClassVar

from mylonite.contracts import (
    AdapterResponse,
    Payload,
    TargetAdapterBase,
    TargetDescriptor,
)
from mylonite.contracts.target_adapter import CONTRACT_VERSION


class EchoTargetAdapter(TargetAdapterBase):
    """A target adapter whose 'target' is just an echo loop."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def __init__(self, target_id: str = "echo://localhost") -> None:
        self._target_id = target_id

    def describe(self) -> TargetDescriptor:
        return TargetDescriptor(
            target_id=self._target_id,
            kind="custom",
            system_prompt="(echo adapter — no real prompt)",
            tools=[],
            data_sources=[],
            notes="Reference echo adapter. Use only for tests.",
        )

    def invoke(self, payload: Payload) -> AdapterResponse:
        return AdapterResponse(
            payload_pattern_id=payload.pattern_id,
            raw_response=payload.body,
            tool_calls=[],
            metadata={"adapter": "echo"},
        )

    def close(self) -> None:
        return None
