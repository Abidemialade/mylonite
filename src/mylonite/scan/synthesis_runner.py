"""Orchestrate synthesize -> validate -> finding for tool-chaining synthesis.

Ties the synthesis pieces into one user-facing flow: synthesize a chain from the
tool surface (S1), differentially validate it against the twins (S3, which runs
S2's execution + S4's escalation), and — only when it validates — emit an
``ExploitRecord`` with the chain embedded for replay. Reference-twin targets
only for now (custom single-variant validation is deferred).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from mylonite.contracts._types import ExploitRecord, Payload, TargetDescriptor
from mylonite.scan.chain_synth import ChainSynthesizer, SynthesizedChain
from mylonite.scan.chain_validator import ChainDifferentialValidator, ChainValidationResult


def chain_to_json(chain: SynthesizedChain) -> str:
    """Serialise a chain for the exploit artefact so ``generate`` can replay it."""
    return json.dumps(
        {
            "plant_tool": chain.plant_tool,
            "plant_args": chain.plant_args,
            "sink_tool": chain.sink_tool,
            "injection": chain.injection,
            "drive_message": chain.drive_message,
            "expected_effect": chain.expected_effect,
            "judge_rubric": chain.judge_rubric,
            "compliance": chain.compliance.model_dump(),
        },
        sort_keys=True,
    )


@dataclass
class SynthesisResult:
    """Outcome of one synthesis run."""

    chain: SynthesizedChain | None
    validation: ChainValidationResult | None
    exploit: ExploitRecord | None


class SynthesisRunner:
    """Synthesize a chain, differentially validate it, and emit a finding."""

    def __init__(
        self,
        *,
        synthesizer: ChainSynthesizer,
        validator: ChainDifferentialValidator,
        target_id: str,
    ) -> None:
        self._synthesizer = synthesizer
        self._validator = validator
        self._target_id = target_id

    async def run(
        self,
        descriptor: TargetDescriptor,
        *,
        seed_arm: Any = None,
        extra_sinks: tuple[str, ...] = (),
    ) -> SynthesisResult:
        chain = await self._synthesizer.synthesize(
            descriptor, seed_arm=seed_arm, extra_sinks=extra_sinks
        )
        if chain is None:
            return SynthesisResult(chain=None, validation=None, exploit=None)
        validation = await self._validator.validate(chain)
        if not validation.validated or validation.winning_outcome is None:
            return SynthesisResult(chain=chain, validation=validation, exploit=None)

        outcome = validation.winning_outcome
        assert outcome.response is not None and outcome.verdict is not None
        payload = Payload(
            pattern_id=f"synthesized-chain-{chain.sink_tool}",
            channel="tool-result",
            body=outcome.final_body,
            metadata={
                "consequential_tool": chain.sink_tool,
                "synthesized_chain": chain_to_json(chain),
                "vuln_rate": str(validation.vuln_rate),
                "guard_leak_rate": str(validation.guard_leak_rate),
            },
        )
        exploit = ExploitRecord(
            target_id=self._target_id,
            pattern_id=payload.pattern_id,
            payload=payload,
            response=outcome.response,
            success_reason=(
                f"synthesized chain reached sink {chain.sink_tool!r} on the vulnerable "
                f"twin ({validation.vuln_fires}/{validation.runs}) and was blocked on "
                f"the guarded twin ({validation.guard_leaks}/{validation.runs})"
            ),
            compliance=chain.compliance,
        )
        return SynthesisResult(chain=chain, validation=validation, exploit=exploit)
