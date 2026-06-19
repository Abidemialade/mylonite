"""Stateful memory-poisoning driver (T1).

The single-turn loop plants and retrieves in one breath. The real-world threat is
slower and nastier: poison is planted ONCE, PERSISTS in the agent's memory/store
across unrelated turns, and is retrieved + acted on in a LATER, innocent turn — the
"zombie agent" / cross-session slow-drip shape that single-turn tests never exercise
and that developers have no regression for.

This is NOT a new attack class or adapter: it deepens the existing W2 indirect-
injection weakness over the existing persistent ``AttackSession`` (one store across
turns) and is validated by the same differential — the guarded twin quarantines the
*recalled* memory (``UntrustedEnvelopeControl`` wraps read results), so the same
attack fires on the vulnerable twin and resists on the guarded one. It also fixes the
silent delivery failure: the driver mints and controls the retrieval handle, then
CONFIRMS the planted poison resurfaced in the retrieval turn (``cross_turn_delivered``)
rather than reading a non-delivery as a clean pass.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.contracts.target_adapter import AttackSession, SupportsAttackSession
from mylonite.scan._types import Verdict
from mylonite.scan.attack_loop import AttackPlan
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.seeds import SeedPattern


@dataclass(frozen=True)
class MemoryPoisonOutcome:
    """The result of one cross-turn memory-poisoning run.

    ``plant_turn`` < ``retrieve_turn`` is the defining property: the poison was acted
    on in a turn LATER than it was planted. ``cross_turn_delivered`` records whether
    the planted content actually resurfaced in the retrieval turn — so a non-delivery
    reads as NOT TESTED, never as a clean pass.
    """

    success: bool
    response: AdapterResponse | None
    verdict: Verdict | None
    plant_turn: int
    retrieve_turn: int
    cross_turn_delivered: bool


def _mint_id() -> str:
    return f"n_{secrets.token_hex(4)}"


def _distinctive_tokens(body: str) -> list[str]:
    """Low-false-positive tokens that mark the planted poison if it resurfaces:
    any email/URL, plus the longest words (>= 6 chars). Zero-config — no injected
    marker — so it works for an arbitrary natural-language payload."""
    tokens: list[str] = re.findall(r"[\w.+-]+@[\w.-]+|https?://\S+", body)
    words = sorted((w for w in re.findall(r"[A-Za-z0-9_]{6,}", body)), key=len, reverse=True)
    tokens.extend(words[:3])
    return tokens


def _poison_resurfaced(body: str, response: AdapterResponse | None) -> bool:
    if response is None:
        return False
    haystack = f"{response.raw_response} {response.metadata.get('effect_trace', '')}"
    return any(tok in haystack for tok in _distinctive_tokens(body))


class MemoryPoisoningDriver:
    """Plants poison, lets it persist across benign turns, then drives a later
    retrieval that surfaces and acts on it — all on ONE persistent session."""

    def __init__(
        self,
        *,
        judge: SuccessJudge,
        id_factory: Callable[[], str] = _mint_id,
    ) -> None:
        if judge is None:
            raise ValueError("MemoryPoisoningDriver requires a judge")
        self._judge = judge
        self._id_factory = id_factory

    async def run(
        self,
        *,
        seed: SeedPattern,
        adapter: SupportsAttackSession,
        plan: AttackPlan,
        benign_turns: Sequence[str] = (),
        extra_metadata: dict[str, str] | None = None,
    ) -> MemoryPoisonOutcome:
        """plant (turn 1) -> N benign turns -> retrieve + act (final turn) -> judge.

        ``benign_turns`` are innocent planner drives that run BETWEEN the plant and
        the retrieval, modelling the time/turn separation that defines memory
        poisoning (the agent has 'forgotten' the planted content is attacker-owned).
        """
        nid = self._id_factory()
        session: AttackSession = await adapter.open_session()
        turn = 0
        try:
            # Turn 1: plant the poison. Raw call (bypasses the boundary control) so
            # the store holds genuinely untrusted content, exactly as a real attacker
            # would leave it for later retrieval.
            turn += 1
            plant_args: dict[str, object] = {
                k: v.replace("{payload}", seed.seed_body).replace("{id}", nid)
                for k, v in plan.plant_args.items()
            }
            await session.call_tool(plan.plant_tool, plant_args)
            plant_turn = turn

            # Intervening benign turns: the agent does normal work; the poison lies
            # dormant in memory. These prove persistence across the session.
            for message in benign_turns:
                turn += 1
                await session.drive_planner(message, pattern_id=f"{seed.pattern_id}:benign")

            # Final turn: an innocent retrieval surfaces the dormant poison.
            turn += 1
            drive = plan.drive_message.replace("{id}", nid)
            response = await session.drive_planner(drive, pattern_id=seed.pattern_id)
            retrieve_turn = turn
        finally:
            await session.close()

        delivered = _poison_resurfaced(seed.seed_body, response)
        payload = Payload(
            pattern_id=seed.pattern_id,
            channel=seed.channel,
            body=seed.seed_body,
            metadata={
                "seed_id": seed.pattern_id,
                "weakness": seed.weakness,
                "predicate": seed.predicate,
                "setup": seed.setup,
                "drive": seed.drive,
                "attack_shape": "memory_poisoning",
                "plant_turn": str(plant_turn),
                "retrieve_turn": str(retrieve_turn),
                "cross_turn_delivered": "true" if delivered else "false",
                **(extra_metadata or {}),
            },
        )
        verdict = await self._judge.judge(payload, response)
        return MemoryPoisonOutcome(
            success=verdict.success,
            response=response,
            verdict=verdict,
            plant_turn=plant_turn,
            retrieve_turn=retrieve_turn,
            cross_turn_delivered=delivered,
        )
