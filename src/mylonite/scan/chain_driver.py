"""Execute a synthesized tool-chain (Driver 2 / Slice 2).

Slice 1 synthesizes a :class:`SynthesizedChain`; this slice executes it against a
session-capable target by *reusing the Driver 1 adaptive loop*. The chain becomes
a synthetic seed (its predicate is the generic effect-aware
``consequential_action_executed``, keyed on the chain's sink via the
``consequential_tool`` metadata) plus an ``AttackPlan`` — so plant → drive →
judge → refine and the strategist all apply unchanged. Success = the synthesized
sink actually took effect (not merely attempted, deferred, or refused).
"""

from __future__ import annotations

from mylonite.contracts.target_adapter import SupportsAttackSession
from mylonite.scan.attack_loop import (
    DEFAULT_MAX_ATTEMPTS,
    AdaptiveAttackDriver,
    AdaptiveOutcome,
    AttackPlan,
)
from mylonite.scan.chain_synth import SynthesizedChain
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.seeds import SeedPattern

#: Generic effect-aware predicate: did ``consequential_tool`` actually execute
#: (not deferred/refused)? Reused for every synthesized chain.
CHAIN_PREDICATE = "consequential_action_executed"


def _synthetic_seed(chain: SynthesizedChain) -> SeedPattern:
    """A SeedPattern standing in for a synthesized chain, so the adaptive loop's
    seed-shaped machinery (payload metadata, refinement, judging) applies."""
    return SeedPattern(
        pattern_id=f"synthesized-chain-{chain.sink_tool}",
        weakness="W2",
        channel="tool-result",
        seed_body=chain.injection,
        setup="seed_note",
        drive="read_note_for_summary",
        predicate=CHAIN_PREDICATE,
        applicable_targets=["kitchen-sink"],
        compliance=chain.compliance,
    )


class ChainAttackDriver:
    """Runs a synthesized chain via the Driver 1 adaptive loop."""

    def __init__(
        self,
        *,
        judge: SuccessJudge,
        strategist_model: str,
        completion_fn: object | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        self._driver = AdaptiveAttackDriver(
            judge=judge,
            strategist_model=strategist_model,
            completion_fn=completion_fn,  # type: ignore[arg-type]
            max_attempts=max_attempts,
        )

    async def run(
        self, *, chain: SynthesizedChain, adapter: SupportsAttackSession
    ) -> AdaptiveOutcome:
        """Plant the chain's injection, drive the planner toward the sink, judge
        whether the sink took effect, refine on failure — within the budget."""
        seed = _synthetic_seed(chain)
        plan = AttackPlan(
            plant_tool=chain.plant_tool,
            plant_args=chain.plant_args,
            drive_message=chain.drive_message,
        )
        return await self._driver.run(
            seed=seed,
            adapter=adapter,
            plan=plan,
            extra_metadata={"consequential_tool": chain.sink_tool},
        )
