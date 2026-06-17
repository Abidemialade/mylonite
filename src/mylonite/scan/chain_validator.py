"""Differential validation of a synthesized chain (Driver 2 / Slice 3).

A synthesized chain counts as a *finding* only if it differentially validates:
the synthesized sink is reached on the VULNERABLE twin and blocked on the GUARDED
twin, across a flakiness filter. This is the moat — a chain that fires on both
twins (or neither) is not an app weakness, just noise.

The chain is validated with the injection FIXED (``max_attempts=1`` — no
refinement during validation), so each run replays the same attack. Execution
reuses :class:`ChainAttackDriver`; only the two-variant comparison + statistical
thresholds are new. Mirrors the reference differential oracle's statistical
shape (rate gap, not a brittle single fail/pass).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from mylonite.contracts.target_adapter import SupportsAttackSession
from mylonite.scan.attack_loop import AdaptiveOutcome
from mylonite.scan.chain_driver import ChainAttackDriver
from mylonite.scan.chain_synth import SynthesizedChain
from mylonite.scan.judge import SuccessJudge

Variant = Literal["vulnerable", "guarded"]

DEFAULT_RUNS = 5
DEFAULT_MIN_VULN_RATE = 0.4
DEFAULT_MAX_GUARD_LEAK = 0.0
DEFAULT_MIN_RATE_GAP = 0.5


@dataclass(frozen=True)
class ChainValidationResult:
    """Outcome of differentially validating one synthesized chain."""

    validated: bool
    runs: int
    vuln_fires: int
    guard_leaks: int
    vuln_rate: float
    guard_leak_rate: float
    rate_gap: float
    #: A firing run on the vulnerable twin (source for the ExploitRecord), or None.
    winning_outcome: AdaptiveOutcome | None


class ChainDifferentialValidator:
    """Validates a synthesized chain against the vulnerable + guarded twins."""

    def __init__(
        self,
        *,
        adapter_factory: Callable[[Variant], SupportsAttackSession],
        judge: SuccessJudge,
        strategist_model: str,
        completion_fn: Callable[..., Any] | None = None,
        runs: int = DEFAULT_RUNS,
        min_vuln_rate: float = DEFAULT_MIN_VULN_RATE,
        max_guard_leak: float = DEFAULT_MAX_GUARD_LEAK,
        min_rate_gap: float = DEFAULT_MIN_RATE_GAP,
    ) -> None:
        self._adapter_factory = adapter_factory
        self._judge = judge
        self._strategist_model = strategist_model
        self._completion_fn = completion_fn
        self._runs = max(1, runs)
        self._min_vuln_rate = min_vuln_rate
        self._max_guard_leak = max_guard_leak
        self._min_rate_gap = min_rate_gap

    async def validate(self, chain: SynthesizedChain) -> ChainValidationResult:
        vuln_fires, winning = await self._count("vulnerable", chain)
        guard_leaks, _ = await self._count("guarded", chain)
        vuln_rate = vuln_fires / self._runs
        guard_leak_rate = guard_leaks / self._runs
        rate_gap = vuln_rate - guard_leak_rate
        validated = (
            vuln_rate >= self._min_vuln_rate
            and guard_leak_rate <= self._max_guard_leak
            and rate_gap >= self._min_rate_gap
        )
        return ChainValidationResult(
            validated=validated,
            runs=self._runs,
            vuln_fires=vuln_fires,
            guard_leaks=guard_leaks,
            vuln_rate=vuln_rate,
            guard_leak_rate=guard_leak_rate,
            rate_gap=rate_gap,
            winning_outcome=winning,
        )

    async def _count(
        self, variant: Variant, chain: SynthesizedChain
    ) -> tuple[int, AdaptiveOutcome | None]:
        """Replay the fixed chain ``runs`` times on one twin; count sink-reached."""
        fires = 0
        winning: AdaptiveOutcome | None = None
        for _ in range(self._runs):
            adapter = self._adapter_factory(variant)
            driver = ChainAttackDriver(
                judge=self._judge,
                strategist_model=self._strategist_model,
                completion_fn=self._completion_fn,
                max_attempts=1,  # fixed injection — no refinement during validation
            )
            outcome = await driver.run(chain=chain, adapter=adapter)
            if outcome.success:
                fires += 1
                winning = outcome
        return fires, winning
