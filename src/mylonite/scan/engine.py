"""ScanEngine — the Phase 1 orchestrator.

Pulls together: TargetAdapter (PR 4) → AttackModule (PR 5) → PayloadCustomiser
(PR 2) → adapter.invoke (PR 4) → SuccessJudge (PR 2). Closes P1 (async-first
with asyncio.gather + Semaphore), A1 (process-wide budget counter wraps every
LLM call), A3 (skip planner failures), A4 (validate Payload metadata at
runtime), and C4 (distinct exit-code signal via ``aborted`` field).

The engine returns a ``ScanResult`` (in-process wrapper around a serialisable
``ScanReport``). ``artefacts.write_artefacts`` turns it into files on disk;
``artefacts.render_summary`` turns it into stdout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mylonite.contracts import Payload, TargetDescriptor
from mylonite.contracts._types import ExploitRecord, ScanAttempt, ScanReport
from mylonite.scan._llm import BudgetExceededError, LiteLLMCallCounter
from mylonite.scan._types import AdapterInvocationSkipped
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern
from mylonite.version import __version__

logger = logging.getLogger(__name__)

REQUIRED_METADATA_KEYS = frozenset({"seed_id", "weakness", "predicate", "setup", "drive"})
DEFAULT_PROVIDER_FAILURE_THRESHOLD = 3
_SEEDS_BY_ID: dict[str, SeedPattern] = {s.pattern_id: s for s in SEED_CATALOGUE}


class ScanConfig(BaseModel):
    """Caller-supplied configuration for one scan."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    target_id: str
    provider: str
    model: str
    max_llm_calls: int = 50
    max_concurrent: int = 3
    output_dir: Path = Field(default_factory=lambda: Path(".mylonite/scans"))
    dry_run: bool = False
    provider_failure_threshold: int = DEFAULT_PROVIDER_FAILURE_THRESHOLD
    pattern_id_filter: str | None = Field(
        default=None,
        description=(
            "If set, only payloads whose pattern_id equals this run; used by the "
            "offline gate to scope a scan to one exploit's seed."
        ),
    )


@dataclass
class ScanResult:
    """Engine output: the serialisable report + the exploit records."""

    report: ScanReport
    exploits: list[ExploitRecord] = field(default_factory=list)


@dataclass
class _PerPayloadOutcome:
    attempt: ScanAttempt
    exploit: ExploitRecord | None


class ScanEngine:
    """Drives the full scan in one async run."""

    def __init__(
        self,
        *,
        config: ScanConfig,
        adapter: Any,  # AsyncTargetAdapter / _AdapterProtocol
        attack_modules: Sequence[Any],  # _AttackModuleProtocol
        customiser: PayloadCustomiser,
        judge: SuccessJudge,
    ) -> None:
        self._config = config
        self._adapter = adapter
        self._attack_modules = list(attack_modules)
        self._customiser = customiser
        self._judge = judge

    async def run(self) -> ScanResult:
        counter = LiteLLMCallCounter(cap=self._config.max_llm_calls)
        start = time.monotonic()
        attempts: list[ScanAttempt] = []
        exploits: list[ExploitRecord] = []
        aborted: str | None = None
        module_ids = [m.attack_metadata().id for m in self._attack_modules]
        module_compliance = {
            m.attack_metadata().id: m.attack_metadata().compliance for m in self._attack_modules
        }

        with counter.active():
            try:
                descriptor = await self._adapter.describe()
            except Exception:
                logger.exception("ScanEngine: adapter.describe() raised")
                aborted = "describe_failed"
                return self._finalize(
                    attempts, exploits, aborted, time.monotonic() - start, module_ids
                )

            tasks: list[asyncio.Task[_PerPayloadOutcome]] = []
            semaphore = asyncio.Semaphore(self._config.max_concurrent)

            for module in self._attack_modules:
                module_id = module.attack_metadata().id
                for payload in module.generate_payloads(descriptor):
                    if (
                        self._config.pattern_id_filter is not None
                        and payload.pattern_id != self._config.pattern_id_filter
                    ):
                        continue
                    tasks.append(
                        asyncio.create_task(
                            self._process_one(
                                payload=payload,
                                module_id=module_id,
                                descriptor=descriptor,
                                semaphore=semaphore,
                                compliance=module_compliance[module_id],
                            )
                        )
                    )

            if not tasks:
                return self._finalize(
                    attempts, exploits, aborted, time.monotonic() - start, module_ids
                )

            for coro in asyncio.as_completed(tasks):
                try:
                    outcome = await coro
                except BudgetExceededError:
                    aborted = "budget_exceeded"
                    for pending in tasks:
                        pending.cancel()
                    break
                attempts.append(outcome.attempt)
                if outcome.exploit is not None:
                    exploits.append(outcome.exploit)
                if counter.consecutive_failures >= self._config.provider_failure_threshold:
                    aborted = "provider_unreachable"
                    for pending in tasks:
                        pending.cancel()
                    break

        return self._finalize(attempts, exploits, aborted, time.monotonic() - start, module_ids)

    def _finalize(
        self,
        attempts: list[ScanAttempt],
        exploits: list[ExploitRecord],
        aborted: str | None,
        elapsed: float,
        module_ids: list[str],
    ) -> ScanResult:
        report = ScanReport(
            target_id=self._config.target_id,
            attack_modules=module_ids,
            provider=self._config.provider,
            model=self._config.model,
            elapsed_seconds=round(elapsed, 3),
            attempts=attempts,
            findings_count=len(exploits),
            aborted=aborted,
            single_run=True,
            mylonite_version=__version__,
        )
        return ScanResult(report=report, exploits=exploits)

    async def _process_one(
        self,
        *,
        payload: Payload,
        module_id: str,
        descriptor: TargetDescriptor,
        semaphore: asyncio.Semaphore,
        compliance: Any,
    ) -> _PerPayloadOutcome:
        seed_id = payload.metadata.get("seed_id") or payload.pattern_id

        # G2 / A4: metadata validation runs before any LLM call.
        missing = REQUIRED_METADATA_KEYS - payload.metadata.keys()
        if missing:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_invalid_metadata",
                    verdict_mechanism=None,
                    verdict_reason=f"payload missing metadata keys: {sorted(missing)}",
                    error_detail=None,
                ),
                exploit=None,
            )

        if self._config.dry_run:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_dry_run",
                    verdict_mechanism=None,
                    verdict_reason="dry-run mode; no customisation or invocation",
                    error_detail=None,
                ),
                exploit=None,
            )

        async with semaphore:
            return await self._run_payload(
                payload=payload,
                module_id=module_id,
                descriptor=descriptor,
                compliance=compliance,
                seed_id=seed_id,
            )

    async def _run_payload(
        self,
        *,
        payload: Payload,
        module_id: str,
        descriptor: TargetDescriptor,
        compliance: Any,
        seed_id: str,
    ) -> _PerPayloadOutcome:
        del module_id  # currently used only for filename; carried via compliance binding
        # Customisation step — requires looking up the SeedPattern by seed_id
        # so the customiser can build its prompt from the right shape. Third-
        # party plugins whose seed_id is not in SEED_CATALOGUE get skipped
        # cleanly (the engine still runs, just without LLM customisation for
        # those seeds).
        seed = _SEEDS_BY_ID.get(seed_id)
        if seed is None:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_unknown_seed",
                    verdict_mechanism=None,
                    verdict_reason=(
                        f"seed_id {seed_id!r} not in SEED_CATALOGUE; engine cannot "
                        "drive customisation for this payload"
                    ),
                    error_detail=None,
                ),
                exploit=None,
            )

        if payload.metadata.get("needs_customisation") == "true":
            payload = await self._customiser.customise(seed, descriptor)

        try:
            response = await self._adapter.invoke(payload)
        except AdapterInvocationSkipped as skip:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_planner_failure",
                    verdict_mechanism=None,
                    verdict_reason=skip.reason,
                    error_detail=skip.attempt_metadata.get("exception"),
                ),
                exploit=None,
            )
        except BudgetExceededError:
            # Propagate up so run() can flip aborted="budget_exceeded".
            raise
        except Exception as exc:
            logger.exception("ScanEngine: adapter.invoke raised unexpectedly")
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="error",
                    verdict_mechanism=None,
                    verdict_reason=str(exc),
                    error_detail=type(exc).__name__,
                ),
                exploit=None,
            )

        try:
            verdict = await self._judge.judge(payload, response)
        except BudgetExceededError:
            raise
        except Exception as exc:
            logger.exception("ScanEngine: judge raised unexpectedly")
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="error",
                    verdict_mechanism=None,
                    verdict_reason=str(exc),
                    error_detail=type(exc).__name__,
                ),
                exploit=None,
            )

        if verdict.success:
            exploit = ExploitRecord(
                target_id=descriptor.target_id,
                pattern_id=payload.pattern_id,
                payload=payload,
                response=response,
                success_reason=verdict.reason,
                compliance=compliance,
            )
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="finding",
                    verdict_mechanism=verdict.mechanism,
                    verdict_reason=verdict.reason,
                    error_detail=None,
                ),
                exploit=exploit,
            )
        return _PerPayloadOutcome(
            attempt=ScanAttempt(
                seed_id=seed_id,
                pattern_id=payload.pattern_id,
                outcome="no_finding",
                verdict_mechanism=verdict.mechanism,
                verdict_reason=verdict.reason,
                error_detail=None,
            ),
            exploit=None,
        )
