"""ScanEngine — the scan orchestrator.

Pulls together: TargetAdapter → AttackModule → PayloadCustomiser →
adapter.invoke → SuccessJudge. Async-first
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

from mylonite._concurrency import gather_bounded
from mylonite.contracts import Payload, TargetDescriptor
from mylonite.contracts._types import ExploitRecord, ScanAttempt, ScanReport
from mylonite.scan._llm import BudgetExceededError, LiteLLMCallCounter
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.exfil import randomize_payload_exfil
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern, target_family
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
    # Role-separated model overrides. Each defaults to ``model`` when unset, so
    # existing callers are unaffected. Separating the roles is the lever for the
    # AI-layer attack class: the PLANNER (the agent-under-test decision-maker) is
    # what an aligned model makes refuse injection even on a vulnerable target,
    # collapsing the differential. Pointing the planner at a representatively
    # exploitable model — while keeping an aligned judge — restores signal.
    planner_model: str | None = Field(
        default=None,
        description="Model for the agent-under-test planner. Defaults to ``model``.",
    )
    customiser_model: str | None = Field(
        default=None,
        description="Model that crafts/refines attack payloads. Defaults to ``model``.",
    )
    judge_model: str | None = Field(
        default=None,
        description="Model for the LLM-judge verdict fallback. Defaults to ``model``.",
    )
    max_llm_calls: int = 50
    max_concurrent: int = 3
    output_dir: Path = Field(default_factory=lambda: Path(".mylonite/scans"))
    dry_run: bool = False
    customise: bool = Field(
        default=True,
        description=(
            "Run the per-seed LLM customiser when a payload requests it. The "
            "deterministic demo/replay path sets this False: the customiser is "
            "a live (non-deterministic) LLM call whose refined body would make "
            "the recorded fixtures unreproducible, so the demo drives raw seed "
            "bodies — which is what it always effectively did before the "
            "JSON-fence parse fix landed."
        ),
    )
    provider_failure_threshold: int = DEFAULT_PROVIDER_FAILURE_THRESHOLD
    pattern_id_filter: str | None = Field(
        default=None,
        description=(
            "If set, only payloads whose pattern_id equals this run; used by the "
            "offline gate to scope a scan to one exploit's seed."
        ),
    )
    runs: int = Field(
        default=1,
        ge=1,
        description=(
            "How many times to invoke + judge each payload (scan-time flakiness "
            "filter). With runs=1 (default) behaviour is unchanged. With runs>1 a "
            "payload is a finding only if it fires in a strict majority of runs, "
            "so a 1-in-N fluke is rejected; the report's single_run flips False."
        ),
    )
    wall_clock_timeout_s: float | None = Field(
        default=None,
        description=(
            "Optional overall wall-clock budget for the scan in seconds. When "
            "exceeded mid-run the engine stops launching/awaiting further work and "
            "returns aborted='wall_clock_timeout' with whatever completed. None "
            "(default) means no wall-clock limit."
        ),
    )
    randomize_exfil: bool = Field(
        default=False,
        description=(
            "Mint a unique exfil destination per run and substitute it into the "
            "payload body, keying the success predicate on the minted token. Tests "
            "whether the control/target GENERALIZES rather than blocking the one "
            "demo address. Default False preserves existing behaviour (and the "
            "recorded-fixture replay path, which must NOT randomize)."
        ),
    )

    @property
    def resolved_planner_model(self) -> str:
        """The planner model, falling back to ``model``."""
        return self.planner_model or self.model

    @property
    def resolved_customiser_model(self) -> str:
        """The customiser model, falling back to ``model``."""
        return self.customiser_model or self.model

    @property
    def resolved_judge_model(self) -> str:
        """The judge model, falling back to ``model``."""
        return self.judge_model or self.model


@dataclass
class ScanResult:
    """Engine output: the serialisable report + the exploit records."""

    report: ScanReport
    exploits: list[ExploitRecord] = field(default_factory=list)


@dataclass
class _PerPayloadOutcome:
    attempt: ScanAttempt
    exploit: ExploitRecord | None
    #: "call_raised" | "unparseable_output" | None — set when the LLM judge fell back.
    judge_fallback_cause: str | None = None
    #: True when the customiser fell back to the unmodified seed body.
    customiser_fallback: bool = False
    #: (success_count, runs) when runs>1 and the runs disagreed (flakiness seen).
    run_disagreement: tuple[int, int] | None = None


@dataclass
class _JudgedPass:
    """One invoke→judge pass that produced a verdict (not a structural skip)."""

    verdict: Any  # mylonite.scan.judge.Verdict
    response: Any  # mylonite.contracts._types.AdapterResponse
    tool_call_trace: list[str]
    judge_evidence: dict[str, str]


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
        inconclusive_attempts = 0
        fallback_breakdown: dict[str, int] = {}
        module_ids = [m.attack_metadata().id for m in self._attack_modules]
        module_compliance = {
            m.attack_metadata().id: m.attack_metadata().compliance for m in self._attack_modules
        }

        with counter.active():
            try:
                descriptor = await self._adapter.describe()
            except ImportError:
                # A missing dependency (e.g. the optional reference target) is a
                # configuration error, not a target failure — surface it so the
                # CLI can map it to a clear exit, rather than hiding it behind a
                # generic "describe_failed".
                raise
            except Exception:
                logger.exception("ScanEngine: adapter.describe() raised")
                aborted = "describe_failed"
                return self._finalize(
                    attempts, exploits, aborted, time.monotonic() - start, module_ids
                )

            tasks: list[asyncio.Task[_PerPayloadOutcome]] = []
            semaphore = asyncio.Semaphore(self._config.max_concurrent)

            # A pattern_id uniquely identifies a seed; the same seed must run at
            # most once even if two modules emit it (belt-and-suspenders behind the
            # per-module weakness filters — #5). Dedup is debug-logged, not a
            # contract outcome, so it never masks a genuine double-emit in review.
            seen_pattern_ids: set[str] = set()

            for module in self._attack_modules:
                module_id = module.attack_metadata().id
                for payload in module.generate_payloads(descriptor):
                    if (
                        self._config.pattern_id_filter is not None
                        and payload.pattern_id != self._config.pattern_id_filter
                    ):
                        continue
                    if payload.pattern_id in seen_pattern_ids:
                        logger.debug(
                            "ScanEngine: skipping duplicate pattern_id %r (already "
                            "emitted by an earlier module)",
                            payload.pattern_id,
                        )
                        continue
                    seen_pattern_ids.add(payload.pattern_id)
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
                # Nothing ran. A pattern_id filter that matched nothing is an
                # intentional scoping (stay clean+empty); but a *real* scan that
                # produced zero payloads means no seeds were applicable to this
                # target — that must be loud, never look like a clean pass (#3).
                if self._config.pattern_id_filter is None:
                    family = target_family(descriptor.target_id)
                    known = sorted({t for s in SEED_CATALOGUE for t in s.applicable_targets})
                    logger.warning(
                        "ScanEngine: no seeds applicable to family %r — nothing ran. "
                        "Known families: %s",
                        family,
                        known,
                    )
                    aborted = "no_payloads"
                return self._finalize(
                    attempts, exploits, aborted, time.monotonic() - start, module_ids
                )

            timeout_s = self._config.wall_clock_timeout_s
            for coro in asyncio.as_completed(tasks):
                try:
                    if timeout_s is not None:
                        # Bound the overall scan: await each completion only within
                        # the remaining budget, so even a hung task can't run past
                        # the deadline. We then cancel whatever is still pending and
                        # report what completed (#8 — no silent open-ended loop).
                        remaining = timeout_s - (time.monotonic() - start)
                        outcome = await asyncio.wait_for(coro, timeout=max(0.0, remaining))
                    else:
                        outcome = await coro
                except TimeoutError:
                    aborted = "wall_clock_timeout"
                    for pending in tasks:
                        pending.cancel()
                    break
                except BudgetExceededError:
                    aborted = "budget_exceeded"
                    for pending in tasks:
                        pending.cancel()
                    break
                attempts.append(outcome.attempt)
                if outcome.exploit is not None:
                    exploits.append(outcome.exploit)
                if outcome.judge_fallback_cause is not None:
                    inconclusive_attempts += 1
                    key = f"judge_{outcome.judge_fallback_cause}"
                    fallback_breakdown[key] = fallback_breakdown.get(key, 0) + 1
                if outcome.customiser_fallback:
                    fallback_breakdown["customiser_fallback"] = (
                        fallback_breakdown.get("customiser_fallback", 0) + 1
                    )
                if outcome.run_disagreement is not None:
                    # The runs both fired and didn't for this payload — observed
                    # flakiness, surfaced for the report (not a contract outcome).
                    fallback_breakdown["nrun_disagreement"] = (
                        fallback_breakdown.get("nrun_disagreement", 0) + 1
                    )
                if counter.consecutive_failures >= self._config.provider_failure_threshold:
                    aborted = "provider_unreachable"
                    for pending in tasks:
                        pending.cancel()
                    break

            # Drain every task before returning. On an abort path the cancelled
            # MCP-invoke tasks must be AWAITED so each one's async context manager
            # runs its __aexit__ — i.e. stdio_client actually tears down the child
            # subprocess. Cancelled-but-unawaited tasks are discarded when the loop
            # closes, leaking subprocesses (worst on Windows, the platform the
            # wall-clock timeout targets). On the normal path every task is already
            # done, so this returns immediately.
            await asyncio.gather(*tasks, return_exceptions=True)

        return self._finalize(
            attempts,
            exploits,
            aborted,
            time.monotonic() - start,
            module_ids,
            inconclusive_attempts=inconclusive_attempts,
            fallback_breakdown=fallback_breakdown,
        )

    def _finalize(
        self,
        attempts: list[ScanAttempt],
        exploits: list[ExploitRecord],
        aborted: str | None,
        elapsed: float,
        module_ids: list[str],
        *,
        inconclusive_attempts: int = 0,
        fallback_breakdown: dict[str, int] | None = None,
    ) -> ScanResult:
        report = ScanReport(
            target_id=self._config.target_id,
            attack_modules=module_ids,
            provider=self._config.provider,
            model=self._config.model,
            elapsed_seconds=round(elapsed, 3),
            attempts=attempts,
            findings_count=len(exploits),
            inconclusive_attempts=inconclusive_attempts,
            fallback_breakdown=fallback_breakdown or {},
            aborted=aborted,
            single_run=self._config.runs == 1,
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
        needs_customisation = payload.metadata.get("needs_customisation") == "true"
        # A catalogue-unknown seed_id is only fatal when the payload asks to be
        # customised — the customiser prompt is built from the SeedPattern shape.
        # Descriptor-synthesised seeds (direct_content / tool_description channels)
        # set needs_customisation=false: their body is already target-shaped, so
        # they run DIRECT instead of skipping. This is what makes Mylonite's probes
        # port to real targets whose tool surface isn't the kitchen-sink shape.
        if seed is None and needs_customisation:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_unknown_seed",
                    verdict_mechanism=None,
                    verdict_reason=(
                        f"seed_id {seed_id!r} not in SEED_CATALOGUE and requests "
                        "customisation; engine cannot build a customiser prompt"
                    ),
                    error_detail=None,
                ),
                exploit=None,
            )

        customiser_fallback = False
        if seed is not None and self._config.customise and needs_customisation:
            payload = await self._customiser.customise(seed, descriptor)
            customiser_fallback = payload.metadata.get("customiser") == "fallback"

        # Generalization probe (opt-in): randomize the exfil destination AFTER
        # customisation so the predicate (keyed on the minted token via metadata)
        # tests whether the control/target stops exfil to ANY attacker address,
        # not just the demo literal. No-op by default; never on the fixture path.
        if self._config.randomize_exfil:
            payload = randomize_payload_exfil(payload)

        # Invoke + judge the (customised) payload `runs` times (scan-time flakiness
        # filter). A structural skip or error on ANY pass is terminal — retrying a
        # missing seed arm, an undelivered payload, or a planner outage tests
        # nothing — so return it immediately. Otherwise tally the judged verdicts:
        # with runs>1 the payload counts as a finding only if it fires in a strict
        # majority, rejecting a 1-in-N fluke. runs=1 reduces to single-pass exactly.
        runs = self._config.runs
        success_passes: list[_JudgedPass] = []
        fail_passes: list[_JudgedPass] = []
        last_pass: _JudgedPass | None = None
        success_count = 0
        # The `runs` passes are independent of each other (same payload,
        # re-invoked/re-judged for the flakiness filter), so with runs>1 they
        # are driven concurrently, bounded by the same limit as cross-payload
        # fan-out. runs=1 (the default, and every demo/replay path) stays a
        # single bare `await` rather than routing through gather_bounded: this
        # whole payload-processing coroutine is itself already running inside
        # an ``asyncio.create_task``-managed Task that the engine's own
        # abort/cancel path (``run()``'s ``pending.cancel()`` on
        # provider_unreachable / budget_exceeded / wall-clock-timeout) can
        # cancel BEFORE that Task ever gets its first execution turn — and a
        # coroutine handed to ``asyncio.gather`` under THOSE conditions can be
        # abandoned un-awaited (Task.cancel() before the wrapping Task's first
        # step throws into it without ever reaching the inner ``await coro``),
        # which trips ``filterwarnings=error``'s "coroutine was never
        # awaited". A single bare await has no such window and is exactly the
        # old sequential form, so runs=1 keeps it. With runs>1, a structural
        # skip/error is still terminal for the OVERALL verdict (the first such
        # result in run order wins, matching the old early-return), but —
        # because all passes are launched up front — a later pass may now run
        # even though an earlier one turned out to be a terminal skip; that
        # only spends extra (already-budgeted) calls, it never changes which
        # result is returned.
        if runs == 1:
            pass_results = [await self._one_pass(payload=payload, seed_id=seed_id)]
        else:
            pass_results = await gather_bounded(
                [self._one_pass(payload=payload, seed_id=seed_id) for _ in range(runs)],
                limit=self._config.max_concurrent,
            )
        for result in pass_results:
            if isinstance(result, _PerPayloadOutcome):
                return result  # structural skip / error — terminal, do not retry
            last_pass = result
            if result.verdict.success:
                success_count += 1
                success_passes.append(result)
            else:
                fail_passes.append(result)

        assert last_pass is not None  # runs >= 1 and every skip returned above  # noqa: S101  # removed in P9
        is_finding = success_count * 2 > runs  # strict majority (runs=1 → 1 pass)
        # Surface observed flakiness: the runs both fired and didn't.
        run_disagreement = (success_count, runs) if runs > 1 and 0 < success_count < runs else None

        # A finding reports a FIRING pass; a no_finding reports a FAILING pass, so
        # the audit record's verdict reason/mechanism never contradicts its outcome
        # (a minority success must not stamp a no_finding with a success reason).
        # When not a finding there is always at least one failing pass; last_pass is
        # a defensive fallback only.
        decisive = (
            success_passes[0] if is_finding else (fail_passes[0] if fail_passes else last_pass)
        )
        verdict = decisive.verdict
        tool_call_trace = decisive.tool_call_trace
        judge_evidence = decisive.judge_evidence

        if is_finding:
            # Provenance from the FIRING seed, not the module (#4). A module emits
            # several weakness classes (W1..W4); stamping module-level compliance
            # mislabels which OWASP/ASI/ATLAS IDs the emitted test actually proves.
            # The seed carries the precise tags; the module-level `compliance` arg
            # is the fallback for catalogue-unknown seeds (which never reach here —
            # they return `skipped_unknown_seed` above — but kept for safety).
            resolved_compliance = seed.compliance if seed is not None else compliance
            # Attack-tier provenance (no contract change — rides payload.metadata).
            tiered_payload = payload.model_copy(
                update={"metadata": {**payload.metadata, "attack_tier": "static"}}
            )
            exploit = ExploitRecord(
                target_id=descriptor.target_id,
                pattern_id=payload.pattern_id,
                payload=tiered_payload,
                response=decisive.response,
                success_reason=verdict.reason,
                compliance=resolved_compliance,
            )
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="finding",
                    verdict_mechanism=verdict.mechanism,
                    verdict_reason=verdict.reason,
                    error_detail=None,
                    tool_call_trace=tool_call_trace,
                    judge_evidence=judge_evidence,
                ),
                exploit=exploit,
                judge_fallback_cause=verdict.fallback_cause,
                customiser_fallback=customiser_fallback,
                run_disagreement=run_disagreement,
            )
        return _PerPayloadOutcome(
            attempt=ScanAttempt(
                seed_id=seed_id,
                pattern_id=payload.pattern_id,
                outcome="no_finding",
                verdict_mechanism=verdict.mechanism,
                verdict_reason=verdict.reason,
                error_detail=None,
                tool_call_trace=tool_call_trace,
                judge_evidence=judge_evidence,
            ),
            exploit=None,
            judge_fallback_cause=verdict.fallback_cause,
            customiser_fallback=customiser_fallback,
            run_disagreement=run_disagreement,
        )

    async def _one_pass(
        self, *, payload: Payload, seed_id: str
    ) -> _PerPayloadOutcome | _JudgedPass:
        """One invoke→delivery→judge pass.

        Returns a :class:`_JudgedPass` (the verdict + audit trace) on success, or
        a terminal :class:`_PerPayloadOutcome` for a structural skip / error that
        must not be retried.
        """
        try:
            response = await self._adapter.invoke(payload)
        except SeedArmUnavailable as skip:
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_no_seed_arm",
                    verdict_mechanism=None,
                    verdict_reason=skip.reason,
                    error_detail=None,
                ),
                exploit=None,
            )
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

        # Delivery verification (R6): an indirect-injection attempt whose poison
        # was never retrieved tested nothing — it must NOT be judged and read as
        # clean. Report it as skipped, distinct from a genuine no_finding.
        if response.metadata.get("payload_delivered") == "false":
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_payload_not_delivered",
                    verdict_mechanism=None,
                    verdict_reason=(
                        "the planted payload was never retrieved by the planner "
                        "(indirect injection not delivered); attempt not exercised"
                    ),
                    error_detail=None,
                    tool_call_trace=list(response.tool_calls),
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

        # Per-attempt audit trail (#14): persist the planner tool-call trace and
        # the judge evidence on EVERY judged outcome, so a no_finding is as
        # auditable as a finding without re-querying the target's own state.
        return _JudgedPass(
            verdict=verdict,
            response=response,
            tool_call_trace=list(response.tool_calls),
            judge_evidence={k: str(v) for k, v in verdict.evidence.items()},
        )
