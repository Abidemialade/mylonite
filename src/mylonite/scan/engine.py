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

from mylonite._redaction import redact
from mylonite.contracts import ExploitRecord, Payload, ScanAttempt, ScanReport, TargetDescriptor
from mylonite.scan._llm import (
    BudgetExceededError,
    LiteLLMCallCounter,
    llm_scope,
    seed_scope,
)
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable
from mylonite.scan.coverage import AbortReason
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.exec_context import ExecContext
from mylonite.scan.exfil import randomize_payload_exfil
from mylonite.scan.judge import SuccessJudge, never_exercised_tool_under_test
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
    max_concurrent: int = Field(
        default=3,
        ge=1,
        description=(
            "Max in-flight payload attempts. asyncio.Semaphore(0) would deadlock "
            "every attempt forever rather than error (DCR-0002); a negative value "
            "raises immediately from asyncio.Semaphore's own constructor. Neither "
            "is a config a caller could have MEANT, so reject both at construction."
        ),
    )
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
    provider_failure_threshold: int = Field(
        default=DEFAULT_PROVIDER_FAILURE_THRESHOLD,
        ge=1,
        description=(
            "Consecutive provider failures before the scan aborts. A value <1 "
            "would abort after the very FIRST attempt regardless of outcome "
            "(DCR-0012) — not a config a caller could have MEANT, so reject it "
            "at construction, mirroring max_concurrent. DCR-0018: 'consecutive' "
            "is a best-effort, PROCESS-WIDE notion under concurrency (max_concurrent "
            "> 1 or runs > 1) — the counter this threshold compares against "
            "(LiteLLMCallCounter.consecutive_failures) is ONE counter shared by "
            "every in-flight call across every concurrently-running payload/pass, "
            "not one per connection. It answers 'has the provider recently failed "
            "N times in a row across the whole scan's interleaved call stream' "
            "(a reasonable proxy for 'is the provider down'), NOT 'has any single "
            "payload's connection failed N times in a row' — an unrelated "
            "payload's success can reset the shared count and mask another "
            "payload's own failure streak, or unrelated failures across several "
            "payloads can cumulatively trip the threshold. See "
            "LiteLLMCallCounter's docstring for the full reasoning."
        ),
    )
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
    #: The target's self-description, when ``adapter.describe()`` succeeded
    #: (``None`` on a describe_failed abort). NOT part of ScanReport's
    #: schema — ScanResult is a plain dataclass, not one of the five
    #: Pydantic contracts, so adding a field here costs no compat event
    #: (contracts/_types.py's `extra="forbid"` + schema regeneration would
    #: apply to ScanReport, not this). Lets the structural recommendation
    #: engine (gate/recommend.py, PR2) see the real tool inventory without
    #: re-describing the target at prescription time.
    descriptor: TargetDescriptor | None = None


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
        aborted: AbortReason | None = None
        inconclusive_attempts = 0
        fallback_breakdown: dict[str, int] = {}
        module_ids = [m.attack_metadata().id for m in self._attack_modules]
        module_compliance = {
            m.attack_metadata().id: m.attack_metadata().compliance for m in self._attack_modules
        }

        # T14 code-review follow-up: routes through llm_scope(counter=...)
        # rather than counter.active() directly -- functionally identical
        # (both just set/reset the same _ACTIVE_COUNTER contextvar), but this
        # is what makes llm_scope's counter= parameter a real, exercised
        # production path instead of dead (only ever passed policy= in
        # practice; the CLI's own llm_scope(policy=...) calls for the active
        # LLMPolicy nest around this one, since asyncio.run() copies the
        # calling context). counter.active() itself stays available as a
        # narrower entry point for a caller that only wants the counter.
        with llm_scope(counter=counter):
            try:
                descriptor = await self._adapter.describe()
            except ImportError:
                # A missing dependency (e.g. the optional reference target) is a
                # configuration error, not a target failure — surface it so the
                # CLI can map it to a clear exit, rather than hiding it behind a
                # generic "describe_failed".
                raise
            except Exception as exc:
                # DCR-0016: logger.exception()'s implicit exc_info renders the
                # RAW (unredacted) exception text + traceback -- the
                # SecretRedactingFilter installed on the "mylonite" logger only
                # touches record.getMessage(), never the exc_info traceback a
                # handler's Formatter renders separately. Log only the
                # exception type name; nothing secret-shaped ever reaches a
                # handler this way.
                logger.error("ScanEngine: adapter.describe() raised: %s", type(exc).__name__)
                aborted = AbortReason.DESCRIBE_FAILED
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
            all_payloads: list[Payload] = []

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
                    all_payloads.append(payload)
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

            # Give every seed a floor of the budget before the rest is shared.
            # Payload tasks are all created up front, so a first-come-first-served
            # counter lets whichever seeds start first drain the pool -- and a
            # chain probe cut off after step one has called a tool without ever
            # reaching the tool under test, which reads as a clean pass unless the
            # honest-coverage check catches it. Starvation must be deterministic.
            counter.reserve_for(len(tasks))

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
                    aborted = AbortReason.NO_PAYLOADS
                return self._finalize(
                    attempts,
                    exploits,
                    aborted,
                    time.monotonic() - start,
                    module_ids,
                    descriptor=descriptor,
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
                    aborted = AbortReason.WALL_CLOCK_TIMEOUT
                    for pending in tasks:
                        pending.cancel()
                    break
                except BudgetExceededError:
                    aborted = AbortReason.BUDGET_EXCEEDED
                    # Name what never ran. A truncated scan that does not say
                    # which seeds it dropped reads downstream as a scan that
                    # covered everything -- the same silence the synthesis cap
                    # warning exists to break.
                    #
                    # `counter.by_seed` alone under-covers "started": a seed
                    # judged entirely by a deterministic predicate (no LLM call
                    # needed) can complete -- and already be sitting in
                    # `attempts` -- while spending zero calls, which put it in
                    # `starved` even though it fully ran and proved something.
                    # Excluding pattern_ids already recorded in `attempts`
                    # closes that: `by_seed` still catches a seed that spent
                    # budget but got cancelled mid-flight before completing.
                    completed = {a.pattern_id for a in attempts}
                    starved = sorted(
                        {p.pattern_id for p in all_payloads} - set(counter.by_seed) - completed
                    )
                    if starved:
                        logger.warning(
                            "budget exhausted after %d call(s): %d seed(s) never started "
                            "and proved NOTHING about this target: %s. Raise "
                            "--max-llm-calls or narrow the scan with --weakness-class.",
                            counter.count,
                            len(starved),
                            ", ".join(starved),
                        )
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
                # DCR-0018: `counter` is ONE process-wide LiteLLMCallCounter
                # shared across every concurrently-running payload/pass this
                # `run()` drives (see its docstring) — this is a best-effort
                # "has the provider recently failed repeatedly across the
                # scan's interleaved call stream" signal, not a strict
                # per-connection "this exact call chain failed N times in a
                # row" one. Accepted trade-off; see
                # ScanConfig.provider_failure_threshold's docstring.
                if counter.consecutive_failures >= self._config.provider_failure_threshold:
                    aborted = AbortReason.PROVIDER_UNREACHABLE
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

        # T15/H4: the planner's tool-schema sanitisation (scan._llm's
        # litellm_tool_call_async, via the SAME counter this run scoped
        # above) is counted on the counter itself, not per-_PerPayloadOutcome
        # like judge/customiser fallbacks — a planner run isn't a single
        # judged pass, it's a multi-iteration tool-calling loop nested inside
        # one payload attempt. Folded into fallback_breakdown here, after the
        # counter has seen every call the run made, so it's visible in the
        # report alongside the other fallback causes.
        if counter.tool_schema_sanitised:
            fallback_breakdown["tool_schema_sanitised"] = counter.tool_schema_sanitised

        return self._finalize(
            attempts,
            exploits,
            aborted,
            time.monotonic() - start,
            module_ids,
            inconclusive_attempts=inconclusive_attempts,
            fallback_breakdown=fallback_breakdown,
            descriptor=descriptor,
        )

    def _finalize(
        self,
        attempts: list[ScanAttempt],
        exploits: list[ExploitRecord],
        aborted: AbortReason | None,
        elapsed: float,
        module_ids: list[str],
        *,
        inconclusive_attempts: int = 0,
        fallback_breakdown: dict[str, int] | None = None,
        descriptor: TargetDescriptor | None = None,
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
        return ScanResult(
            report=report, exploits=self._stamp_exec_context(exploits), descriptor=descriptor
        )

    def _stamp_exec_context(self, exploits: list[ExploitRecord]) -> list[ExploitRecord]:
        """Stamp T12 execution-context metadata onto every finding's payload.

        Writer half of the T12 fix (see ``mylonite.scan.exec_context``): the
        model/provider that actually produced this scan's findings otherwise
        lives only on the sibling ``ScanReport`` (which ``TestGenerator.emit``
        never reads) -- so without this, an emitted regression test falls back
        to a hardcoded default that can silently differ from the model that
        found/validated the exploit. Rides in ``Payload.metadata`` (allowlisted,
        schema-invisible) rather than a new ``ExploitRecord`` field or an
        ``emit()`` signature change, so this needs no `contract-change`.
        """
        if not exploits:
            return exploits
        exec_context = ExecContext(
            provider=self._config.provider,
            model=self._config.model,
            planner_model=self._config.resolved_planner_model,
            customiser_model=self._config.resolved_customiser_model,
            judge_model=self._config.resolved_judge_model,
            mylonite_version=__version__,
        )
        stamped_metadata = exec_context.to_metadata()
        return [
            exploit.model_copy(
                update={
                    "payload": exploit.payload.model_copy(
                        update={"metadata": {**exploit.payload.metadata, **stamped_metadata}}
                    )
                }
            )
            for exploit in exploits
        ]

    async def _process_one(
        self,
        *,
        payload: Payload,
        module_id: str,
        descriptor: TargetDescriptor,
        semaphore: asyncio.Semaphore,
        compliance: Any,
    ) -> _PerPayloadOutcome:
        # DCR-0013: an explicit `is None` check, not truthy-`or` — a
        # present-but-EMPTY seed_id must not silently fall back to pattern_id
        # (which would corrupt compliance provenance for an otherwise-valid
        # metadata dict).
        _raw_seed_id = payload.metadata.get("seed_id")
        seed_id = _raw_seed_id if _raw_seed_id is not None else payload.pattern_id

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

        # DCR-0005: `semaphore` is threaded down into `_run_payload` (and from
        # there into `_run_flakiness_passes`) rather than held open here for
        # the payload's entire lifetime. See `_run_payload`'s docstring for
        # why holding it here caused effective concurrency to scale to
        # `max_concurrent ** 2` under `runs > 1`.
        # Every LLM call made below is attributed to this pattern, so the counter
        # can honour a per-seed floor and afterwards name the seeds that never
        # started. Keyed on pattern_id rather than seed_id: it is what the
        # starved-seed report and `--pattern-id` both speak, and several
        # synthesised patterns can share one seed_id.
        with seed_scope(payload.pattern_id):
            return await self._run_payload(
                payload=payload,
                module_id=module_id,
                descriptor=descriptor,
                compliance=compliance,
                seed_id=seed_id,
                semaphore=semaphore,
            )

    async def _run_payload(
        self,
        *,
        payload: Payload,
        module_id: str,
        descriptor: TargetDescriptor,
        compliance: Any,
        seed_id: str,
        semaphore: asyncio.Semaphore,
    ) -> _PerPayloadOutcome:
        """Customise, invoke, and judge one payload (``runs`` times under the
        scan-time flakiness filter).

        ``semaphore`` (DCR-0005) is the SAME cross-payload semaphore ``run()``
        constructs, threaded all the way down to every actual target-facing
        call this payload makes -- the customiser call below, the single
        ``_one_pass`` invocation (``runs == 1``), and every pass
        ``_run_flakiness_passes`` fans out (``runs > 1``) -- each acquiring
        and releasing it individually rather than one caller holding it open
        for this whole coroutine's lifetime. Before this, `_process_one` held
        one permit for the ENTIRE payload (customisation + all `runs`
        passes), and `_run_flakiness_passes` separately constructed its OWN
        fresh `Semaphore(max_concurrent)` to bound its `runs` passes -- so
        with `max_concurrent` payloads simultaneously mid-flakiness-fan-out,
        up to `max_concurrent ** 2` `adapter.invoke()` calls could be
        in-flight at once, `max_concurrent` times over its documented "max
        in-flight payload attempts" budget. Sharing one instance, acquired
        per actual call rather than held across the whole function, also
        rules out the deadlock a naive "just reuse it" fix would hit: a
        held-open outer permit plus a nested acquire of the SAME semaphore
        from the same task self-deadlocks the moment every permit is already
        claimed by an outer hold.
        """
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
            # Mirrors the judge call's handling below (see `_one_pass`): a
            # BudgetExceededError must keep propagating so `run()` can flip
            # `aborted="budget_exceeded"`, but any OTHER exception here — most
            # notably a `NonRecoverableProviderError` re-raised by `_llm.py`
            # (T4) for an auth/tls/context_window-classified failure — must
            # degrade to a per-attempt `outcome="error"` rather than escape
            # `_run_payload` uncaught. An uncaught exception here would skip
            # `run()`'s `asyncio.as_completed` loop entirely (it only catches
            # `TimeoutError`/`BudgetExceededError`), which in turn skips the
            # post-loop `asyncio.gather(*tasks, return_exceptions=True)` drain
            # that reaps cancelled/in-flight MCP subprocess tasks (worst on
            # Windows), AND skips the CLI's redaction step on the way out —
            # an unhandled provider exception's raw text (`Diagnosis.detail`)
            # could otherwise reach stderr/CI logs unredacted.
            try:
                async with semaphore:
                    payload = await self._customiser.customise(seed, descriptor)
            except BudgetExceededError:
                raise
            except Exception as exc:
                # DCR-0016: see the identical note at the adapter.describe()
                # catch site above -- logger.exception()'s traceback bypasses
                # the redaction filter entirely.
                logger.error("ScanEngine: customiser raised unexpectedly: %s", type(exc).__name__)
                return _PerPayloadOutcome(
                    attempt=ScanAttempt(
                        seed_id=seed_id,
                        pattern_id=payload.pattern_id,
                        outcome="error",
                        verdict_mechanism=None,
                        verdict_reason=redact(str(exc)),
                        error_detail=type(exc).__name__,
                    ),
                    exploit=None,
                )
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
        # fan-out — see ``_run_flakiness_passes`` for why that helper (not a
        # plain ``gather_bounded`` call) is what actually does the work.
        # runs=1 (the default, and every demo/replay path) stays a single bare
        # `await`, identical to the old sequential form -- just individually
        # acquiring the SAME shared semaphore around the one invoke, like
        # every other actual target-facing call in this function (DCR-0005).
        if runs == 1:
            async with semaphore:
                pass_results = [await self._one_pass(payload=payload, seed_id=seed_id)]
        else:
            pass_results = await self._run_flakiness_passes(
                payload=payload, seed_id=seed_id, runs=runs, semaphore=semaphore
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

        if last_pass is None:
            raise RuntimeError(
                "internal error: last_pass is None after the pass loop — runs >= 1 "
                "and every structural skip returns above, so at least one pass "
                "should have been recorded"
            )
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
        # An attempt whose seed attacks a capability this target does not expose is
        # NOT evidence the target is defended — it never got the chance to fail.
        # Reported as its own outcome so it can never be counted as a clean pass.
        # Requires EVERY pass to agree: one applicable pass means the capability
        # was reachable at least once, and a partly-applicable attempt is an
        # ordinary no_finding, not a structural skip.
        if all(not p.verdict.applicable for p in (*success_passes, *fail_passes)):
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="not_applicable",
                    verdict_mechanism=verdict.mechanism,
                    verdict_reason=verdict.reason,
                    not_applicable_reason=verdict.reason,
                    error_detail=None,
                    tool_call_trace=tool_call_trace,
                    judge_evidence=judge_evidence,
                ),
                exploit=None,
                judge_fallback_cause=verdict.fallback_cause,
                customiser_fallback=customiser_fallback,
                run_disagreement=run_disagreement,
            )
        # An attempt in which the agent made ZERO tool calls, on a target that
        # exposes tools, exercised nothing — the attack was delivered and the
        # planner simply never engaged with the tool surface. That is not a
        # demonstration that the target resisted, and it must not fall through to
        # `no_finding`. Requires EVERY pass to agree, mirroring the
        # `not_applicable` branch above: one pass with a tool call means the
        # surface WAS reachable, and a partly-engaged attempt is an ordinary
        # no_finding.
        #
        # Scoped by a known, non-empty tool_surface, so a black-box
        # `transport: rest` agent (no tools, judged on its reply text) is never
        # caught here.
        #
        # Scoped to the tool the seed actually declared, not merely to "any tool
        # call". A chain probe whose first step fails (a source tool returning
        # 503) leaves a NON-empty trace while never reaching the sink — measured,
        # and it fell straight through to `no_finding`. Empty means the seed
        # resolved no tool (every catalogue seed), and falls back to the
        # zero-call check unchanged.
        tool_under_test = payload.metadata.get("egress_tool") or payload.metadata.get(
            "consequential_tool", ""
        )
        all_passes = (*success_passes, *fail_passes)
        # `success_passes` non-empty here means a MINORITY success (is_finding
        # already returned above for a majority): with runs>1, some pass's
        # verdict fired. Success and this check are independent mechanisms — a
        # fuzzy-judge success is decided from the reply text/effect trace as a
        # whole, not by re-checking that `tool_under_test` literally appears in
        # THAT pass's `response.tool_calls` — so a genuinely landing pass can
        # still satisfy `never_exercised_tool_under_test` for its own response
        # (e.g. seed metadata names a slightly stale tool name). Requiring
        # `not success_passes` means any real engagement, in any pass, rules out
        # "the attack was never put to the target" — that framing is only true
        # when NOTHING fired across every run.
        if (
            not success_passes
            and all_passes
            and all(
                never_exercised_tool_under_test(p.response, tool_under_test) for p in all_passes
            )
        ):
            unexercised_reason = (
                (
                    f"the planner never invoked {tool_under_test!r}, the tool this attack "
                    "targets — the attack was delivered but never exercised against it, so "
                    "this is NOT evidence the target is defended"
                )
                if tool_under_test
                else (
                    "the planner made no tool calls on a tool-exposing target — "
                    "the attack was delivered but never exercised, so this is NOT "
                    "evidence the target is defended"
                )
            )
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_planner_no_engagement",
                    verdict_mechanism=verdict.mechanism,
                    verdict_reason=unexercised_reason,
                    error_detail=None,
                    tool_call_trace=tool_call_trace,
                    judge_evidence=judge_evidence,
                ),
                exploit=None,
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

    async def _run_flakiness_passes(
        self, *, payload: Payload, seed_id: str, runs: int, semaphore: asyncio.Semaphore
    ) -> list[_PerPayloadOutcome | _JudgedPass]:
        """Run ``runs`` invoke→judge passes for one payload, concurrently and bounded.

        Not a plain ``gather_bounded`` fan-out: the scan-wide LLM-call budget
        (``LiteLLMCallCounter``) is a SINGLE counter shared across every payload
        in the scan, not one per payload. Under the old strictly-sequential
        loop, a mid-run structural skip/error (pass 2 of 5, say) short-circuited
        immediately and passes 3-5 never spent budget. A naive concurrent
        fan-out launches all ``runs`` passes up front regardless — a structural
        skip (``SeedArmUnavailable``/``AdapterInvocationSkipped``) is a
        *returned* ``_PerPayloadOutcome``, not a raised exception, so
        ``asyncio.gather`` has no reason to cancel siblings — spending strictly
        more of the SHARED budget on passes that are discarded anyway. For a
        ``runs>1`` scan running close to ``--max-llm-calls``, that could tip a
        scan that would have completed under the old code into
        ``aborted=budget_exceeded``.

        So instead: launch all ``runs`` passes as real ``asyncio.Task``s,
        bounded by ``semaphore`` -- the SAME cross-payload semaphore ``run()``
        constructs and every sibling payload's passes also acquire (DCR-0005:
        this used to construct its OWN fresh ``Semaphore(max_concurrent)``,
        so total in-flight ``adapter.invoke()`` calls could reach
        ``max_concurrent ** 2`` — every one of up to ``max_concurrent``
        concurrently-processing payloads fanning out up to ``max_concurrent``
        of its own passes. Sharing one instance instead means the TOTAL
        in-flight invoke count across every payload and every one of its
        passes is what's capped at ``max_concurrent``, matching the
        setting's own documented "max in-flight payload attempts" budget).
        Each task checks a shared ``terminal_found`` flag *immediately after*
        acquiring the semaphore and *before* calling ``self._one_pass(...)`` —
        i.e. before it would spend any budget — and skips the call entirely if
        the flag is already set. As soon as any pass resolves to a terminal
        outcome (a structural-skip ``_PerPayloadOutcome``, or the one
        exception ``_one_pass`` can raise — ``BudgetExceededError``,
        propagated so ``run()`` can flip ``aborted="budget_exceeded"``) it
        sets the flag (synchronously, before yielding) and any pass still
        blocked behind the semaphore observes it and does no work. Passes
        already mid-flight when the flag flips are left to finish (there is
        no undoing a call already in progress) but nothing NEW is started —
        so at most ``max_concurrent`` passes ever reach ``adapter.invoke()``
        after the terminal is discovered, never scaling up to ``runs``. This
        matches the old early-return's budget behaviour while still running
        the common (all-non-terminal) case concurrently. Still-pending tasks
        are additionally cancelled once a terminal is found, purely so
        ``_run_payload`` doesn't wait around for passes whose result will be
        discarded.

        Each pass's ``self._one_pass(...)`` coroutine is created INSIDE its own
        wrapper task rather than up front in a list comprehension, so a task
        cancelled before its first execution turn never leaves an orphaned,
        never-awaited ``_one_pass`` coroutine (the same class of
        ``filterwarnings=error``-tripping "coroutine was never awaited" bug the
        runs=1 fast path avoids — see the call site).
        """
        sem = semaphore
        terminal_found = False

        async def _bounded(idx: int) -> tuple[int, _PerPayloadOutcome | _JudgedPass | None]:
            nonlocal terminal_found
            async with sem:
                if terminal_found:
                    return idx, None  # a sibling already proved this payload is pointless
                try:
                    result = await self._one_pass(payload=payload, seed_id=seed_id)
                except BaseException:
                    terminal_found = True  # a raised BudgetExceededError is terminal too
                    raise
                if isinstance(result, _PerPayloadOutcome):
                    terminal_found = True
                return idx, result

        tasks: list[asyncio.Task[tuple[int, _PerPayloadOutcome | _JudgedPass | None]]] = [
            asyncio.ensure_future(_bounded(i)) for i in range(runs)
        ]
        results: list[_PerPayloadOutcome | _JudgedPass | None] = [None] * runs
        pending: set[asyncio.Task[tuple[int, _PerPayloadOutcome | _JudgedPass | None]]] = set(tasks)
        terminal_exc: BaseException | None = None
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                stop = False
                # If MULTIPLE passes resolve to a terminal `_PerPayloadOutcome`
                # in the SAME completed batch (e.g. two concurrent invokes
                # both hit the same missing seed arm), each writes to its OWN
                # `results[idx]` slot — neither is overwritten, both survive
                # into the returned list. The actual tie-break happens one
                # level up, in `_run_payload`'s `for result in pass_results:
                # ... return result`, which returns the first terminal
                # outcome in ascending list/idx order — deterministic, not
                # "whichever finishes first". (`terminal_exc` IS a single
                # shared variable, so if instead multiple passes raise —
                # only `BudgetExceededError` can — whichever this loop
                # processes last does win there.) Either way this is safe
                # today because a structural-skip outcome for the same
                # payload/seed is content-equivalent regardless of which
                # concurrent copy is returned (same reason, same
                # verdict_mechanism=None) — but would need revisiting if a
                # future structural-skip type ever carried per-attempt state
                # that made one copy meaningfully different from another.
                for finished in done:
                    exc = finished.exception()
                    if exc is not None:
                        terminal_exc = exc
                        stop = True
                        continue
                    idx, result = finished.result()
                    if result is not None:
                        results[idx] = result
                    if isinstance(result, _PerPayloadOutcome):
                        stop = True
                if stop:
                    break
        finally:
            for pending_task in pending:
                pending_task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        if terminal_exc is not None:
            raise terminal_exc
        return [r for r in results if r is not None]

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
            # DCR-0017: redact, matching verdict_reason's treatment in the
            # sibling exception handlers below — attempt_metadata["exception"]
            # is raw exception text (e.g. from a str(exc) an adapter embedded),
            # not just a bare type name, so it can carry a secret-shaped value
            # (a credential embedded in a request that failed) straight into
            # this ScanAttempt, which write_artefacts persists to disk.
            _exc_detail = skip.attempt_metadata.get("exception")
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="skipped_planner_failure",
                    verdict_mechanism=None,
                    verdict_reason=skip.reason,
                    error_detail=redact(_exc_detail)
                    if isinstance(_exc_detail, str)
                    else _exc_detail,
                ),
                exploit=None,
            )
        except BudgetExceededError:
            # Propagate up so run() can flip aborted="budget_exceeded".
            raise
        except Exception as exc:
            # DCR-0016: see the identical note at the adapter.describe() catch
            # site in run() -- logger.exception()'s traceback bypasses the
            # redaction filter entirely.
            logger.error("ScanEngine: adapter.invoke raised unexpectedly: %s", type(exc).__name__)
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="error",
                    verdict_mechanism=None,
                    verdict_reason=redact(str(exc)),
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
            # DCR-0016: see the identical note at the adapter.describe() catch
            # site in run() -- logger.exception()'s traceback bypasses the
            # redaction filter entirely.
            logger.error("ScanEngine: judge raised unexpectedly: %s", type(exc).__name__)
            return _PerPayloadOutcome(
                attempt=ScanAttempt(
                    seed_id=seed_id,
                    pattern_id=payload.pattern_id,
                    outcome="error",
                    verdict_mechanism=None,
                    verdict_reason=redact(str(exc)),
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
