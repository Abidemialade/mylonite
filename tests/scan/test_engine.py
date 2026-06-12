"""ScanEngine integration-ish tests with mocked adapter, customiser, judge."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from mylonite.contracts._types import (
    AdapterResponse,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.scan._llm import BudgetExceededError, LiteLLMCallCounter, active_counter
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable, Verdict
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.seeds import SEED_CATALOGUE


class _ModuleStub:
    def __init__(self, payloads: list[Payload]) -> None:
        self._payloads = payloads

    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="stub-pattern",
            name="stub",
            summary="test",
            target_kinds=["mcp"],
            compliance=ComplianceTags(owasp_llm=["LLM01"]),
        )

    def generate_payloads(self, target: TargetDescriptor) -> list[Payload]:
        del target
        return self._payloads


class _AdapterStub:
    def __init__(
        self,
        response: AdapterResponse | None = None,
        *,
        raise_skipped: bool = False,
        raise_no_seed_arm: bool = False,
        raise_describe: bool = False,
    ) -> None:
        self._response = response
        self._raise_skipped = raise_skipped
        self._raise_no_seed_arm = raise_no_seed_arm
        self._raise_describe = raise_describe
        self.invoked: list[Payload] = []

    async def describe(self) -> TargetDescriptor:
        if self._raise_describe:
            raise RuntimeError("describe boom")
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
        if self._raise_no_seed_arm:
            raise SeedArmUnavailable(
                "setup arm 'seed_note' has no implementation for family 'stub'",
                attempt_metadata={"family": "stub", "setup": "seed_note"},
            )
        if self._raise_skipped:
            raise AdapterInvocationSkipped(
                "planner failure: simulated",
                attempt_metadata={"variant": "vulnerable", "exception": "RuntimeError"},
            )
        self.invoked.append(payload)
        assert self._response is not None
        return self._response

    async def close(self) -> None:
        return None


class _CustomiserStub:
    def __init__(self) -> None:
        self.calls = 0

    async def customise(self, seed: Any, target: Any) -> Payload:
        del target
        self.calls += 1
        return Payload(
            pattern_id=seed.pattern_id,
            channel=seed.channel,
            body=f"refined:{seed.seed_body[:20]}",
            metadata={
                "seed_id": seed.pattern_id,
                "weakness": seed.weakness,
                "predicate": seed.predicate,
                "setup": seed.setup,
                "drive": seed.drive,
            },
        )


class _JudgeStub:
    def __init__(self, verdict: Verdict) -> None:
        self._verdict = verdict
        self.calls = 0

    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        self.calls += 1
        return self._verdict


def _ok_response() -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="x",
        raw_response="ok",
        tool_calls=["read_note", "send_email"],
        metadata={"store_emails_sent": "[('attacker@example.com',)]"},
    )


def _payload_from_seed_index(i: int) -> Payload:
    seed = SEED_CATALOGUE[i]
    return Payload(
        pattern_id=seed.pattern_id,
        channel=seed.channel,
        body=seed.seed_body,
        metadata={
            "seed_id": seed.pattern_id,
            "weakness": seed.weakness,
            "predicate": seed.predicate,
            "setup": seed.setup,
            "drive": seed.drive,
            "needs_customisation": "true",
        },
    )


def _config(
    *,
    dry_run: bool = False,
    max_llm_calls: int = 50,
    pattern_id_filter: str | None = None,
    customise: bool = True,
    runs: int = 1,
    wall_clock_timeout_s: float | None = None,
) -> ScanConfig:
    return ScanConfig(
        target_id="reference:vulnerable",
        provider="anthropic",
        model="stub-model",
        max_llm_calls=max_llm_calls,
        max_concurrent=2,
        output_dir=Path(".mylonite/scans"),
        dry_run=dry_run,
        pattern_id_filter=pattern_id_filter,
        customise=customise,
        runs=runs,
        wall_clock_timeout_s=wall_clock_timeout_s,
    )


class _JudgeSequence:
    """Judge double that returns scripted verdicts in order (per invoke→judge pass)."""

    def __init__(self, verdicts: list[Verdict]) -> None:
        self._verdicts = verdicts
        self.calls = 0

    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        v = self._verdicts[min(self.calls, len(self._verdicts) - 1)]
        self.calls += 1
        return v


def _yes() -> Verdict:
    return Verdict(success=True, reason="fired", evidence={}, mechanism="predicate")


def _no() -> Verdict:
    return Verdict(success=False, reason="held", evidence={}, mechanism="predicate")


# --- happy path -------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_records_finding_on_success_verdict() -> None:
    payload = _payload_from_seed_index(0)
    module = _ModuleStub([payload])
    adapter = _AdapterStub(_ok_response())
    customiser = _CustomiserStub()
    judge = _JudgeStub(
        Verdict(success=True, reason="caught it", evidence={}, mechanism="predicate")
    )

    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[module],
        customiser=customiser,
        judge=judge,
    )
    result = await engine.run()
    assert result.report.findings_count == 1
    assert len(result.exploits) == 1
    assert result.exploits[0].pattern_id == payload.pattern_id
    assert result.report.attempts[0].outcome == "finding"
    assert customiser.calls == 1


@pytest.mark.asyncio
async def test_engine_stamps_compliance_from_firing_seed_not_module() -> None:
    """Provenance (#4): the emitted ExploitRecord carries the FIRING seed's
    compliance tags, not the umbrella module's. A module spans several weakness
    classes, so module-level tags mislabel which OWASP/ASI/ATLAS IDs the test
    actually proves. The module stub here advertises only ``owasp_llm=['LLM01']``
    with empty ASI/ATLAS; the seed carries fuller tags, so the difference is
    observable end-to-end."""
    seed = SEED_CATALOGUE[0]
    payload = _payload_from_seed_index(0)
    # Precondition: the seed's tags differ from the module stub's, so the
    # assertion can actually distinguish the two sources.
    assert seed.compliance != _ModuleStub([]).attack_metadata().compliance

    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(
            Verdict(success=True, reason="caught it", evidence={}, mechanism="predicate")
        ),
    )
    result = await engine.run()

    assert len(result.exploits) == 1
    # Round-trip: the emitted compliance is exactly the firing seed's, not the module's.
    assert result.exploits[0].compliance == seed.compliance


@pytest.mark.asyncio
async def test_engine_customise_false_skips_customiser() -> None:
    """config.customise=False: the per-seed customiser is never called (demo determinism)."""
    payload = _payload_from_seed_index(0)  # has needs_customisation=true
    customiser = _CustomiserStub()
    engine = ScanEngine(
        config=_config(customise=False),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=customiser,
        judge=_JudgeStub(Verdict(success=True, reason="x", evidence={}, mechanism="predicate")),
    )
    result = await engine.run()
    assert customiser.calls == 0
    assert result.report.attempts[0].outcome == "finding"


# --- G2 / A4 metadata validation -------------------------------------------


@pytest.mark.asyncio
async def test_engine_skips_payload_missing_required_metadata() -> None:
    broken = Payload(
        pattern_id="missing-meta",
        channel="tool-result",
        body="x",
        metadata={"seed_id": "missing-meta"},  # no predicate / setup / drive / weakness
    )
    module = _ModuleStub([broken])
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(),
        attack_modules=[module],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert len(result.report.attempts) == 1
    assert result.report.attempts[0].outcome == "skipped_invalid_metadata"
    assert result.report.findings_count == 0


# --- G3 / A3 planner skip --------------------------------------------------


@pytest.mark.asyncio
async def test_engine_logs_skipped_planner_failure() -> None:
    payload = _payload_from_seed_index(0)
    adapter = _AdapterStub(raise_skipped=True)
    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "skipped_planner_failure"
    assert result.report.findings_count == 0


@pytest.mark.asyncio
async def test_engine_undelivered_payload_is_skipped_not_clean() -> None:
    """Issue R6: an indirect attempt whose poison wasn't retrieved is skipped, not clean."""
    payload = _payload_from_seed_index(0)
    undelivered = AdapterResponse(
        payload_pattern_id="x",
        raw_response="I couldn't find that note.",
        tool_calls=["recall"],
        metadata={"payload_delivered": "false"},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(undelivered),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=True, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "skipped_payload_not_delivered"
    assert result.report.findings_count == 0


@pytest.mark.asyncio
async def test_engine_records_skipped_no_seed_arm_not_no_finding() -> None:
    """Issue #5: an un-plantable indirect seed is reported skipped, never no_finding."""
    payload = _payload_from_seed_index(0)
    adapter = _AdapterStub(raise_no_seed_arm=True)
    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "skipped_no_seed_arm"
    assert "seed_note" in (result.report.attempts[0].verdict_reason or "")
    assert result.report.findings_count == 0


# --- dry-run ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_dry_run_skips_customisation_and_invocation() -> None:
    payload = _payload_from_seed_index(0)
    adapter = _AdapterStub(_ok_response())
    customiser = _CustomiserStub()
    engine = ScanEngine(
        config=_config(dry_run=True),
        adapter=adapter,
        attack_modules=[_ModuleStub([payload])],
        customiser=customiser,
        judge=_JudgeStub(Verdict(success=True, reason="x", evidence={}, mechanism="predicate")),
    )
    result = await engine.run()
    assert customiser.calls == 0
    assert adapter.invoked == []
    assert result.report.attempts[0].outcome == "skipped_dry_run"


# --- skipped_unknown_seed --------------------------------------------------


@pytest.mark.asyncio
async def test_engine_skips_unknown_seed_id() -> None:
    payload = Payload(
        pattern_id="unknown-pattern",
        channel="tool-result",
        body="x",
        metadata={
            "seed_id": "not-in-catalogue",
            "weakness": "W2",
            "predicate": "send_email_to_attacker",
            "setup": "seed_note",
            "drive": "read_note_for_summary",
            "needs_customisation": "true",
        },
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "skipped_unknown_seed"


# --- pattern_id_filter (single-seed scoping) -------------------------------


@pytest.mark.asyncio
async def test_engine_pattern_id_filter_runs_only_matching_seed() -> None:
    """``pattern_id_filter`` set → only payloads with that pattern_id attempt."""
    p0 = _payload_from_seed_index(0)
    p1 = _payload_from_seed_index(1)
    assert p0.pattern_id != p1.pattern_id
    customiser = _CustomiserStub()
    judge = _JudgeStub(Verdict(success=False, reason="held", evidence={}, mechanism="llm"))
    engine = ScanEngine(
        config=_config(pattern_id_filter=p1.pattern_id),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([p0, p1])],
        customiser=customiser,
        judge=judge,
    )
    result = await engine.run()
    assert {a.pattern_id for a in result.report.attempts} == {p1.pattern_id}
    # Filtered-out seed never reached the customiser / judge (pre-task drop).
    assert customiser.calls == 1
    assert judge.calls == 1


@pytest.mark.asyncio
async def test_engine_pattern_id_filter_no_match_is_clean_empty() -> None:
    """A filter matching nothing → no attempts, no crash, clean result."""
    p0 = _payload_from_seed_index(0)
    p1 = _payload_from_seed_index(1)
    customiser = _CustomiserStub()
    engine = ScanEngine(
        config=_config(pattern_id_filter="does-not-exist"),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([p0, p1])],
        customiser=customiser,
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts == []
    assert result.report.findings_count == 0
    assert result.report.aborted is None
    assert customiser.calls == 0


@pytest.mark.asyncio
async def test_engine_describe_failure_aborts_describe_failed() -> None:
    """adapter.describe() raising → aborted=describe_failed (not a silent clean pass)."""
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(raise_describe=True),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.aborted == "describe_failed"
    assert result.report.attempts == []


@pytest.mark.asyncio
async def test_engine_zero_payloads_aborts_no_payloads() -> None:
    """Issue #3: a real scan that produced no payloads must be loud, not clean-empty."""
    engine = ScanEngine(
        config=_config(),  # no pattern_id_filter
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([])],  # module yields nothing
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts == []
    assert result.report.aborted == "no_payloads"


@pytest.mark.asyncio
async def test_engine_pattern_id_filter_none_runs_all_payloads() -> None:
    """Default ``pattern_id_filter=None`` → every payload runs (backward-compat)."""
    p0 = _payload_from_seed_index(0)
    p1 = _payload_from_seed_index(1)
    engine = ScanEngine(
        config=_config(),  # pattern_id_filter defaults to None
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([p0, p1])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert {a.pattern_id for a in result.report.attempts} == {p0.pattern_id, p1.pattern_id}


@pytest.mark.asyncio
async def test_engine_dedupes_same_pattern_id_across_modules() -> None:
    """The same pattern_id emitted by two modules runs at most once (#5).

    Belt-and-suspenders behind the per-module weakness filters: a seed must not
    be exercised (or counted) twice just because two modules surface it.
    """
    p0 = _payload_from_seed_index(0)
    dup = _payload_from_seed_index(0)  # identical pattern_id from a second module
    p1 = _payload_from_seed_index(1)
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([p0, p1]), _ModuleStub([dup])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()

    pattern_ids = [a.pattern_id for a in result.report.attempts]
    assert sorted(pattern_ids) == sorted({p0.pattern_id, p1.pattern_id})
    # The duplicate ran exactly once, not twice.
    assert pattern_ids.count(p0.pattern_id) == 1


# --- #14 per-attempt audit trace -------------------------------------------


@pytest.mark.asyncio
async def test_engine_persists_tool_trace_and_evidence_on_no_finding() -> None:
    """A no_finding attempt still carries the planner tool-call trace + judge evidence."""
    payload = _payload_from_seed_index(0)
    judge = _JudgeStub(
        Verdict(
            success=False,
            reason="held",
            evidence={"confidence": 0.1, "recipient": "ops@example.com"},
            mechanism="llm",
        )
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),  # tool_calls=["read_note", "send_email"]
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "no_finding"
    assert attempt.tool_call_trace == ["read_note", "send_email"]
    assert attempt.judge_evidence["recipient"] == "ops@example.com"


# --- #8 inconclusive / fallback-rate tally ---------------------------------


@pytest.mark.asyncio
async def test_engine_counts_inconclusive_judge_fallbacks() -> None:
    """A judge verdict carrying fallback_cause is tallied as inconclusive, not clean."""
    payload = _payload_from_seed_index(0)
    judge = _JudgeStub(
        Verdict(
            success=False,
            reason="LLM-judge inconclusive — LLM output not parseable as JSON",
            evidence={},
            mechanism="llm",
            fallback_cause="unparseable_output",
        )
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "no_finding"
    assert result.report.inconclusive_attempts == 1
    assert result.report.fallback_breakdown == {"judge_unparseable_output": 1}


# --- G7 budget tracking across layers -------------------------------------


@pytest.mark.asyncio
async def test_engine_budget_aborts_on_exhaustion() -> None:
    """Customiser raises BudgetExceededError → engine sets aborted=budget_exceeded."""

    class _BudgetBreakingCustomiser:
        async def customise(self, seed: Any, target: Any) -> Payload:
            del seed, target
            counter = active_counter()
            if counter is not None:
                # Force the cap to be hit on first call.
                counter.record("customiser")
            raise BudgetExceededError("test budget exhausted")

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(max_llm_calls=1),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_BudgetBreakingCustomiser(),  # type: ignore[arg-type]
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.aborted == "budget_exceeded"


@pytest.mark.asyncio
async def test_engine_runs_active_counter_inside_scope() -> None:
    """Sanity check: counter is active when engine runs (so wrapped completion_fns work)."""
    captured: list[LiteLLMCallCounter | None] = []

    class _CapturingCustomiser:
        async def customise(self, seed: Any, target: Any) -> Payload:
            del target
            captured.append(active_counter())
            return Payload(
                pattern_id=seed.pattern_id,
                channel=seed.channel,
                body="x",
                metadata={
                    "seed_id": seed.pattern_id,
                    "weakness": seed.weakness,
                    "predicate": seed.predicate,
                    "setup": seed.setup,
                    "drive": seed.drive,
                },
            )

    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CapturingCustomiser(),  # type: ignore[arg-type]
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    await engine.run()
    assert captured[0] is not None
    assert isinstance(captured[0], LiteLLMCallCounter)


# --- #8 / Pattern E: N-run flakiness filter + wall-clock timeout -----------


@pytest.mark.asyncio
async def test_engine_default_runs_is_single_run() -> None:
    """runs defaults to 1 → report.single_run stays True (backward-compat)."""
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(_no()),
    )
    result = await engine.run()
    assert result.report.single_run is True


@pytest.mark.asyncio
async def test_engine_nrun_majority_fires_is_finding() -> None:
    """runs=3 with 2 fires + 1 hold → strict majority → finding; single_run=False."""
    judge = _JudgeSequence([_yes(), _no(), _yes()])
    engine = ScanEngine(
        config=_config(runs=3),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    assert judge.calls == 3  # invoked + judged 3 times
    assert result.report.single_run is False
    assert result.report.findings_count == 1
    assert result.report.attempts[0].outcome == "finding"
    # The runs disagreed (2 of 3) → flakiness surfaced.
    assert result.report.fallback_breakdown.get("nrun_disagreement") == 1


@pytest.mark.asyncio
async def test_engine_nrun_minority_fire_is_rejected_as_flaky() -> None:
    """runs=3 with only 1 fire → below strict majority → no_finding (fluke rejected)."""
    judge = _JudgeSequence([_yes(), _no(), _no()])
    engine = ScanEngine(
        config=_config(runs=3),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    assert result.report.findings_count == 0
    assert result.report.attempts[0].outcome == "no_finding"
    assert result.report.fallback_breakdown.get("nrun_disagreement") == 1


@pytest.mark.asyncio
async def test_engine_nrun_minority_success_last_reports_failing_reason() -> None:
    """A minority fire whose SUCCESS pass is LAST must still stamp the no_finding
    attempt with a FAILING verdict reason — not the success pass's reason (the
    audit record must never contradict its own outcome)."""
    # Order matters: success is the final pass, so a naive `last_pass` would leak
    # the success reason ("fired") onto a no_finding attempt.
    judge = _JudgeSequence([_no(), _no(), _yes()])
    engine = ScanEngine(
        config=_config(runs=3),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "no_finding"
    assert attempt.verdict_reason == "held"  # the FAIL reason, not "fired"


@pytest.mark.asyncio
async def test_engine_nrun_unanimous_has_no_disagreement_tally() -> None:
    """runs=2 both fire → finding with no nrun_disagreement (agreement, not flake)."""
    engine = ScanEngine(
        config=_config(runs=2),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeSequence([_yes(), _yes()]),
    )
    result = await engine.run()
    assert result.report.findings_count == 1
    assert "nrun_disagreement" not in result.report.fallback_breakdown


@pytest.mark.asyncio
async def test_engine_nrun_does_not_retry_structural_skip() -> None:
    """A no-seed-arm skip on the first pass is terminal — not retried under runs>1."""
    adapter = _AdapterStub(raise_no_seed_arm=True)
    engine = ScanEngine(
        config=_config(runs=5),
        adapter=adapter,
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(_no()),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "skipped_no_seed_arm"


@pytest.mark.asyncio
async def test_engine_wall_clock_timeout_aborts_with_partial_results() -> None:
    """A wall-clock budget that elapses mid-scan → aborted='wall_clock_timeout'."""

    class _SlowAdapter(_AdapterStub):
        async def invoke(self, payload: Payload) -> AdapterResponse:
            await asyncio.sleep(0.5)
            return await super().invoke(payload)

    engine = ScanEngine(
        config=_config(wall_clock_timeout_s=0.05, max_llm_calls=50),
        adapter=_SlowAdapter(_ok_response()),
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(_no()),
    )
    result = await engine.run()
    assert result.report.aborted == "wall_clock_timeout"
