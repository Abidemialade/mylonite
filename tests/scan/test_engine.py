"""ScanEngine integration-ish tests with mocked adapter, customiser, judge."""

from __future__ import annotations

import asyncio
import json
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
from mylonite.scan._llm import (
    BudgetExceededError,
    LiteLLMCallCounter,
    NonRecoverableProviderError,
    active_counter,
    litellm_tool_call_async,
)
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable, Verdict
from mylonite.scan.diagnostics import Diagnosis
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
        #: Every invoke() ATTEMPT, including ones that go on to raise a
        #: structural skip — unlike ``invoked`` (only successful calls). Lets
        #: tests assert how much work a runs>1 flakiness filter actually did.
        self.invoke_call_count = 0

    async def describe(self) -> TargetDescriptor:
        if self._raise_describe:
            raise RuntimeError("describe boom")
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
        self.invoke_call_count += 1
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
async def test_engine_stamps_exec_context_metadata_on_exploit() -> None:
    """T12: ``_finalize`` stamps ``mylonite.exec.*`` exec-context metadata onto
    every finding's payload -- provider/model (from ``ScanConfig``) and the
    resolved role models -- so an emitted regression test can gate on the SAME
    model that discovered the finding, instead of a testkit hardcoded default.
    """
    from mylonite.scan.exec_context import ExecContext
    from mylonite.version import __version__

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
    assert len(result.exploits) == 1
    ctx = ExecContext.from_metadata(result.exploits[0].payload.metadata)
    assert ctx is not None
    assert ctx.provider == "anthropic"
    assert ctx.model == "stub-model"
    # _config() sets no role overrides, so every role falls back to `model`.
    assert ctx.planner_model == "stub-model"
    assert ctx.customiser_model == "stub-model"
    assert ctx.judge_model == "stub-model"
    assert ctx.mylonite_version == __version__


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
async def test_engine_redacts_secret_shaped_exception_in_skipped_planner_failure() -> None:
    """DCR-0017: ``AdapterInvocationSkipped.attempt_metadata["exception"]`` is raw
    exception text (not just a bare type name) an adapter can embed a live
    secret into (e.g. a credential from a failed request), stored VERBATIM
    into ``ScanAttempt.error_detail`` -- which ``write_artefacts`` persists to
    ``scan_report.json``, a file the operator is told to commit. Must be
    redacted, matching the treatment ``verdict_reason`` already gets in the
    sibling exception handlers in this same file.
    """
    sentinel = "sk-ant-sentinelsecretvalue1234567890"

    class _SecretLeakingSkipAdapter(_AdapterStub):
        async def invoke(self, payload: Payload) -> AdapterResponse:
            self.invoke_call_count += 1
            raise AdapterInvocationSkipped(
                "planner failure: simulated",
                attempt_metadata={
                    "variant": "vulnerable",
                    "exception": f"RuntimeError: connection failed ({sentinel})",
                },
            )

    payload = _payload_from_seed_index(0)
    adapter = _SecretLeakingSkipAdapter(raise_skipped=True)
    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "skipped_planner_failure"
    assert attempt.error_detail is not None
    assert sentinel not in attempt.error_detail


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
async def test_engine_zero_tool_calls_is_skipped_not_clean() -> None:
    """An attempt in which the agent called NO tools is not evidence of resistance.

    The planner was driven and returned, but never touched the tool surface, so
    the attack was never exercised against the target. Reporting that as
    ``no_finding`` is what let an untested attempt render as a clean pass —
    measured at 15 of 22 clean verdicts on a third-party corpus.
    """
    payload = _payload_from_seed_index(0)
    no_action = AdapterResponse(
        payload_pattern_id="x",
        raw_response="I'd rather not do that.",
        tool_calls=[],
        metadata={"tool_surface": json.dumps([{"name": "send_email"}])},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(no_action),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="declined", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "skipped_planner_no_engagement"
    assert "no tool calls" in (attempt.verdict_reason or "")
    assert result.report.findings_count == 0


@pytest.mark.asyncio
async def test_engine_zero_tool_calls_on_toolless_target_is_still_no_finding() -> None:
    """A black-box ``transport: rest`` agent exposes no tools and is judged on its reply.

    It must NOT be swept into the no-engagement branch — there is nothing to call,
    so an empty trace is the normal, correct shape for that target kind.
    """
    payload = _payload_from_seed_index(0)
    toolless = AdapterResponse(
        payload_pattern_id="x",
        raw_response="Here is a harmless answer.",
        tool_calls=[],
        metadata={},  # no tool_surface stamped → not a tool-exposing target
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(toolless),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="clean", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "no_finding"


@pytest.mark.asyncio
async def test_engine_one_tool_call_is_a_real_no_finding() -> None:
    """The agent acted and the target held — that IS a genuine negative result."""
    payload = _payload_from_seed_index(0)
    acted = AdapterResponse(
        payload_pattern_id="x",
        raw_response="Sent nothing useful.",
        tool_calls=["read_note"],
        metadata={"tool_surface": json.dumps([{"name": "read_note"}])},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(acted),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="resisted", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "no_finding"


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


@pytest.mark.asyncio
async def test_engine_treats_present_but_empty_seed_id_as_unknown_not_pattern_id_fallback() -> None:
    """DCR-0013: `seed_id = payload.metadata.get("seed_id") or payload.pattern_id`
    used truthy-`or`, not an `is None` check -- a present-but-EMPTY seed_id
    silently fell back to pattern_id, corrupting compliance provenance. Uses a
    pattern_id that IS a real catalogue seed id so the OLD buggy fallback would
    resolve it successfully (treated as a known seed, proceeding normally)
    while the fixed behaviour (an explicit empty seed_id is not in the
    catalogue) correctly reports skipped_unknown_seed."""
    real_seed_id = SEED_CATALOGUE[0].pattern_id
    payload = Payload(
        pattern_id=real_seed_id,
        channel="tool-result",
        body="x",
        metadata={
            "seed_id": "",  # present but EMPTY -- must NOT fall back to pattern_id
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


# --- T15/H4: tool_schema_sanitised end-to-end through a real ScanEngine.run --

#: A $ref-bearing tool schema shaped like real pydantic-generated MCP output
#: (see scan/schema_sanitise.py's module docstring) -- STRICT-dialect
#: providers (Gemini/Vertex/Bedrock) reject this unsanitised.
_REF_BEARING_TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "note_id": {"type": "string"},
        "filter": {"$ref": "#/$defs/NoteFilter"},
    },
    "required": ["note_id"],
    "$defs": {
        "NoteFilter": {
            "type": "object",
            "properties": {"tag": {"type": "string"}},
            "required": ["tag"],
        }
    },
}

_CLEAN_TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"note_id": {"type": "string"}},
    "required": ["note_id"],
}


class _PlannerCallingAdapterStub:
    """Simulates what a REAL adapter's invoke() does mid-scan: drive
    ``litellm_tool_call_async`` -- the planner's SOLE chokepoint (T14) -- with
    a real tool schema and a stubbed ``completion_fn``. Close enough to
    exercise T15's ``LiteLLMCallCounter.tool_schema_sanitised`` bump ->
    ``ScanEngine._finalize``'s ``fallback_breakdown`` fold end-to-end through
    a genuine ``ScanEngine.run()``, without spinning up a real MCP
    session/subprocess (unlike ``_AdapterStub``, which never touches the LLM
    chokepoint at all and so could never have caught this wiring breaking).
    """

    def __init__(self, *, model: str, tool_schema: dict[str, Any]) -> None:
        self._model = model
        self._tool_schema = tool_schema

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
        del payload

        async def _stub_completion(**_: Any) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="done.", tool_calls=None))]
            )

        await litellm_tool_call_async(
            model=self._model,
            messages=[{"role": "user", "content": "hi"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "get_notes",
                        "description": "fetch notes",
                        "parameters": self._tool_schema,
                    },
                }
            ],
            completion_fn=_stub_completion,
        )
        return _ok_response()

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_engine_folds_tool_schema_sanitisation_into_fallback_breakdown() -> None:
    """A STRICT-dialect model (bedrock/...) whose planner tool schema carries a
    $ref must show up as ``fallback_breakdown["tool_schema_sanitised"]`` on the
    finished report -- the counter bump inside ``litellm_tool_call_async``
    (T15) has to survive all the way through ``ScanEngine._finalize``'s fold,
    not just be observable by poking ``LiteLLMCallCounter`` directly."""
    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_PlannerCallingAdapterStub(
            model="bedrock/anthropic.claude-3-haiku", tool_schema=_REF_BEARING_TOOL_SCHEMA
        ),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert result.report.fallback_breakdown.get("tool_schema_sanitised") == 1


@pytest.mark.asyncio
async def test_engine_tool_schema_sanitised_absent_for_permissive_model() -> None:
    """A PERMISSIVE-dialect model (anthropic/...) with the SAME $ref-bearing
    schema must leave ``tool_schema_sanitised`` out of the breakdown entirely
    -- sanitisation never ran, so there is nothing to count."""
    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_PlannerCallingAdapterStub(
            model="anthropic/claude-haiku-4-5", tool_schema=_REF_BEARING_TOOL_SCHEMA
        ),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert "tool_schema_sanitised" not in result.report.fallback_breakdown


@pytest.mark.asyncio
async def test_engine_tool_schema_sanitised_absent_for_already_clean_schema() -> None:
    """A STRICT-dialect model with an already-clean schema (no $ref/anyOf/
    const/additionalProperties) must also leave the key out -- sanitisation
    ran but had no real effect, matching the "only when it changes something"
    contract."""
    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_PlannerCallingAdapterStub(
            model="bedrock/anthropic.claude-3-haiku", tool_schema=_CLEAN_TOOL_SCHEMA
        ),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    assert "tool_schema_sanitised" not in result.report.fallback_breakdown


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
async def test_starved_report_excludes_a_seed_that_already_completed_with_zero_llm_calls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A seed judged entirely by a deterministic predicate (no LLM call needed)
    can complete -- and already be sitting in `attempts` -- while spending ZERO
    LLM calls. Before the fix, the starved-seed warning was computed purely from
    `counter.by_seed`, so a seed like this was reported as having "never
    started" and having "proved NOTHING", even though it fully ran and produced
    a recorded outcome -- just because a LATER seed exhausted the budget.
    """
    safe_seed_id = SEED_CATALOGUE[0].pattern_id
    boom_seed_id = SEED_CATALOGUE[1].pattern_id
    starved_seed_id = SEED_CATALOGUE[2].pattern_id

    def _mk(seed_id: str) -> Payload:
        return Payload(
            pattern_id=seed_id,
            channel="tool-result",
            body="x",
            metadata={
                "seed_id": seed_id,
                "weakness": "W1",
                "predicate": "x",
                "setup": "no_setup",
                "drive": "verbatim",
            },
        )

    safe_payload = _mk(safe_seed_id)
    boom_payload = _mk(boom_seed_id)
    starved_payload = _mk(starved_seed_id)

    class _MixedAdapter:
        async def describe(self) -> TargetDescriptor:
            return TargetDescriptor(
                target_id="stub-target", kind="mcp", system_prompt="x", tools=[]
            )

        async def invoke(self, payload: Payload) -> AdapterResponse:
            if payload.pattern_id == boom_seed_id:
                # Yield first so `safe_payload` (no await before its adapter
                # response) completes and is appended to `attempts` before this
                # one raises.
                await asyncio.sleep(0.02)
                counter = active_counter()
                if counter is not None:
                    counter.record("adapter")
                raise BudgetExceededError("test budget exhausted")
            if payload.pattern_id == starved_seed_id:
                # Long enough that `run()`'s cancel-and-break (triggered by
                # `boom_payload`'s exception) fires first -- this one never
                # gets a chance to prove anything.
                await asyncio.sleep(5)
                return _ok_response()
            return _ok_response()

        async def close(self) -> None:
            return None

    engine = ScanEngine(
        config=_config(max_llm_calls=1, customise=False),
        adapter=_MixedAdapter(),  # type: ignore[arg-type]
        attack_modules=[_ModuleStub([safe_payload, boom_payload, starved_payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    with caplog.at_level("WARNING", logger="mylonite.scan.engine"):
        result = await engine.run()

    assert result.report.aborted == "budget_exceeded"
    assert any(a.pattern_id == safe_seed_id for a in result.report.attempts)
    warning_text = "\n".join(caplog.messages)
    assert safe_seed_id not in warning_text, "an already-completed seed must not read as starved"
    assert starved_seed_id in warning_text, "a seed that never got to run must still be named"


@pytest.mark.asyncio
async def test_customiser_non_recoverable_error_degrades_to_error_outcome_not_crash() -> None:
    """T4 follow-up (reviewer-flagged gap): a NonRecoverableProviderError (auth/
    tls/context_window — see ``_llm.py``) raised by the customiser must NOT escape
    ``_run_payload``/``run()`` as an unhandled exception.

    Before this fix, an exception here skipped `run()`'s `asyncio.as_completed`
    loop entirely (it only catches `TimeoutError`/`BudgetExceededError`), which
    in turn skipped the post-loop `asyncio.gather(*tasks, return_exceptions=True)`
    drain that reaps cancelled/in-flight MCP `stdio_client` subprocess tasks
    (worst on Windows — see `run()`'s own comment), AND skipped the CLI's
    redaction step on the exception's way out to stderr. Mirrors the judge
    call's pre-existing `except Exception: outcome="error"` handling in
    `_one_pass` — the customiser call site now gets the same treatment.

    Proving `engine.run()` returns a normal `ScanResult` (rather than the
    exception propagating out of this call) is sufficient to prove the drain
    runs: the post-loop `gather` sits unconditionally between the
    `as_completed` loop and `_finalize()` on every normal-return path.
    """

    class _BoomCustomiser:
        async def customise(self, seed: Any, target: Any) -> Payload:
            del seed, target
            raise NonRecoverableProviderError(
                Diagnosis(category="auth", detail="boom: bad key", remedy="fix your key"),
                caller="customiser",
            )

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_BoomCustomiser(),  # type: ignore[arg-type]
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()  # must not raise
    assert result.report.aborted is None
    assert len(result.report.attempts) == 1
    attempt = result.report.attempts[0]
    assert attempt.outcome == "error"
    assert attempt.error_detail == "NonRecoverableProviderError"
    assert attempt.verdict_reason is not None
    assert "auth" in attempt.verdict_reason
    assert result.report.findings_count == 0


# --- DCR-0005: exception text persisted to ScanAttempt must be redacted ----

#: A RuntimeError message shaped like a real leak: an Authorization header
#: echoed back by an httpx error, or an env-var value baked into an MCP
#: subprocess launch failure. `write_artefacts` persists `verdict_reason`
#: verbatim to `scan_report.json` -- a directory the CLI's own next-step
#: guidance (`cli.py`) tells the operator to commit.
_SECRET_EXC_TEXT = (
    "connection failed: Authorization: Bearer sk-live-shouldnotleak123"  # pragma: allowlist secret
)


@pytest.mark.asyncio
async def test_customiser_exception_text_is_redacted_before_persisting() -> None:
    """DCR-0005: a customiser exception carrying a credential-shaped string must
    not land verbatim in the persisted `ScanAttempt.verdict_reason`.
    """

    class _LeakyCustomiser:
        async def customise(self, seed: Any, target: Any) -> Payload:
            del seed, target
            raise RuntimeError(_SECRET_EXC_TEXT)

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_LeakyCustomiser(),  # type: ignore[arg-type]
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "error"
    assert attempt.verdict_reason is not None
    assert "sk-live-shouldnotleak123" not in attempt.verdict_reason  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_adapter_invoke_exception_text_is_redacted_before_persisting() -> None:
    """DCR-0005: same guarantee at the `adapter.invoke()` catch site in `_one_pass`."""

    class _LeakyAdapter:
        async def describe(self) -> TargetDescriptor:
            return TargetDescriptor(
                target_id="stub-target", kind="mcp", system_prompt="x", tools=[]
            )

        async def invoke(self, payload: Payload) -> AdapterResponse:
            del payload
            raise RuntimeError(_SECRET_EXC_TEXT)

        async def close(self) -> None:
            return None

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(customise=False),
        adapter=_LeakyAdapter(),  # type: ignore[arg-type]
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "error"
    assert attempt.verdict_reason is not None
    assert "sk-live-shouldnotleak123" not in attempt.verdict_reason  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_judge_exception_text_is_redacted_before_persisting() -> None:
    """DCR-0005: same guarantee at the `judge.judge()` catch site in `_one_pass`."""

    class _LeakyJudge:
        async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
            del payload, response
            raise RuntimeError(_SECRET_EXC_TEXT)

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(customise=False),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_LeakyJudge(),  # type: ignore[arg-type]
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "error"
    assert attempt.verdict_reason is not None
    assert "sk-live-shouldnotleak123" not in attempt.verdict_reason  # pragma: allowlist secret


# --- DCR-0016: logger.exception() embeds the raw, unredacted traceback -----
# (SecretRedactingFilter only touches record.getMessage(); the exc_info
# traceback logging.Formatter renders separately is never redacted by it —
# see caplog.text below, which is what a real logging.Handler would emit.)


@pytest.mark.asyncio
async def test_adapter_describe_exception_not_logged_with_raw_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DCR-0016: adapter.describe() raising must not log the raw exception text
    (via logger.exception()'s implicit traceback) -- redact before logging, or
    log only the exception type name."""
    payload = _payload_from_seed_index(0)

    class _LeakyDescribeAdapter(_AdapterStub):
        async def describe(self) -> TargetDescriptor:
            raise RuntimeError(_SECRET_EXC_TEXT)

    engine = ScanEngine(
        config=_config(),
        adapter=_LeakyDescribeAdapter(_ok_response()),  # type: ignore[arg-type]
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    with caplog.at_level("DEBUG", logger="mylonite.scan.engine"):
        await engine.run()
    assert "sk-live-shouldnotleak123" not in caplog.text  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_customiser_exception_not_logged_with_raw_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DCR-0016: same guarantee at the customiser.customise() catch site."""

    class _LeakyCustomiser:
        async def customise(self, seed: Any, target: Any) -> Payload:
            del seed, target
            raise RuntimeError(_SECRET_EXC_TEXT)

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_LeakyCustomiser(),  # type: ignore[arg-type]
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    with caplog.at_level("DEBUG", logger="mylonite.scan.engine"):
        await engine.run()
    assert "sk-live-shouldnotleak123" not in caplog.text  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_adapter_invoke_exception_not_logged_with_raw_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DCR-0016: same guarantee at the adapter.invoke() catch site in `_one_pass`."""

    class _LeakyAdapter:
        async def describe(self) -> TargetDescriptor:
            return TargetDescriptor(
                target_id="stub-target", kind="mcp", system_prompt="x", tools=[]
            )

        async def invoke(self, payload: Payload) -> AdapterResponse:
            del payload
            raise RuntimeError(_SECRET_EXC_TEXT)

        async def close(self) -> None:
            return None

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(customise=False),
        adapter=_LeakyAdapter(),  # type: ignore[arg-type]
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(Verdict(success=False, reason="x", evidence={}, mechanism="llm")),
    )
    with caplog.at_level("DEBUG", logger="mylonite.scan.engine"):
        await engine.run()
    assert "sk-live-shouldnotleak123" not in caplog.text  # pragma: allowlist secret


@pytest.mark.asyncio
async def test_judge_exception_not_logged_with_raw_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DCR-0016: same guarantee at the judge.judge() catch site in `_one_pass`."""

    class _LeakyJudge:
        async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
            del payload, response
            raise RuntimeError(_SECRET_EXC_TEXT)

    payload = _payload_from_seed_index(0)
    engine = ScanEngine(
        config=_config(customise=False),
        adapter=_AdapterStub(_ok_response()),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_LeakyJudge(),  # type: ignore[arg-type]
    )
    with caplog.at_level("DEBUG", logger="mylonite.scan.engine"):
        await engine.run()
    assert "sk-live-shouldnotleak123" not in caplog.text  # pragma: allowlist secret


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
async def test_engine_nrun_minority_success_is_not_reported_as_no_engagement() -> None:
    """A minority success must never be reclassified as "the planner never
    engaged the tool under test".

    `never_exercised_tool_under_test` and the judge's success verdict are
    INDEPENDENT mechanisms: a fuzzy-judge success is decided from the reply
    text/effect trace as a whole, not by re-checking that `tool_under_test`
    literally appears in THAT pass's `response.tool_calls`. So a genuinely
    landing pass (however minority) can still satisfy
    `never_exercised_tool_under_test` for its own response -- e.g. seed
    metadata names a slightly stale tool name relative to what the adapter's
    trace recorded. Before the fix, `all(never_exercised_tool_under_test(...)
    for p in all_passes)` did not exclude `success_passes`, so a minority
    success on a response whose `tool_calls` never happens to name
    `tool_under_test` was misreported as `skipped_planner_no_engagement` --
    "the attack was never put to the target" -- when in fact it landed once.
    """
    judge = _JudgeSequence([_yes(), _no(), _no()])
    payload = Payload(
        pattern_id="synth-w3-egress-export_report",
        channel="user-message",
        body="x",
        metadata={
            "seed_id": "synth-w3-egress-export_report",
            "weakness": "W3",
            "predicate": "x",
            "setup": "no_setup",
            "drive": "verbatim",
            # Not in the response's `tool_calls` (`read_note`, `send_email`), so
            # every pass's response fails the "tool was exercised" check --
            # independent of what the judge decided about that pass.
            "egress_tool": "export_report",
        },
    )
    # `never_exercised_tool_under_test` only evaluates `tool not in
    # response.tool_calls` when `_target_has_tool_surface` is True, which needs
    # a non-empty `tool_surface` in metadata -- `_ok_response()` has none, which
    # would make this a no-op test of the fix (the branch is never entered
    # either way). A real synthesised-seed target always stamps `tool_surface`.
    response = AdapterResponse(
        payload_pattern_id="x",
        raw_response="ok",
        tool_calls=["read_note", "send_email"],
        metadata={"tool_surface": json.dumps([{"name": "read_note"}, {"name": "send_email"}])},
    )
    engine = ScanEngine(
        config=_config(runs=3),
        adapter=_AdapterStub(response),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=judge,
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "no_finding"
    assert result.report.attempts[0].outcome != "skipped_planner_no_engagement"


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
async def test_engine_nrun_structural_skip_does_not_blow_the_shared_budget() -> None:
    """runs>1 concurrency must not spend the SCAN-WIDE LLM-call budget on passes
    made pointless by a structural skip.

    ``LiteLLMCallCounter`` is one counter shared across the whole scan, not one
    per payload. The old sequential loop stopped at the FIRST skip, so passes
    after it never ran. A naive concurrent fan-out (plain ``gather_bounded``)
    would launch all `runs` passes up front regardless — a structural skip is
    a RETURNED ``_PerPayloadOutcome``, not a raised exception, so a bare
    gather has no reason to cancel the rest — silently spending more of the
    shared budget than the old code ever did, which could tip a `runs>1` scan
    running close to ``--max-llm-calls`` into a spurious ``budget_exceeded``.

    This pins the fix (``ScanEngine._run_flakiness_passes``): once ANY pass
    resolves to a terminal skip, the passes still blocked behind the
    concurrency semaphore are cancelled BEFORE they ever call
    ``adapter.invoke()`` — so invoke() is attempted at most ``max_concurrent``
    times (the semaphore limit), never scaling up to ``runs``.
    """

    class _SlowSkippingAdapter(_AdapterStub):
        """Structural skip with a real await, so the semaphore genuinely blocks
        the remaining passes instead of everything racing through in one
        scheduler tick (which would make the invoke-count bound trivially
        true for the wrong reason)."""

        async def invoke(self, payload: Payload) -> AdapterResponse:
            self.invoke_call_count += 1
            await asyncio.sleep(0.01)
            raise AdapterInvocationSkipped(
                "planner failure: simulated",
                attempt_metadata={"variant": "vulnerable", "exception": "RuntimeError"},
            )

    adapter = _SlowSkippingAdapter(raise_skipped=True)
    engine = ScanEngine(
        config=_config(runs=5),  # max_concurrent=2 (see _config's fixed default)
        adapter=adapter,
        attack_modules=[_ModuleStub([_payload_from_seed_index(0)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(_no()),
    )
    result = await engine.run()

    assert result.report.attempts[0].outcome == "skipped_planner_failure"
    # Bounded by max_concurrent(2), not runs(5): the remaining in-flight
    # passes were cancelled before they ever reached adapter.invoke().
    assert adapter.invoke_call_count <= 2, (
        "expected the terminal skip to cancel still-pending passes before they "
        f"called adapter.invoke() (bounded by max_concurrent=2); got "
        f"{adapter.invoke_call_count} invoke() attempts out of runs=5"
    )


@pytest.mark.asyncio
async def test_engine_concurrency_bounded_across_payloads_and_flakiness_runs() -> None:
    """DCR-0005: ``max_concurrent`` must bound TOTAL in-flight ``adapter.invoke()``
    calls across BOTH cross-payload fan-out AND per-payload ``runs>1``
    flakiness fan-out -- not multiply them together.

    Before the fix, ``_run_flakiness_passes`` constructed its OWN fresh
    ``Semaphore(max_concurrent)`` instead of reusing the outer cross-payload
    semaphore ``run()`` builds, so with ``max_concurrent`` payloads
    concurrently mid-flakiness-fan-out, up to ``max_concurrent ** 2``
    concurrent ``invoke()`` calls could be in flight -- 4 here, since
    ``_config``'s fixed ``max_concurrent=2``.

    Uses 2 payloads (== max_concurrent, so cross-payload fan-out actually
    saturates) and ``runs=3`` (> max_concurrent, so per-payload flakiness
    fan-out is also exercised) with a slow adapter, so the semaphore
    genuinely has to hold work back rather than everything racing through in
    one scheduler tick.
    """

    class _ConcurrencyTrackingAdapter:
        def __init__(self, response: AdapterResponse) -> None:
            self._response = response
            self._current = 0
            self.peak_concurrent = 0

        async def describe(self) -> TargetDescriptor:
            return TargetDescriptor(
                target_id="stub-target", kind="mcp", system_prompt="x", tools=[]
            )

        async def invoke(self, payload: Payload) -> AdapterResponse:
            del payload
            self._current += 1
            self.peak_concurrent = max(self.peak_concurrent, self._current)
            try:
                await asyncio.sleep(0.05)
                return self._response
            finally:
                self._current -= 1

        async def close(self) -> None:
            return None

    adapter = _ConcurrencyTrackingAdapter(_ok_response())
    engine = ScanEngine(
        config=_config(runs=3),  # max_concurrent=2 (see _config's fixed default)
        adapter=adapter,
        attack_modules=[_ModuleStub([_payload_from_seed_index(0), _payload_from_seed_index(1)])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(_no()),
    )
    await engine.run()

    assert adapter.peak_concurrent <= 2, (
        "expected peak concurrent adapter.invoke() calls bounded by "
        f"max_concurrent=2 (2 payloads x runs=3 flakiness fan-out each); got "
        f"{adapter.peak_concurrent} in flight at once"
    )


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


# --- DCR-0002: max_concurrent must be >= 1 -----------------------------------


@pytest.mark.parametrize("bad_value", [0, -1])
def test_scan_config_rejects_non_positive_max_concurrent(bad_value: int) -> None:
    """asyncio.Semaphore(0) would deadlock every attempt forever (not error);
    asyncio.Semaphore(-1) raises from its OWN constructor with a much less
    actionable message. Neither is a config a caller could have MEANT —
    reject both at ScanConfig construction instead."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        ScanConfig(
            target_id="reference:vulnerable",
            provider="anthropic",
            model="stub-model",
            max_concurrent=bad_value,
            output_dir=Path(".mylonite/scans"),
        )


# --- DCR-0012: provider_failure_threshold must be >= 1 ------------------------


@pytest.mark.parametrize("bad_value", [0, -1])
def test_scan_config_rejects_non_positive_provider_failure_threshold(bad_value: int) -> None:
    """provider_failure_threshold had no lower-bound validation, unlike
    max_concurrent (Field(ge=1)) -- a value of 0 aborts a scan after the very
    FIRST attempt regardless of outcome (`consecutive_failures >= threshold`
    is true even at 0 consecutive failures). Not a config a caller could have
    MEANT -- reject it at ScanConfig construction, mirroring max_concurrent."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        ScanConfig(
            target_id="reference:vulnerable",
            provider="anthropic",
            model="stub-model",
            provider_failure_threshold=bad_value,
            output_dir=Path(".mylonite/scans"),
        )


@pytest.mark.asyncio
async def test_engine_chain_that_never_reaches_the_sink_is_not_clean() -> None:
    """A chain probe whose FIRST step fails is not evidence of resistance.

    Measured: with the source tool returning 503, the planner calls it, reports
    the error and stops. The trace is NOT empty, so the zero-call check does not
    fire, and the attempt fell straight through to ``no_finding`` — a clean pass
    on an attack that never reached the tool it targets. This is the same
    false-clean class as the zero-call case, one level down, and it only became
    reachable once probes became chains.
    """
    base = _payload_from_seed_index(0)
    # A synthesised seed sets customise=False, so the customiser never runs and
    # the resolved-tool metadata reaches the engine intact -- which is exactly
    # the path this branch serves.
    payload = base.model_copy(
        update={
            "metadata": {
                **base.metadata,
                "needs_customisation": "false",
                "egress_tool": "export_report",
            }
        }
    )
    stalled = AdapterResponse(
        payload_pattern_id="x",
        raw_response="The analytics store is unavailable (503), so I stopped.",
        tool_calls=["read_analytics"],
        metadata={"tool_surface": json.dumps(["read_analytics", "export_report"])},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(stalled),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(
            Verdict(success=False, reason="nothing sent", evidence={}, mechanism="llm")
        ),
    )
    result = await engine.run()
    attempt = result.report.attempts[0]
    assert attempt.outcome == "skipped_planner_no_engagement"
    assert "export_report" in (attempt.verdict_reason or ""), (
        "the reason must name the tool that was never reached, or the operator "
        "cannot tell this from a target that simply declined"
    )
    assert result.report.findings_count == 0


@pytest.mark.asyncio
async def test_engine_sink_reached_still_produces_a_real_verdict() -> None:
    """The narrowing must not swallow a genuine negative.

    The sink WAS invoked and the attack still did not land — that is real
    evidence of resistance and must stay ``no_finding``.
    """
    base = _payload_from_seed_index(0)
    payload = base.model_copy(
        update={
            "metadata": {
                **base.metadata,
                "needs_customisation": "false",
                "egress_tool": "export_report",
            }
        }
    )
    exercised = AdapterResponse(
        payload_pattern_id="x",
        raw_response="Exported to the approved endpoint.",
        tool_calls=["read_analytics", "export_report"],
        metadata={"tool_surface": json.dumps(["read_analytics", "export_report"])},
    )
    engine = ScanEngine(
        config=_config(),
        adapter=_AdapterStub(exercised),
        attack_modules=[_ModuleStub([payload])],
        customiser=_CustomiserStub(),
        judge=_JudgeStub(
            Verdict(success=False, reason="allowlist held", evidence={}, mechanism="llm")
        ),
    )
    result = await engine.run()
    assert result.report.attempts[0].outcome == "no_finding"
