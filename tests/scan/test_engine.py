"""ScanEngine integration-ish tests with mocked adapter, customiser, judge."""

from __future__ import annotations

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
from mylonite.scan._types import AdapterInvocationSkipped, Verdict
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
        self, response: AdapterResponse | None = None, *, raise_skipped: bool = False
    ) -> None:
        self._response = response
        self._raise_skipped = raise_skipped
        self.invoked: list[Payload] = []

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:
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
    )


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
