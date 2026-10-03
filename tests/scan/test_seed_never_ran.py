"""A seed that never ran is a NOT TESTED row, never a gap that reads resisted.

Two ways a scheduled seed used to vanish from the result:

* the per-class synthesis ceiling dropped the tool before any seed existed
  for it, with only a log warning;
* the scan stopped early (call budget, provider, wall clock) before the seed
  finished, so it had no attempt at all.

Either way the class's remaining attempts could all resist and the class read
RESISTED with tools or seeds never exercised.
"""

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
    ToolSpec,
)
from mylonite.reason_codes import (
    NT_CODE_BY_BUCKET,
    NT_SEED_CUT_OFF,
    NT_SYNTHESIS_CAPPED,
    REGISTRY,
)
from mylonite.scan import coverage
from mylonite.scan._llm import BudgetExceededError, active_counter
from mylonite.scan._types import Verdict
from mylonite.scan.artefacts import OUTCOME_MARKS, render_summary, row_mark
from mylonite.scan.class_verdict import (
    STATUS_NOT_TESTED,
    STATUS_RESISTED,
    class_verdicts,
)
from mylonite.scan.coverage import SEED_CUT_OFF_KEY, SYNTHESIS_CAPPED_KEY, ScanOutcome
from mylonite.scan.engine import ScanConfig, ScanEngine, ScanResult
from mylonite.scan.seed_synth import _SYNTH_CAP_CEILING


class _Module:
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


class _Customiser:
    async def customise(self, seed: Any, target: Any) -> Payload:
        raise AssertionError("customise=False in these tests")


class _JudgeNo:
    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        return Verdict(success=False, reason="resisted", evidence={}, mechanism="llm")


def _tools(n: int) -> list[ToolSpec]:
    """``n`` consequential tools, so W4 synthesis has ``n`` candidates."""
    return [
        ToolSpec(
            name=f"delete_record_{i}",
            description=f"Delete record {i}.",
            json_schema={"type": "object", "properties": {"record_id": {"type": "string"}}},
        )
        for i in range(n)
    ]


def _payload(pattern_id: str, weakness: str) -> Payload:
    return Payload(
        pattern_id=pattern_id,
        channel="user-message",
        body="x",
        metadata={
            "seed_id": pattern_id,
            "weakness": weakness,
            "predicate": "x",
            "setup": "no_setup",
            "drive": "verbatim",
        },
    )


def _response(tools: list[str]) -> AdapterResponse:
    return AdapterResponse(
        payload_pattern_id="x",
        raw_response="ok",
        tool_calls=tools,
        metadata={},
    )


def _config(**overrides: Any) -> ScanConfig:
    defaults: dict[str, Any] = {
        "target_id": "mcp:custom-app",
        "provider": "anthropic",
        "model": "stub-model",
        "max_llm_calls": 50,
        "max_concurrent": 4,
        "output_dir": Path(".mylonite/scans"),
        "customise": False,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


class _Adapter:
    def __init__(self, descriptor: TargetDescriptor, *, boom: str = "", slow: str = "") -> None:
        self._descriptor = descriptor
        self._boom = boom
        self._slow = slow

    async def describe(self) -> TargetDescriptor:
        return self._descriptor

    async def invoke(self, payload: Payload) -> AdapterResponse:
        if payload.pattern_id == self._boom:
            await asyncio.sleep(0.02)
            counter = active_counter()
            if counter is not None:
                counter.record("adapter")
            raise BudgetExceededError("test budget exhausted")
        if payload.pattern_id == self._slow:
            await asyncio.sleep(5)
        return _response(["delete_record_0"])

    async def close(self) -> None:
        return None


def _capped_scan(**config: Any) -> ScanResult:
    descriptor = TargetDescriptor(
        target_id="mcp:custom-app",
        kind="mcp",
        system_prompt="x",
        tools=_tools(12),
        weakness_classes=["W4"],
    )
    engine = ScanEngine(
        config=_config(**config),
        adapter=_Adapter(descriptor),  # type: ignore[arg-type]
        attack_modules=[_Module([_payload("synth-w4-unconfirmed-delete_record_0", "W4")])],
        customiser=_Customiser(),  # type: ignore[arg-type]
        judge=_JudgeNo(),  # type: ignore[arg-type]
    )
    return asyncio.run(engine.run())


def test_a_tool_the_synthesis_ceiling_dropped_is_a_not_tested_row() -> None:
    result = _capped_scan()

    capped = [a for a in result.report.attempts if a.judge_evidence.get(SYNTHESIS_CAPPED_KEY)]
    assert len(capped) == 12 - _SYNTH_CAP_CEILING
    assert {a.judge_evidence["weakness"] for a in capped} == {"W4"}
    assert {a.judge_evidence[SYNTHESIS_CAPPED_KEY] for a in capped} == {
        f"delete_record_{i}" for i in range(_SYNTH_CAP_CEILING, 12)
    }
    assert all(coverage.reason_code_for_attempt(a) == NT_SYNTHESIS_CAPPED for a in capped)
    assert all(NT_SYNTHESIS_CAPPED in (a.verdict_reason or "") for a in capped)


def test_a_class_with_unprobed_tools_does_not_read_resisted() -> None:
    """The one W4 attempt that ran resisted; eleven tools never got a probe."""
    result = _capped_scan()

    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W4"].status == STATUS_NOT_TESTED
    assert NT_SYNTHESIS_CAPPED in rows["W4"].codes
    outcome = ScanOutcome.from_report(result.report)
    assert not outcome.trustworthy_clean
    summary = " ".join(render_summary(result, ascii_safe=True).split())
    assert NT_SYNTHESIS_CAPPED in summary


def test_a_single_seed_re_drive_adds_no_capped_rows() -> None:
    """A pattern-id filter re-drives one seed on purpose; it is not a coverage claim."""
    result = _capped_scan(pattern_id_filter="synth-w4-unconfirmed-delete_record_0")
    assert not any(a.judge_evidence.get(SYNTHESIS_CAPPED_KEY) for a in result.report.attempts)


def _budget_scan(payloads: list[Payload], *, boom: str, slow: str) -> ScanResult:
    descriptor = TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])
    engine = ScanEngine(
        config=_config(max_llm_calls=1, target_id="stub-target"),
        adapter=_Adapter(descriptor, boom=boom, slow=slow),  # type: ignore[arg-type]
        attack_modules=[_Module(payloads)],
        customiser=_Customiser(),  # type: ignore[arg-type]
        judge=_JudgeNo(),  # type: ignore[arg-type]
    )
    return asyncio.run(engine.run())


def test_seeds_the_budget_cut_off_are_not_tested_rows() -> None:
    ran, boom, slow = (
        "synth-w2-direct-content-a",
        "synth-w4-unconfirmed-b",
        "synth-w4-unconfirmed-c",
    )
    result = _budget_scan(
        [_payload(ran, "W2"), _payload(boom, "W4"), _payload(slow, "W4")], boom=boom, slow=slow
    )

    assert result.report.aborted == "budget_exceeded"
    cut = {
        a.pattern_id: a for a in result.report.attempts if a.judge_evidence.get(SEED_CUT_OFF_KEY)
    }
    assert set(cut) == {boom, slow}
    for attempt in cut.values():
        assert attempt.judge_evidence[SEED_CUT_OFF_KEY] == "budget_exceeded"
        assert attempt.judge_evidence["weakness"] == "W4"
        assert coverage.reason_code_for_attempt(attempt) == NT_SEED_CUT_OFF
    # The seed that finished keeps its real outcome and gets no extra row.
    assert [a.outcome for a in result.report.attempts if a.pattern_id == ran] == ["no_finding"]


def test_a_class_whose_only_seeds_were_cut_off_reads_not_tested() -> None:
    """Before, W4 had no attempts at all and dropped out of the class summary."""
    ran, boom, slow = (
        "synth-w2-direct-content-a",
        "synth-w4-unconfirmed-b",
        "synth-w4-unconfirmed-c",
    )
    result = _budget_scan(
        [_payload(ran, "W2"), _payload(boom, "W4"), _payload(slow, "W4")], boom=boom, slow=slow
    )

    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W2"].status == STATUS_RESISTED
    assert rows["W4"].status == STATUS_NOT_TESTED
    assert rows["W4"].codes == (NT_SEED_CUT_OFF,)


def test_a_class_with_one_resisted_and_one_cut_off_seed_does_not_read_resisted() -> None:
    ran, boom, slow = (
        "synth-w2-direct-content-a",
        "synth-w2-direct-content-b",
        "synth-w2-direct-content-c",
    )
    result = _budget_scan(
        [_payload(ran, "W2"), _payload(boom, "W2"), _payload(slow, "W2")], boom=boom, slow=slow
    )

    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W2"].status == STATUS_NOT_TESTED
    assert rows["W2"].resisted == 1
    assert rows["W2"].not_tested == 2


def test_never_ran_rows_render_as_not_tested_not_as_a_missing_capability() -> None:
    result = _budget_scan(
        [_payload("seed-boom", "W4"), _payload("seed-slow", "W4")],
        boom="seed-boom",
        slow="seed-slow",
    )
    cut = next(a for a in result.report.attempts if a.judge_evidence.get(SEED_CUT_OFF_KEY))
    assert row_mark(cut, OUTCOME_MARKS) == "⚠ NOT TESTED"


@pytest.mark.parametrize("code", [NT_SYNTHESIS_CAPPED, NT_SEED_CUT_OFF])
def test_the_new_codes_are_registered_not_tested_codes(code: str) -> None:
    assert REGISTRY[code].category == "not-tested"
    assert code in NT_CODE_BY_BUCKET.values()
