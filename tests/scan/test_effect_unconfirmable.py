"""A W3/W4 class on a custom target with no effect_probe in effect reads NOT
TESTED, never resisted.

With no probe, nothing reads the target's own state, so an effect can never be
confirmed or ruled out, whether or not the server has a readback tool. The
class reads NOT TESTED under its own code unless an attempt in it fired, in
which case the finding stands. The per-attempt verdict rule is unchanged: this
is one extra NOT TESTED attempt per class.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.contracts import ToolSpec
from mylonite.contracts._types import AdapterResponse, Payload, TargetDescriptor
from mylonite.reason_codes import NT_CODE_BY_BUCKET, NT_EFFECT_UNCONFIRMABLE, REGISTRY
from mylonite.scan._types import Verdict
from mylonite.scan.class_verdict import STATUS_FINDING, STATUS_NOT_TESTED, class_verdicts
from mylonite.scan.coverage import EFFECT_UNCONFIRMABLE_KEY, ScanOutcome
from mylonite.scan.effect_verdict import classify_trace, is_read_tool
from mylonite.scan.engine import ScanConfig, ScanEngine, ScanResult
from mylonite.scan.seeds import SEED_CATALOGUE
from mylonite.scan.tool_roles import effect_readback

_SEND = ToolSpec(
    name="send_email",
    description="Send an email to a recipient.",
    json_schema={
        "type": "object",
        "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "body"],
    },
)
_OUTBOX = ToolSpec(
    name="list_outbox",
    description="List the messages that were sent.",
    json_schema={"type": "object", "properties": {}},
)


class _Module:
    def __init__(self, payloads: list[Payload]) -> None:
        self._payloads = payloads

    def attack_metadata(self) -> object:
        from mylonite.contracts._types import AttackPattern, ComplianceTags

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


class _Adapter:
    def __init__(self, tools: list[ToolSpec], probe: bool | None) -> None:
        self._tools = tools
        if probe is not None:
            self.declares_effect_probe = probe

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(
            target_id="mcp:acme",
            kind="mcp",
            system_prompt="x",
            tools=self._tools,
            weakness_classes=["W4"],
        )

    async def invoke(self, payload: Payload) -> AdapterResponse:
        return AdapterResponse(payload_pattern_id=payload.pattern_id, raw_response="ok")

    async def close(self) -> None:
        return None


class _Customiser:
    async def customise(self, seed: object, target: object) -> Payload:
        raise AssertionError("not used")


class _Judge:
    def __init__(self, success: bool) -> None:
        self._success = success

    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        return Verdict(success=self._success, reason="stub", evidence={}, mechanism="llm")


def _w4_payload() -> Payload:
    seed = next(s for s in SEED_CATALOGUE if s.weakness == "W4" and s.setup == "no_setup")
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
        },
    )


async def _scan(
    tools: list[ToolSpec], *, probe: bool | None, success: bool = False, dry_run: bool = False
) -> ScanResult:
    engine = ScanEngine(
        config=ScanConfig(
            target_id="mcp:acme",
            provider="anthropic",
            model="stub-model",
            max_llm_calls=50,
            max_concurrent=2,
            output_dir=Path(".mylonite/scans"),
            dry_run=dry_run,
        ),
        adapter=_Adapter(tools, probe),
        attack_modules=[_Module([_w4_payload()])],
        customiser=_Customiser(),
        judge=_Judge(success),
    )
    return await engine.run()


def _marked(result: ScanResult) -> list[object]:
    return [a for a in result.report.attempts if a.judge_evidence.get(EFFECT_UNCONFIRMABLE_KEY)]


def test_the_new_code_is_registered_and_bucketed() -> None:
    assert NT_EFFECT_UNCONFIRMABLE in REGISTRY
    assert NT_CODE_BY_BUCKET["effect_unconfirmable"] == NT_EFFECT_UNCONFIRMABLE


def test_effect_readback_is_the_scaffold_verify_candidate() -> None:
    assert effect_readback([_SEND]) is None
    choice = effect_readback([_SEND, _OUTBOX])
    assert choice is not None and choice.tool == "list_outbox" and choice.tied


def test_a_consequential_verify_tool_is_never_a_read() -> None:
    """A tool named both consequential and the verify tool must count as a
    dispatch, so a misconfigured probe cannot hide the agent's own call."""
    assert not is_read_tool(
        "clear_log", consequential_tool_names=("clear_log",), verify_tool="clear_log"
    )
    outcome = classify_trace(
        [{"tool": "clear_log"}],
        consequential_tool_names=("clear_log",),
        verify_tool="clear_log",
    )
    assert outcome == "dispatched-ok"


@pytest.mark.asyncio
async def test_a_readback_on_the_server_does_not_stand_in_for_a_probe() -> None:
    """The rule keys on what the run used: a readback tool the run never
    declared confirms nothing, and the reason names it as the probe to add."""
    result = await _scan([_SEND, _OUTBOX], probe=False)
    marked = _marked(result)
    assert len(marked) == 1
    assert "list_outbox" in marked[0].verdict_reason
    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W4"].status == STATUS_NOT_TESTED


@pytest.mark.asyncio
async def test_no_readback_and_no_probe_reads_not_tested_never_resisted() -> None:
    result = await _scan([_SEND], probe=False)

    marked = _marked(result)
    assert len(marked) == 1
    assert marked[0].outcome == "not_applicable"
    assert marked[0].judge_evidence["weakness"] == "W4"
    assert NT_EFFECT_UNCONFIRMABLE in marked[0].verdict_reason

    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W4"].status == STATUS_NOT_TESTED
    assert NT_EFFECT_UNCONFIRMABLE in rows["W4"].codes
    outcome = ScanOutcome.from_report(result.report)
    assert not outcome.trustworthy_clean
    assert outcome.exit_code == 2


@pytest.mark.asyncio
async def test_a_finding_in_the_class_still_wins() -> None:
    result = await _scan([_SEND], probe=False, success=True)
    rows = {v.weakness: v for v in class_verdicts(result.report)}
    assert rows["W4"].status == STATUS_FINDING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tools", "probe"),
    [
        ([_SEND], True),  # an effect_probe is declared
        ([_SEND, _OUTBOX], True),  # a probe is declared and a readback exists
        ([_SEND], None),  # the adapter does not say (reference, REST, stubs)
    ],
    ids=["probe-declared", "probe-and-readback", "adapter-silent"],
)
async def test_rule_does_not_apply(tools: list[ToolSpec], probe: bool | None) -> None:
    assert _marked(await _scan(tools, probe=probe)) == []


@pytest.mark.asyncio
async def test_dry_run_records_nothing() -> None:
    assert _marked(await _scan([_SEND], probe=False, dry_run=True)) == []
