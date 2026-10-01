"""A weakness class no attack module emitted a payload for reads NOT TESTED (#221).

A ``transport: rest`` target that declares W3 or W4 got the bundled W3/W4 seeds
scheduled (a REST target reports no tool surface, so nothing filtered them), but
the excessive-agency module emits nothing for a non-MCP target. W3/W4 then had
zero attempts, and when W2 resisted the scan read clean. Coverage now comes from
the payloads each class actually emitted.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.exit_codes import EXIT_SUCCESS
from mylonite.plugins._http.http_adapter import HTTPAgentAdapter
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
from mylonite.reason_codes import NT_CODE_BY_BUCKET, NT_NO_ATTACK_EMITTED
from mylonite.scan._types import Verdict
from mylonite.scan.artefacts import render_summary
from mylonite.scan.class_verdict import (
    STATUS_NOT_TESTED,
    STATUS_RESISTED,
    class_verdicts,
)
from mylonite.scan.coverage import NO_ATTACK_EMITTED_KEY, ScanOutcome
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine, ScanResult


def _register_rest(weakness_classes: tuple[str, ...]) -> None:
    request = target_registry.RequestSpec(
        url="https://agent.example/chat",
        body='{"prompt": "{prompt}"}',
        response_path="reply",
    )
    spec = target_registry.TargetSpec(
        family="myagent",
        command="",
        args_template=(),
        scope_validator=lambda _s: None,
        default_system_prompt="You are a support agent.",
        requires_scope=False,
        weakness_classes=weakness_classes,
        transport="rest",
        request=request,
    )
    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)


def teardown_function() -> None:
    target_registry.clear_runtime_targets()


class _JudgeNo:
    """Every attempt that runs is decided as resisted."""

    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        return Verdict(success=False, reason="the agent declined", evidence={}, mechanism="llm")


async def _completion(**_: Any) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"body": "refined"}'))]
    )


def _rest_scan(weakness_classes: tuple[str, ...], **config: Any) -> ScanResult:
    _register_rest(weakness_classes)

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json={"reply": "I can't help with that."})

    adapter = HTTPAgentAdapter(family="myagent")
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cfg = ScanConfig(
        target_id="rest:myagent",
        provider="anthropic",
        model="stub-model",
        max_llm_calls=50,
        max_concurrent=2,
        output_dir=Path(".mylonite/scans"),
        **config,
    )
    engine = ScanEngine(
        config=cfg,
        adapter=adapter,
        attack_modules=[PromptInjectionAttackModule(), ExcessiveAgencyAttackModule()],
        customiser=PayloadCustomiser(model="stub", completion_fn=_completion),
        judge=_JudgeNo(),
    )
    try:
        return asyncio.run(engine.run())
    finally:
        asyncio.run(adapter.close())


def _rows(result: ScanResult) -> dict[str, Any]:
    return {v.weakness: v for v in class_verdicts(result.report)}


def test_rest_target_declaring_w2_and_w4_reads_w4_not_tested_not_clean() -> None:
    result = _rest_scan(("W2", "W4"))

    rows = _rows(result)
    # W2 ran and resisted; it is a real negative.
    assert rows["W2"].status == STATUS_RESISTED
    # W4 had seeds scheduled but no module emitted an attack for a REST target.
    assert rows["W4"].status == STATUS_NOT_TESTED
    assert rows["W4"].codes == (NT_NO_ATTACK_EMITTED,)

    lost = [a for a in result.report.attempts if a.judge_evidence.get(NO_ATTACK_EMITTED_KEY)]
    assert [a.judge_evidence["weakness"] for a in lost] == ["W4"]
    assert all(a.outcome == "not_applicable" for a in lost)
    assert result.report.aborted is None

    outcome = ScanOutcome.from_report(result.report)
    assert not outcome.trustworthy_clean
    assert outcome.exit_code != EXIT_SUCCESS

    summary = " ".join(render_summary(result, ascii_safe=True).split())
    assert NT_NO_ATTACK_EMITTED in summary
    assert "W4" in summary


def test_rest_target_declaring_only_w3_and_w4_reads_not_tested_not_an_empty_abort() -> None:
    result = _rest_scan(("W3", "W4"))

    rows = _rows(result)
    assert {w: r.status for w, r in rows.items()} == {
        "W3": STATUS_NOT_TESTED,
        "W4": STATUS_NOT_TESTED,
    }
    # Not "no seeds applied": the cause is named per class instead.
    assert result.report.aborted is None
    assert ScanOutcome.from_report(result.report).exit_code != EXIT_SUCCESS


def test_dry_run_records_no_unemitted_class_attempt() -> None:
    result = _rest_scan(("W2", "W4"), dry_run=True)
    assert not [a for a in result.report.attempts if a.judge_evidence.get(NO_ATTACK_EMITTED_KEY)]


def test_the_bucket_maps_to_the_new_code() -> None:
    assert NT_CODE_BY_BUCKET["no_attack_emitted"] == NT_NO_ATTACK_EMITTED


@pytest.mark.parametrize("target_id", ["reference:vulnerable"])
def test_mcp_target_whose_modules_emit_every_class_gets_no_extra_attempt(target_id: str) -> None:
    """On an MCP target the shipped modules emit every scheduled class, so the
    rule adds nothing (dry run would skip it, so check the helper directly)."""
    from mylonite.contracts import TargetDescriptor
    from mylonite.scan.engine import _unemitted_class_attempts
    from mylonite.scan.seeds import seeds_for_descriptor

    descriptor = TargetDescriptor(target_id=target_id, kind="mcp")
    payloads = [
        *PromptInjectionAttackModule().generate_payloads(descriptor),
        *ExcessiveAgencyAttackModule().generate_payloads(descriptor),
    ]
    assert {s.weakness for s in seeds_for_descriptor(descriptor)} == {"W1", "W2", "W3", "W4"}
    assert _unemitted_class_attempts(descriptor, payloads, already_lost=set()) == []
