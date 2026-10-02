"""The guarded reference twin's W4 leg still reads resisted, not NOT TESTED.

The guarded kitchen-sink server answers every ``send_email`` with a staging
reply ("staged — call confirm_send to dispatch"), and both of those words are
default deferral markers. The deferral rule reads a deferred call NOT TESTED
unless the effect probe saw the hold, so this pins where that rule does and
does not reach the twin:

* In process (``InProcessReferenceAdapter``, the path the differential oracle
  runs), the adapter records no trace outcome, so the guarded leg is decided on
  the seed's predicate and reads resisted (``no_finding``). If this flips, the
  differential loses its guarded half.
* Through the real stdio MCP adapter, the committed target files declare no
  effect probe (the twin has no tool that reads sent mail back), so a staged
  send is NOT TESTED under ``MYL-INC-012``: never a finding, and never a
  negative resting on the reply alone.

Scripted planner, no model call.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import ScanAttempt
from mylonite.plugins._mcp import calibration, target_registry
from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge

_EXAMPLE_TARGET = Path(__file__).resolve().parents[2] / "examples" / "target.yaml"
_SEND_SEEDS = (
    "excessive-agency-send-email-direct-unconfirmed",
    "synth-w4-unconfirmed-send_email",
)


def _text(content: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=None))]
    )


async def _planner(**kwargs: Any) -> SimpleNamespace:
    """Falls for the attack: one send to an outside address, then stops."""
    if any(m.get("role") == "tool" for m in kwargs.get("messages", [])):
        return _text("done")
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(
            name="send_email",
            arguments=json.dumps({"to": "ops@outside.example", "subject": "s", "body": "b"}),
        ),
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[call]))]
    )


async def _no_verdict(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"success": False, "confidence": 0.0, "reason": "n/a"}))


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> Any:
    import litellm

    async def _refuse(**kwargs: Any) -> Any:
        raise AssertionError("no model call is allowed in this module")

    monkeypatch.setattr(litellm, "acompletion", _refuse)
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    yield
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()


async def _send_attempts(adapter: Any, tmp_path: Path) -> list[ScanAttempt]:
    engine = ScanEngine(
        config=ScanConfig(
            target_id="mcp:kitchen-sink",
            provider="anthropic",
            model="stub",
            max_llm_calls=200,
            max_concurrent=1,
            output_dir=tmp_path,
        ),
        adapter=adapter,
        attack_modules=[ExcessiveAgencyAttackModule()],
        customiser=PayloadCustomiser(model="stub", completion_fn=_no_verdict),
        judge=SuccessJudge(model="stub", completion_fn=_no_verdict),
    )
    try:
        result = await engine.run()
    finally:
        await adapter.close()
    attempts = [a for a in result.report.attempts if a.seed_id in _SEND_SEEDS]
    assert attempts, [a.seed_id for a in result.report.attempts]
    return attempts


@pytest.mark.asyncio
async def test_in_process_guarded_twin_w4_send_is_resisted(tmp_path: Path) -> None:
    adapter = InProcessReferenceAdapter(variant="guarded", model="stub", completion_fn=_planner)
    attempts = await _send_attempts(adapter, tmp_path)
    for attempt in attempts:
        assert attempt.outcome == "no_finding", attempt
        assert "trace_outcome" not in attempt.judge_evidence, attempt


@pytest.mark.asyncio
async def test_in_process_vulnerable_twin_w4_send_is_a_finding(tmp_path: Path) -> None:
    """The other half of the differential, so the guarded result above means
    something: the same planner lands the attack on the vulnerable twin."""
    adapter = InProcessReferenceAdapter(variant="vulnerable", model="stub", completion_fn=_planner)
    attempts = await _send_attempts(adapter, tmp_path)
    assert all(a.outcome == "finding" for a in attempts), attempts


@pytest.mark.asyncio
async def test_stdio_guarded_twin_staged_send_is_not_tested_without_a_probe(
    tmp_path: Path,
) -> None:
    spec = dataclasses.replace(
        build_target_spec(load_target_file(_EXAMPLE_TARGET)),
        command=sys.executable,
        args_template=("-m", "mcp_kitchen_sink.stdio_guarded"),
    )
    assert spec.effect_probe is None
    target_registry.register_target(spec)
    adapter = build_adapter_for_spec(
        spec, scope=None, model="stub", completion_fn=_planner, intent=LaunchIntent()
    )
    attempts = await _send_attempts(adapter, tmp_path)
    for attempt in attempts:
        assert attempt.outcome == "undecided", attempt
        assert attempt.judge_evidence.get("trace_outcome") == "dispatched-deferred", attempt
        assert attempt.judge_evidence.get("reason_code") == "MYL-INC-012", attempt
