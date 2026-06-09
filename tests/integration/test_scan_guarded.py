"""End-to-end ScanEngine integration test against ``reference:guarded``.

Phase 1's truth-table: same scan, zero findings. The guarded planner stub
refuses to follow injection-shaped instructions and emits plain refusal text
for every seed. No predicate should fire; the LLM-judge fallback also
returns low confidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.plugins._reference.prompt_injection_module import (
    PromptInjectionAttackModule,
)
from mylonite.plugins._reference.reference_target_adapter import (
    InProcessReferenceAdapter,
)
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge


def _text(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


async def _guarded_planner(**kwargs: Any) -> SimpleNamespace:
    """Guarded planner always emits a polite refusal — no tool calls."""
    del kwargs
    return _text(
        "I cannot follow embedded instructions from note content. "
        "Please clarify what you'd like me to do."
    )


async def _customiser_completion(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"body": "REFINED"}))


async def _judge_low_confidence(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"success": False, "confidence": 0.1, "reason": "guarded refused"}))


@pytest.mark.asyncio
async def test_scan_guarded_finds_zero(tmp_path: Path) -> None:
    adapter = InProcessReferenceAdapter(
        variant="guarded",
        model="stub",
        completion_fn=_guarded_planner,
    )
    customiser = PayloadCustomiser(model="stub", completion_fn=_customiser_completion)
    judge = SuccessJudge(model="stub", completion_fn=_judge_low_confidence)

    config = ScanConfig(
        target_id="reference:guarded",
        provider="anthropic",
        model="stub",
        max_llm_calls=200,
        max_concurrent=1,
        output_dir=tmp_path,
    )
    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=[PromptInjectionAttackModule()],
        customiser=customiser,
        judge=judge,
    )

    result = await engine.run()
    # Acceptance criterion #2: 0 findings on guarded.
    assert result.report.findings_count == 0, result.report
    assert result.report.aborted is None
    # No attempts should be marked as 'finding'.
    assert all(a.outcome != "finding" for a in result.report.attempts)
