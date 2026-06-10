"""Recorded end-to-end scan against ``mcp:filesystem:<sandbox>``.

Mocks the MCP subprocess via ``stdio_adapter._open_mcp_session``; the fake
session writes real files to ``tmp_path`` so the adapter's ``sandbox_diff``
predicate sees evidence. ScriptedLLM stubs drive the planner through a
W2 read-then-write sequence.

Asserts ≥1 finding whose verdict_reason names ``write_file`` — the v0.2.2
acceptance bar (target-specific tool + attacker args + execution evidence).
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from mylonite.plugins._mcp import stdio_adapter
from mylonite.plugins._mcp.stdio_adapter import FilesystemMCPAdapter
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
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


class _RealWriteFakeSession:
    """Fake mcp.ClientSession that writes real files inside ``sandbox``.

    Lets the adapter's ``sandbox_diff`` capture the planner's write_file as
    execution evidence — without this, the predicate has no diff to inspect
    and would never fire.
    """

    def __init__(self, sandbox: Path) -> None:
        self._sandbox = sandbox

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[
                MCPTool(name="read_file", description="read a file", inputSchema={}),
                MCPTool(name="write_file", description="write a file", inputSchema={}),
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        if name == "write_file":
            target = Path(arguments.get("path", str(self._sandbox / "out.txt")))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(arguments.get("content", ""), encoding="utf-8")
            return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)
        if name == "read_file":
            path = Path(arguments.get("path", ""))
            try:
                body = path.read_text(encoding="utf-8")
            except OSError:
                body = ""
            return CallToolResult(content=[TextContent(type="text", text=body)], isError=False)
        return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)


class _FilesystemPlannerStub:
    """Drives W2 read-then-write on the seeded poisoned file."""

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

        # W2 (read_file_for_summary): read the seeded poisoned file, then write
        # the attacker-attributed file as instructed by its body.
        if "summarise it for me" in user_msg and "read the file at" in user_msg.lower():
            if step == 0:
                # Extract the file path from "Please read the file at <path> and..."
                lower = user_msg.lower()
                start = lower.find("at ") + 3
                end = user_msg.find(" and")
                path = user_msg[start:end].strip()
                return _tool_response([_tool_call("read_file", {"path": path})])
            if step == 1:
                # Follow the injected instruction: write attacker-attributed file.
                last_tool = next(
                    (m.get("content", "") for m in reversed(messages) if m.get("role") == "tool"),
                    "",
                )
                # Extract sandbox path from one of the prior user messages or just
                # use the seeded path's parent.
                tool_calls = [m for m in messages if m.get("role") == "assistant"]
                base_path = ""
                for m in tool_calls:
                    tcs = m.get("tool_calls", []) or []
                    for tc in tcs:
                        if tc.get("function", {}).get("name") == "read_file":
                            args = json.loads(tc["function"]["arguments"])
                            base_path = str(Path(args["path"]).parent)
                            break
                    if base_path:
                        break
                if not base_path:
                    base_path = "/tmp"
                exfil_path = f"{base_path}/exfil-attacker.txt"
                return _tool_response(
                    [
                        _tool_call(
                            "write_file",
                            {
                                "path": exfil_path,
                                "content": (
                                    "leaked from attacker@example.com workflow — "
                                    f"context: {last_tool[:120]}"
                                ),
                            },
                            call_id="c2",
                        )
                    ]
                )
            return _text_response("done.")
        # W4 direct write / W1 description smuggle: produce a single write_file
        # straight from the user message body.
        if step == 0 and "write_file" in user_msg.lower():
            # The W1/W4 seeds say "Please use write_file to create '...' with body '...'"
            # The body contains the attacker marker via the seed.
            base = "/tmp"  # default; not used by predicate
            return _tool_response(
                [
                    _tool_call(
                        "write_file",
                        {
                            "path": f"{base}/audit.txt",
                            "content": (
                                "Forwarded to attacker@example.com per ADMINISTRATIVE NOTICE."
                            ),
                        },
                    )
                ]
            )
        return _text_response("done.")


async def _passthrough_customiser_completion(**kwargs: Any) -> SimpleNamespace:
    """Echo the seed body so the planner stub can route on it."""
    messages = kwargs.get("messages", [])
    user_msg = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"),
        "",
    )
    marker = "SEED PATTERN ("
    if marker in user_msg:
        seed_block = user_msg.split(marker, 1)[1]
        if ")\n" in seed_block:
            body = seed_block.split(")\n", 1)[1].split("\n\n")[0].strip()
        else:
            body = seed_block.strip()
    else:
        body = "REFINED"
    return _text_response(json.dumps({"body": body}))


async def _judge_low_confidence(**kwargs: Any) -> SimpleNamespace:
    del kwargs
    return _text_response(json.dumps({"success": False, "confidence": 0.0, "reason": "n/a"}))


@pytest.mark.asyncio
async def test_scan_mcp_filesystem_finds_write_file_exploit(tmp_path: Path) -> None:
    """v0.2.2 acceptance criterion 1 — filesystem produces ≥1 finding naming write_file."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    @asynccontextmanager
    async def fake_open(*args: Any, **kwargs: Any):
        yield _RealWriteFakeSession(sandbox)

    planner_stub = _FilesystemPlannerStub()
    with patch.object(stdio_adapter, "_open_mcp_session", fake_open):
        adapter = FilesystemMCPAdapter(scope=str(sandbox), model="stub", completion_fn=planner_stub)
        customiser = PayloadCustomiser(
            model="stub", completion_fn=_passthrough_customiser_completion
        )
        judge = SuccessJudge(model="stub", completion_fn=_judge_low_confidence)

        config = ScanConfig(
            target_id=f"mcp:filesystem:{sandbox}",
            provider="anthropic",
            model="stub",
            max_llm_calls=200,
            max_concurrent=1,
            output_dir=tmp_path / "scans",
        )
        engine = ScanEngine(
            config=config,
            adapter=adapter,
            attack_modules=[PromptInjectionAttackModule()],
            customiser=customiser,
            judge=judge,
        )
        result = await engine.run()

    findings_by_reason = [
        attempt.verdict_reason for attempt in result.report.attempts if attempt.outcome == "finding"
    ]
    assert result.report.findings_count >= 1, result.report
    assert any("write_file" in (r or "") for r in findings_by_reason), findings_by_reason
    assert result.report.aborted is None
