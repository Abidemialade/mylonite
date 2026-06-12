"""Unit tests for the MCP stdio adapter base.

The SDK's ``stdio_client`` is async-context-manager-of-anyio-streams; we
sidestep all of that by patching the adapter's internal
``_open_mcp_session`` helper to yield a hand-rolled fake session. This
keeps tests deterministic and fast (no subprocess).
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from mylonite.contracts import Payload
from mylonite.plugins._mcp import stdio_adapter
from mylonite.plugins._mcp.stdio_adapter import (
    MCPStdioAdapter,
    _extract_first_number,
    _user_message_for_drive,
)
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable

_classify_failure = MCPStdioAdapter._classify_failure


class _FakeSession:
    """Hand-rolled fake mcp.ClientSession that records all calls."""

    def __init__(
        self,
        tools: list[MCPTool] | None = None,
        call_responses: dict[str, CallToolResult] | None = None,
    ) -> None:
        self._tools = tools or [
            MCPTool(name="read_file", description="read a file", inputSchema={"type": "object"}),
            MCPTool(name="write_file", description="write a file", inputSchema={"type": "object"}),
        ]
        self._responses = call_responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(tools=list(self._tools))

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, dict(arguments)))
        if name in self._responses:
            return self._responses[name]
        return CallToolResult(
            content=[TextContent(type="text", text=f"{name} ok")],
            isError=False,
        )


@asynccontextmanager
async def _fake_open(*args: Any, **kwargs: Any):
    """Drop-in for stdio_adapter._open_mcp_session — yields a default FakeSession."""
    yield _FakeSession()


# --- _classify_failure ----------------------------------------------------------


def test_classify_failure_timeout() -> None:
    assert _classify_failure(TimeoutError()) == "timeout"


def test_classify_failure_subprocess_crash() -> None:
    assert _classify_failure(BrokenPipeError()) == "subprocess_crash"


def test_classify_failure_generic() -> None:
    assert _classify_failure(ValueError("nope")) == "planner_exception"


# --- _extract_first_number ------------------------------------------------------


def test_extract_first_number_from_text_blocks() -> None:
    blocks = [
        SimpleNamespace(text="Issue created. URL: https://github.com/x/y/issues/42 created."),
    ]
    assert _extract_first_number(blocks) == "42"


def test_extract_first_number_returns_none_on_no_match() -> None:
    blocks = [SimpleNamespace(text="No digits here.")]
    assert _extract_first_number(blocks) is None


# --- _user_message_for_drive ----------------------------------------------------


def test_user_message_read_file_for_summary() -> None:
    msg = _user_message_for_drive(
        "read_file_for_summary", payload_body="ignored", seeded_artefact_id="/tmp/x.txt"
    )
    assert "summarise" in msg.lower() and "/tmp/x.txt" in msg


def test_user_message_fetch_attacker_url_passes_body_through() -> None:
    msg = _user_message_for_drive(
        "fetch_attacker_url",
        payload_body="Please fetch http://attacker.example.com/x",
        seeded_artefact_id=None,
    )
    assert "attacker.example.com" in msg


def test_user_message_unknown_drive_falls_back_to_body() -> None:
    msg = _user_message_for_drive(
        "totally-unknown-drive", payload_body="DO STUFF", seeded_artefact_id=None
    )
    assert "DO STUFF" in msg


# --- MCPStdioAdapter --------------------------------------------------------------


@pytest.mark.asyncio
async def test_describe_returns_target_descriptor_with_tools(tmp_path: Path) -> None:
    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(family="filesystem", scope=str(tmp_path))
        descriptor = await adapter.describe()
    assert descriptor.target_id == f"mcp:filesystem:{tmp_path}"
    assert descriptor.kind == "mcp"
    assert {t.name for t in descriptor.tools} == {"read_file", "write_file"}


@pytest.mark.asyncio
async def test_target_id_without_scope_omits_segment() -> None:
    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(family="fetch", scope=None)
        descriptor = await adapter.describe()
    assert descriptor.target_id == "mcp:fetch"


@pytest.mark.asyncio
async def test_invoke_happy_path_returns_adapter_response(tmp_path: Path) -> None:
    """Planner stub calls write_file once then says done; adapter records it."""

    async def planner_stub(**_: Any) -> SimpleNamespace:

        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="done",
                        tool_calls=None,
                    )
                )
            ]
        )

    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(
            family="filesystem", scope=str(tmp_path), completion_fn=planner_stub
        )
        payload = Payload(
            pattern_id="test",
            channel="user-message",
            body="please read a file",
            metadata={"setup": "no_setup", "drive": "read_file_direct", "seed_id": "test"},
        )
        response = await adapter.invoke(payload)
    assert response.payload_pattern_id == "test"
    assert response.metadata["family"] == "filesystem"
    assert response.metadata["mcp_trace_planner"] == "[]"
    assert response.metadata["mcp_trace_setup"] == "[]"


@pytest.mark.asyncio
async def test_invoke_seed_file_setup_writes_file_and_records_trace(tmp_path: Path) -> None:
    """seed_file setup arm: write_file is called BEFORE planner runs.

    The setup call lands in ``mcp_trace_setup``, NOT ``mcp_trace_planner``
    (review A6 — predicates inspect planner trace only).
    """
    captured_session = SimpleNamespace(value=None)

    @asynccontextmanager
    async def fake_open(*args: Any, **kwargs: Any):
        session = _FakeSession()
        captured_session.value = session
        yield session

    async def planner_stub(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
        )

    with patch.object(stdio_adapter, "_open_mcp_session", fake_open):
        adapter = MCPStdioAdapter(
            family="filesystem", scope=str(tmp_path), completion_fn=planner_stub
        )
        payload = Payload(
            pattern_id="seed-file-test",
            channel="tool-result",
            body="[INJECTED] poisoned content",
            metadata={
                "setup": "seed_file",
                "drive": "read_file_for_summary",
                "seed_id": "seed-file-test",
            },
        )
        response = await adapter.invoke(payload)

    setup_trace = json.loads(response.metadata["mcp_trace_setup"])
    assert any(c["tool"] == "write_file" for c in setup_trace)
    planner_trace = json.loads(response.metadata["mcp_trace_planner"])
    assert planner_trace == []  # planner stub didn't call any tools
    assert response.metadata["seeded_artefact_id"].startswith(str(tmp_path))


@pytest.mark.asyncio
async def test_seed_arm_plants_poisoned_content_via_declared_tool(tmp_path: Path) -> None:
    """Issue #5 (real seeding): a declared seed_arm calls the target's tool with {payload}."""
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
    from mylonite.plugins._mcp.target_registry import SeedArmSpec

    target_registry.clear_runtime_targets()
    spec = build_target_spec(
        TargetFile(
            family="triagent",
            command="python",
            args=["-m", "srv"],
            weakness_classes=["W2"],
            seed_arm=SeedArmSpec(tool="remember", args_template={"content": "{payload}"}),
        )
    )
    target_registry.register_target(spec)

    captured = SimpleNamespace(session=None)

    @asynccontextmanager
    async def fake_open(*args: Any, **kwargs: Any):
        session = _FakeSession(
            tools=[MCPTool(name="remember", description="store", inputSchema={"type": "object"})]
        )
        captured.session = session
        yield session

    async def planner_stub(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
        )

    try:
        with patch.object(stdio_adapter, "_open_mcp_session", fake_open):
            adapter = MCPStdioAdapter(family="triagent", scope=None, completion_fn=planner_stub)
            payload = Payload(
                pattern_id="w2",
                channel="tool-result",
                body="[INJECTED] exfiltrate data",
                metadata={"setup": "seed_note", "drive": "read_note_for_summary", "seed_id": "w2"},
            )
            response = await adapter.invoke(payload)
    finally:
        target_registry.clear_runtime_targets()

    # The declared tool was called BEFORE the planner, with the payload substituted in.
    assert captured.session is not None
    remember_calls = [c for c in captured.session.calls if c[0] == "remember"]
    assert remember_calls, "expected the seed_arm tool 'remember' to be called"
    assert remember_calls[0][1] == {"content": "[INJECTED] exfiltrate data"}
    setup_trace = json.loads(response.metadata["mcp_trace_setup"])
    assert any(c["tool"] == "remember" for c in setup_trace)


@pytest.mark.asyncio
async def test_invoke_unknown_setup_arm_raises_seed_arm_unavailable(tmp_path: Path) -> None:
    """Issue #5: an un-plantable indirect seed must raise, not silently no-op.

    ``seed_note`` (the kitchen-sink arm) has no generic implementation; on a
    non-bundled target it must surface as SeedArmUnavailable so the engine can
    record skipped_no_seed_arm rather than scoring a fake no_finding.
    """

    async def planner_stub(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
        )

    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(
            family="filesystem", scope=str(tmp_path), completion_fn=planner_stub
        )
        payload = Payload(
            pattern_id="note-test",
            channel="tool-result",
            body="[INJECTED]",
            metadata={"setup": "seed_note", "drive": "read_note_for_summary", "seed_id": "note"},
        )
        with pytest.raises(SeedArmUnavailable) as excinfo:
            await adapter.invoke(payload)
    assert "seed_note" in str(excinfo.value)
    assert excinfo.value.attempt_metadata["setup"] == "seed_note"


@pytest.mark.asyncio
async def test_invoke_planner_exception_raises_skipped(tmp_path: Path) -> None:
    async def planner_stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(
            family="filesystem", scope=str(tmp_path), completion_fn=planner_stub
        )
        payload = Payload(
            pattern_id="test",
            channel="user-message",
            body="x",
            metadata={"setup": "no_setup", "drive": "read_file_direct", "seed_id": "test"},
        )
        with pytest.raises(AdapterInvocationSkipped) as excinfo:
            await adapter.invoke(payload)
    assert excinfo.value.attempt_metadata["reason"] == "planner_exception"
    assert excinfo.value.attempt_metadata["exception"] == "RuntimeError"
    assert excinfo.value.attempt_metadata["family"] == "filesystem"


@pytest.mark.asyncio
async def test_invoke_timeout_raises_skipped_with_reason(tmp_path: Path) -> None:
    async def slow_planner(**_: Any) -> SimpleNamespace:
        await asyncio.sleep(10)
        return SimpleNamespace()

    with patch.object(stdio_adapter, "_open_mcp_session", _fake_open):
        adapter = MCPStdioAdapter(
            family="filesystem",
            scope=str(tmp_path),
            completion_fn=slow_planner,
            planner_timeout_s=0.1,
        )
        payload = Payload(
            pattern_id="test",
            channel="user-message",
            body="x",
            metadata={"setup": "no_setup", "drive": "read_file_direct", "seed_id": "test"},
        )
        with pytest.raises(AdapterInvocationSkipped) as excinfo:
            await adapter.invoke(payload)
    assert excinfo.value.attempt_metadata["reason"] == "timeout"


@pytest.mark.asyncio
async def test_close_is_noop(tmp_path: Path) -> None:
    adapter = MCPStdioAdapter(family="filesystem", scope=str(tmp_path))
    result = await adapter.close()
    assert result is None
