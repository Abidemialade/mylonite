"""Unit tests for the MCP-session-to-_ServerLike shim.

Mocks ``mcp.ClientSession`` directly — no subprocess. Verifies the type
conversions, especially ``isError`` propagation (review **A3**).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.types import (
    BlobResourceContents,
    CallToolResult,
    EmbeddedResource,
    TextContent,
)
from mcp.types import Tool as MCPTool

from mylonite.plugins._mcp.server_shim import (
    MCPSessionAsServerLike,
    _result_to_tool_result,
    _tool_to_description,
)


def _mcp_tool(name: str = "read_file") -> MCPTool:
    return MCPTool(
        name=name,
        description="read a file",
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
    )


def test_tool_to_description_converts_input_schema_case() -> None:
    desc = _tool_to_description(_mcp_tool("read_file"))
    assert desc.name == "read_file"
    assert desc.description == "read a file"
    assert desc.input_schema == {"type": "object", "properties": {"path": {"type": "string"}}}


def test_tool_to_description_handles_missing_description() -> None:
    t = MCPTool(name="noisy", description=None, inputSchema={})
    desc = _tool_to_description(t)
    assert desc.description == ""
    assert desc.input_schema == {"type": "object", "properties": {}}


def test_result_to_tool_result_joins_text_blocks() -> None:
    result = CallToolResult(
        content=[
            TextContent(type="text", text="line 1"),
            TextContent(type="text", text="line 2"),
        ],
        isError=False,
    )
    tr = _result_to_tool_result("read_file", result)
    assert tr.name == "read_file"
    assert tr.content == "line 1\nline 2"
    assert tr.isError is False


def test_result_to_tool_result_propagates_is_error_true() -> None:
    """Guarded-server refusal contract: isError must surface to the planner."""
    result = CallToolResult(
        content=[TextContent(type="text", text="host not in allowlist")],
        isError=True,
    )
    tr = _result_to_tool_result("fetch", result)
    assert tr.isError is True
    assert "allowlist" in tr.content


def test_result_to_tool_result_ignores_non_text_content() -> None:
    """Embedded resources are skipped — Phase 1 predicates only inspect text."""
    result = CallToolResult(
        content=[
            TextContent(type="text", text="some text"),
            EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(uri="file:///x", mimeType="image/png", blob="abcd"),
            ),
        ],
        isError=False,
    )
    tr = _result_to_tool_result("x", result)
    assert tr.content == "some text"


@pytest.mark.asyncio
async def test_shim_list_tools_delegates_and_converts() -> None:
    session = SimpleNamespace(
        list_tools=AsyncMock(return_value=SimpleNamespace(tools=[_mcp_tool("a"), _mcp_tool("b")]))
    )
    shim = MCPSessionAsServerLike(session)  # type: ignore[arg-type]
    tools = await shim.list_tools()
    assert [t.name for t in tools] == ["a", "b"]
    session.list_tools.assert_awaited_once()


@pytest.mark.asyncio
async def test_shim_call_tool_delegates_and_propagates_is_error() -> None:
    session = SimpleNamespace(
        call_tool=AsyncMock(
            return_value=CallToolResult(
                content=[TextContent(type="text", text="refused")],
                isError=True,
            )
        )
    )
    shim = MCPSessionAsServerLike(session)  # type: ignore[arg-type]
    result = await shim.call_tool("fetch", {"url": "http://x"})
    assert result.name == "fetch"
    assert result.isError is True
    assert "refused" in result.content
    session.call_tool.assert_awaited_once_with("fetch", {"url": "http://x"})
