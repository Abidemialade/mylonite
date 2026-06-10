"""Adapt an ``mcp.ClientSession`` to the planner's async ``_ServerLike``.

The MCP SDK returns its own ``mcp.types.Tool`` (camelCase ``inputSchema``)
and ``CallToolResult`` (``content`` is a list of content blocks, plus
``isError`` for guarded refusals). The planner expects mylonite's
``ToolDescription`` + ``ToolResult`` shapes. This shim converts both
directions explicitly.

``isError`` propagation is load-bearing: without it, a guarded MCP server's
refusal (``isError=True``, body "host not in allowlist") would look like a
successful tool return and predicates could fire false positives. See
plan-eng-review finding **A3**.
"""

from __future__ import annotations

from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from mylonite.scan.llm_types import ToolDescription, ToolResult


def _tool_to_description(t: MCPTool) -> ToolDescription:
    """Convert one MCP SDK Tool entry to mylonite's ToolDescription."""
    return ToolDescription(
        name=t.name,
        description=t.description or "",
        input_schema=t.inputSchema or {"type": "object", "properties": {}},
    )


def _result_to_tool_result(name: str, r: CallToolResult) -> ToolResult:
    """Convert one MCP SDK CallToolResult to mylonite's ToolResult.

    The SDK's ``content`` is a list of content blocks; we keep just the
    text. ``isError`` propagates so predicates can distinguish guarded
    refusals from successful tool returns.
    """
    text_parts = [c.text for c in r.content if isinstance(c, TextContent)]
    return ToolResult(
        name=name,
        content="\n".join(text_parts),
        isError=bool(r.isError),
    )


class MCPSessionAsServerLike:
    """Async adapter from ``mcp.ClientSession`` to ``LLMPlanner._ServerLike``."""

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> list[ToolDescription]:
        resp = await self._session.list_tools()
        return [_tool_to_description(t) for t in resp.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        result = await self._session.call_tool(name, arguments)
        return _result_to_tool_result(name, result)
