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

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from mylonite.plugins._mcp.tool_surface import wire_tool_dump
from mylonite.scan.llm_types import ToolDescription, ToolResult

logger = logging.getLogger(__name__)

#: Most ``tools/list`` pages read before giving up. A server that keeps handing
#: back a cursor past this is treated as broken: the tools read so far are used
#: and a warning is logged.
MAX_TOOL_LIST_PAGES = 100


@dataclass(frozen=True)
class ToolListing:
    """The tools a server listed, and whether the listing reached its end."""

    tools: list[MCPTool]
    #: False when reading stopped early (page cap or a repeated cursor), so
    #: tools on unread pages are missing from :attr:`tools`.
    complete: bool


async def _list_page(
    session: ClientSession, cursor: str | None, page_timeout_s: float | None
) -> Any:
    """One ``tools/list`` request, bounded by ``page_timeout_s`` when set.

    A later page is requested through ``params=PaginatedRequestParams(...)``,
    the SDK's current spelling. An SDK too old for that keyword gets the
    positional ``cursor`` instead.
    """

    async def _request() -> Any:
        if cursor is None:
            return await session.list_tools()
        try:
            from mcp.types import PaginatedRequestParams

            return await session.list_tools(params=PaginatedRequestParams(cursor=cursor))
        except (ImportError, TypeError):
            return await session.list_tools(cursor)

    if page_timeout_s is None:
        return await _request()
    return await asyncio.wait_for(_request(), timeout=page_timeout_s)


async def list_all_tools(
    session: ClientSession, *, page_timeout_s: float | None = None
) -> ToolListing:
    """Every tool the server lists, following ``nextCursor`` across pages.

    The MCP spec lets a server split ``tools/list`` into pages; reading only the
    first would silently drop the rest from every scan. Stops when the server
    returns no cursor. A repeated cursor, or more than
    :data:`MAX_TOOL_LIST_PAGES` pages, stops early with a warning and returns
    ``complete=False``, so the caller can say the surface is partial. A tool
    name seen on an earlier page is not added twice. Each page is bounded by
    ``page_timeout_s`` when given; a page that times out raises.
    """
    tools: dict[str, MCPTool] = {}

    def _add(page: Any) -> None:
        for tool in page.tools:
            tools.setdefault(tool.name, tool)

    resp = await _list_page(session, None, page_timeout_s)
    _add(resp)
    seen: set[str] = set()
    pages = 1
    cursor = getattr(resp, "nextCursor", None)
    while cursor:
        if cursor in seen:
            logger.warning(
                "tools/list returned a repeated cursor after %d pages; the %d tools read "
                "are a partial list",
                pages,
                len(tools),
            )
            return ToolListing(tools=list(tools.values()), complete=False)
        if pages >= MAX_TOOL_LIST_PAGES:
            logger.warning(
                "tools/list still had more after %d pages; the %d tools read are a partial list",
                pages,
                len(tools),
            )
            return ToolListing(tools=list(tools.values()), complete=False)
        seen.add(cursor)
        resp = await _list_page(session, cursor, page_timeout_s)
        _add(resp)
        pages += 1
        cursor = getattr(resp, "nextCursor", None)
    return ToolListing(tools=list(tools.values()), complete=True)


def _tool_to_description(t: MCPTool) -> ToolDescription:
    """Convert one MCP SDK Tool entry to mylonite's ToolDescription.

    ``annotations`` is dumped rather than typed so a server that ships fields
    newer than the pinned SDK still round-trips them; ``exclude_none`` keeps an
    undeclared hint absent instead of an explicit null, which matters because
    "the server said nothing" and "the server said false" are different signals
    to ``tool_classifier.classify``.

    The tool as the server sent it is kept on ``wire`` (every key), so the
    rug-pull check can sign fields this model does not carry.
    """
    annotations: dict[str, object] | None = None
    raw = getattr(t, "annotations", None)
    if raw is not None:
        dump = getattr(raw, "model_dump", None)
        annotations = dump(exclude_none=True) if callable(dump) else None
        if not annotations:
            annotations = None
    return ToolDescription(
        name=t.name,
        description=t.description or "",
        input_schema=t.inputSchema or {"type": "object", "properties": {}},
        annotations=annotations,
        wire=wire_tool_dump(t),
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
        task_handle=_is_task_handle(r),
    )


def _is_task_handle(r: CallToolResult) -> bool:
    """Whether the server answered with a task handle instead of a final result.

    A server with its own job queue can wrap the handle in an ordinary tool
    result: ``resultType: "task"`` or a ``task`` object next to the content.
    Either means the action was accepted for later, not carried out, whatever
    the text says.
    """
    extra = r.model_extra or {}
    return extra.get("resultType") == "task" or extra.get("task") is not None


class MCPSessionAsServerLike:
    """Async adapter from ``mcp.ClientSession`` to ``LLMPlanner._ServerLike``."""

    def __init__(self, session: ClientSession, *, page_timeout_s: float | None = None) -> None:
        self._session = session
        self._page_timeout_s = page_timeout_s
        #: True once any listing through this shim stopped before its last
        #: page. Sticky: a later complete listing does not clear it, because the
        #: planner may already have acted on the partial one.
        self.truncated = False

    async def list_tools(self) -> list[ToolDescription]:
        listing = await list_all_tools(self._session, page_timeout_s=self._page_timeout_s)
        if not listing.complete:
            self.truncated = True
        return [_tool_to_description(t) for t in listing.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        result = await self._session.call_tool(name, arguments)
        return _result_to_tool_result(name, result)
