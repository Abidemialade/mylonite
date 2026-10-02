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


@pytest.mark.parametrize(
    "extra",
    [
        {"resultType": "task"},
        {"task": {"taskId": "t-1", "status": "working"}},
        {"resultType": "task", "task": {"taskId": "t-1", "status": "working"}},
    ],
)
def test_result_to_tool_result_marks_a_task_handle(extra: dict[str, object]) -> None:
    """A server that answers with a task handle accepted the call for later. The
    flag is structural, so it holds whatever the text says."""
    result = CallToolResult.model_validate(
        {"content": [{"type": "text", "text": "Done. id=t-1"}], "isError": False, **extra}
    )
    assert _result_to_tool_result("send_email", result).task_handle is True


@pytest.mark.parametrize("extra", [{}, {"resultType": "complete"}, {"task": None}])
def test_result_to_tool_result_plain_result_has_no_task_handle(extra: dict[str, object]) -> None:
    result = CallToolResult.model_validate(
        {"content": [{"type": "text", "text": "sent"}], "isError": False, **extra}
    )
    assert _result_to_tool_result("send_email", result).task_handle is False


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


# --- tools/list pagination ------------------------------------------------------


class _PagingSession:
    """A fake ``mcp.ClientSession`` that serves ``tools/list`` in pages."""

    def __init__(self, pages: list[list[str]], *, loop_forever: bool = False) -> None:
        self.pages = pages
        self.loop_forever = loop_forever
        self.cursors: list[str | None] = []

    async def list_tools(self, cursor: str | None = None) -> SimpleNamespace:
        self.cursors.append(cursor)
        if self.loop_forever:
            n = len(self.cursors)
            return SimpleNamespace(tools=[_mcp_tool(f"t{n}")], nextCursor=f"c{n}")
        index = 0 if cursor is None else int(cursor)
        nxt = str(index + 1) if index + 1 < len(self.pages) else None
        return SimpleNamespace(tools=[_mcp_tool(n) for n in self.pages[index]], nextCursor=nxt)


@pytest.mark.asyncio
async def test_list_tools_follows_next_cursor_across_pages() -> None:
    session = _PagingSession([["read_file", "write_file"], ["send_email"]])
    shim = MCPSessionAsServerLike(session)  # type: ignore[arg-type]
    tools = await shim.list_tools()
    assert [t.name for t in tools] == ["read_file", "write_file", "send_email"]
    assert session.cursors == [None, "1"]


@pytest.mark.asyncio
async def test_list_tools_single_page_makes_one_request() -> None:
    session = _PagingSession([["read_file"]])
    tools = await MCPSessionAsServerLike(session).list_tools()  # type: ignore[arg-type]
    assert [t.name for t in tools] == ["read_file"]
    assert session.cursors == [None]


@pytest.mark.asyncio
async def test_list_tools_stops_at_the_page_cap(caplog: pytest.LogCaptureFixture) -> None:
    from mylonite.plugins._mcp.server_shim import MAX_TOOL_LIST_PAGES

    session = _PagingSession([], loop_forever=True)
    with caplog.at_level("WARNING"):
        tools = await MCPSessionAsServerLike(session).list_tools()  # type: ignore[arg-type]
    assert len(session.cursors) == MAX_TOOL_LIST_PAGES
    assert len(tools) == MAX_TOOL_LIST_PAGES
    assert "pages" in caplog.text


@pytest.mark.asyncio
async def test_list_tools_stops_on_a_repeated_cursor(caplog: pytest.LogCaptureFixture) -> None:
    class _Stuck:
        calls = 0

        async def list_tools(self, cursor: str | None = None) -> SimpleNamespace:
            self.calls += 1
            return SimpleNamespace(tools=[_mcp_tool(f"t{self.calls}")], nextCursor="same")

    session = _Stuck()
    with caplog.at_level("WARNING"):
        tools = await MCPSessionAsServerLike(session).list_tools()  # type: ignore[arg-type]
    assert session.calls == 2
    assert [t.name for t in tools] == ["t1", "t2"]
    assert "repeated" in caplog.text


@pytest.mark.asyncio
async def test_describe_lists_tools_from_every_page() -> None:
    """End to end through the stdio adapter: a paginating server loses no tools."""
    from contextlib import asynccontextmanager

    from mylonite.plugins._mcp import stdio_adapter, target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec

    session = _PagingSession([["read_file"], ["write_file"], ["send_email"]])

    def _open(*args: object, **kwargs: object) -> object:
        @asynccontextmanager
        async def _ctx():  # type: ignore[no-untyped-def]
            yield session

        return _ctx()

    target_registry.clear_runtime_targets()
    try:
        target_registry.register_target(
            build_target_spec(TargetFile(family="paging-app", command="python", args=["-m", "srv"]))
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(stdio_adapter, "_open_mcp_session", _open)
            descriptor = await MCPStdioAdapter(family="paging-app", scope=None).describe()
    finally:
        target_registry.clear_runtime_targets()
    assert [t.name for t in descriptor.tools] == ["read_file", "write_file", "send_email"]


@pytest.mark.asyncio
async def test_a_complete_listing_is_marked_complete() -> None:
    from mylonite.plugins._mcp.server_shim import list_all_tools

    listing = await list_all_tools(_PagingSession([["a"], ["b"]]))  # type: ignore[arg-type]
    assert listing.complete is True
    assert [t.name for t in listing.tools] == ["a", "b"]


@pytest.mark.asyncio
async def test_a_stopped_listing_is_marked_partial_on_the_shim() -> None:
    from mylonite.plugins._mcp.server_shim import list_all_tools

    listing = await list_all_tools(_PagingSession([], loop_forever=True))  # type: ignore[arg-type]
    assert listing.complete is False
    shim = MCPSessionAsServerLike(_PagingSession([], loop_forever=True))  # type: ignore[arg-type]
    assert shim.truncated is False
    await shim.list_tools()
    assert shim.truncated is True


@pytest.mark.asyncio
async def test_a_tool_on_two_pages_is_listed_once() -> None:
    session = _PagingSession([["read_file", "write_file"], ["write_file", "send_email"]])
    tools = await MCPSessionAsServerLike(session).list_tools()  # type: ignore[arg-type]
    assert [t.name for t in tools] == ["read_file", "write_file", "send_email"]


@pytest.mark.asyncio
async def test_later_pages_use_the_params_keyword_when_the_sdk_has_it() -> None:
    from mcp.types import PaginatedRequestParams

    class _ParamsSession:
        def __init__(self) -> None:
            self.calls: list[tuple[str | None, object]] = []

        async def list_tools(
            self, cursor: str | None = None, *, params: PaginatedRequestParams | None = None
        ) -> SimpleNamespace:
            self.calls.append((cursor, params))
            if params is None:
                return SimpleNamespace(tools=[_mcp_tool("a")], nextCursor="p2")
            return SimpleNamespace(tools=[_mcp_tool("b")], nextCursor=None)

    session = _ParamsSession()
    tools = await MCPSessionAsServerLike(session).list_tools()  # type: ignore[arg-type]
    assert [t.name for t in tools] == ["a", "b"]
    assert session.calls[1][0] is None
    assert isinstance(session.calls[1][1], PaginatedRequestParams)
    assert session.calls[1][1].cursor == "p2"


@pytest.mark.asyncio
async def test_a_page_that_hangs_times_out() -> None:
    import asyncio

    class _Hangs:
        async def list_tools(self, cursor: str | None = None) -> SimpleNamespace:
            if cursor is None:
                return SimpleNamespace(tools=[_mcp_tool("a")], nextCursor="next")
            await asyncio.sleep(10)
            raise AssertionError("unreachable")  # pragma: no cover

    shim = MCPSessionAsServerLike(_Hangs(), page_timeout_s=0.05)  # type: ignore[arg-type]
    with pytest.raises(asyncio.TimeoutError):
        await shim.list_tools()
