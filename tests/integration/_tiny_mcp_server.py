"""Minimal stdio MCP server for the session-lifecycle live test (no network).

Launched as a subprocess (``python _tiny_mcp_server.py``) so the AttackSession
lifecycle test exercises the real ``stdio_client``/``ClientSession`` + anyio
machinery without downloading an npm/uvx server. Not a test module (the ``_``
prefix keeps pytest from collecting it).
"""

from __future__ import annotations

import asyncio

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

app: Server = Server("tiny-mylonite-test")


@app.list_tools()
async def _list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="ping",
            description="ping",
            inputSchema={"type": "object", "properties": {}},
        )
    ]


@app.call_tool()
async def _call_tool(name: str, arguments: dict[str, object]) -> list[types.TextContent]:
    return [types.TextContent(type="text", text="pong")]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
