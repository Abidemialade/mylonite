"""Minimal stdio MCP server that delays its first response (no network).

Launched as a subprocess by the live describe()-timeout test, so that test
exercises the REAL ``stdio_client``/``ClientSession`` + anyio task-group
machinery -- the only way to reproduce the ``ExceptionGroup``-wrapped timeout
a genuinely slow/hung server produces (a fake session double that raises a
bare ``TimeoutError``/``McpError`` never wraps it, and so never exercised the
bug this guards). Sleeps before opening the stdio transport at all, standing
in for a slow `npx -y`/`uvx` package download that delays the server's first
response, not just a slow in-session call. Not a test module (the ``_``
prefix keeps pytest from collecting it).
"""

from __future__ import annotations

import asyncio
import sys

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

app: Server = Server("sleepy-mylonite-test")


@app.list_tools()
async def _list_tools() -> list[types.Tool]:
    return []


async def _main() -> None:
    delay_s = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    await asyncio.sleep(delay_s)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
