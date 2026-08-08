"""Shared stdio-transport wrapper for the kitchen-sink reference servers.

Phase 0 shipped ``server_vulnerable.py``/``server_guarded.py`` as in-process
server *classes* only — ``VulnerableKitchenSinkServer``/
``GuardedKitchenSinkServer`` implement ``list_tools()``/``call_tool()`` but
never speak the MCP wire protocol themselves ("wrap it in your own MCP
transport" per each module's docstring). That left ``mylonite``'s own
custom-target flow (``--target-file`` pointing at a ``command``/``args`` that
spawn a real stdio MCP server) with no in-repo exercise path against this
reference target.

This module is that transport wrapper. It builds a real ``mcp.server.Server``
whose ``list_tools``/``call_tool`` handlers delegate straight to one of the
two existing server classes' methods — no tool logic is reimplemented here,
only the protocol adaptation (mylonite's ``ToolDescription``/``ToolResult`` <->
the MCP SDK's ``Tool``/``CallToolResult``). This is the transport-side mirror
of ``mylonite.plugins._mcp.server_shim`` (which adapts a *client* session to
mylonite's shapes); this module adapts a *server* implementation the other
way.

Entry points: ``stdio_vulnerable.main`` / ``stdio_guarded.main`` (registered
as the ``mcp-kitchen-sink-vulnerable`` / ``mcp-kitchen-sink-guarded`` console
scripts in ``pyproject.toml``) each call :func:`run` with their fixed variant.
"""

from __future__ import annotations

import asyncio
from typing import Literal

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from mcp_kitchen_sink._types import ToolResult
from mcp_kitchen_sink.server_guarded import GuardedKitchenSinkServer
from mcp_kitchen_sink.server_vulnerable import VulnerableKitchenSinkServer

Variant = Literal["vulnerable", "guarded"]


def _build_impl(variant: Variant) -> VulnerableKitchenSinkServer | GuardedKitchenSinkServer:
    if variant == "vulnerable":
        return VulnerableKitchenSinkServer()
    if variant == "guarded":
        return GuardedKitchenSinkServer()
    msg = f"unknown kitchen-sink variant: {variant!r}"
    raise ValueError(msg)


def _tool_result_to_call_result(result: ToolResult) -> types.CallToolResult:
    """Convert the reference classes' ``ToolResult`` to the MCP SDK's shape.

    ``isError`` propagation is load-bearing here exactly as it is on the
    client-side shim (``server_shim.py``): a guarded refusal (``isError=True``)
    must not read as a successful call to whatever drives this server over
    stdio, or a guarded-twin differential check would see a false "it
    complied".
    """
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=result.content)],
        isError=bool(result.isError),
    )


def build_app(variant: Variant) -> Server:
    """Build a real ``mcp.server.Server`` delegating to ``variant``'s reference class.

    Exposed (not just used internally by :func:`run`) so a test can construct
    the app and drive it in-process via the SDK's client/server memory
    streams without spawning a subprocess.
    """
    impl = _build_impl(variant)
    app: Server = Server(f"mcp-kitchen-sink-{variant}")

    @app.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=d.name,
                description=d.description,
                inputSchema=d.input_schema,
            )
            for d in impl.list_tools()
        ]

    @app.call_tool()
    async def _call_tool(name: str, arguments: dict[str, object]) -> types.CallToolResult:
        result = impl.call_tool(name, dict(arguments))
        return _tool_result_to_call_result(result)

    return app


async def _run(variant: Variant) -> None:
    app = build_app(variant)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run(variant: Variant) -> None:
    """Synchronous entry point: run ``variant``'s server over stdio until EOF."""
    asyncio.run(_run(variant))
