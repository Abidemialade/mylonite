"""Minimal stdio MCP server that pushes unsolicited notifications on a timer.

Launched as a subprocess for MYL-NT-002's repro (see
``tests/mcp_plugin/test_timed_notification_teardown.py``). Models any
server whose own background timer keeps emitting server-initiated
notifications (``notifications/message``, a resource-update push, ...)
independently of whatever the client is doing -- the shape the official
"everything" reference server uses for its periodic logging notification.

Not a test module (the ``_`` prefix keeps pytest from collecting it).

Env knobs:

* ``MYLONITE_TEST_NOTIFY_INTERVAL_S`` -- seconds between notifications
  (default ``0.2``, matching the task's repro spec).
* ``MYLONITE_TEST_NOTIFY_LINGER_S`` -- how long the timer keeps firing
  AFTER the client's side of stdio has gone away (``app.run()`` returned
  because the read stream hit EOF), modeling a server whose timer is not
  wired to the transport's own lifecycle. Default ``1.5`` -- inside the
  SDK client's ``PROCESS_TERMINATION_TIMEOUT`` (2.0s) grace window.
* ``MYLONITE_TEST_NOTIFY_EXIT_ON_WRITE_ERROR`` -- "1" makes the server
  process hard-exit (``os._exit``) the moment a notification write fails,
  modeling a server (like the Node SDK's ``StdioServerTransport``) whose
  writable-stream error is unhandled and kills the whole process -- the
  ``write EPIPE`` crash this task's evidence shows at teardown.
* ``MYLONITE_TEST_CRASH_ON_CALL_TOOL`` -- "1" makes ``call_tool`` hard-exit
  (``os._exit``) the instant it is invoked, instead of answering --
  deterministically modeling ANY cause of a mid-attempt process death
  (the timer-notification race is one; a crash in unrelated request
  handling is another) so the "Mylonite gives up on the whole attempt,
  no retry" behaviour can be checked without depending on a real timing
  race to land.
"""

from __future__ import annotations

import asyncio
import os

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

app: Server = Server("notifying-mylonite-test")

#: Populated from inside a request handler, where ``app.request_context``
#: is valid -- there is no public hook to grab the live ``ServerSession``
#: any other way from outside ``Server.run()``.
_session_holder: list[object] = []


@app.list_tools()
async def _list_tools() -> list[types.Tool]:
    if not _session_holder:
        _session_holder.append(app.request_context.session)
    return [
        types.Tool(
            name="ping",
            description="ping",
            inputSchema={"type": "object", "properties": {}},
        )
    ]


@app.call_tool()
async def _call_tool(name: str, arguments: dict[str, object]) -> list[types.TextContent]:
    del name, arguments
    if os.environ.get("MYLONITE_TEST_CRASH_ON_CALL_TOOL") == "1":
        os._exit(1)
    return [types.TextContent(type="text", text="pong")]


async def _notify_loop(interval_s: float, exit_on_error: bool) -> None:
    """Fire an unsolicited log notification every ``interval_s`` seconds.

    Deliberately NOT tied to ``app.run()``'s own read loop: a server whose
    background timer is independent of request/response traffic is exactly
    the shape under test.
    """
    while not _session_holder:
        await asyncio.sleep(0.01)
    session = _session_holder[0]
    while True:
        await asyncio.sleep(interval_s)
        try:
            await session.send_log_message(  # type: ignore[attr-defined]
                level="info", data="tick", logger="timer"
            )
        except Exception:
            if exit_on_error:
                # Models the Node SDK's unhandled 'error' event on a write to
                # an already-closed pipe: the whole process dies, not just
                # this one write.
                os._exit(1)
            return


async def _main() -> None:
    interval_s = float(os.environ.get("MYLONITE_TEST_NOTIFY_INTERVAL_S", "0.2"))
    linger_s = float(os.environ.get("MYLONITE_TEST_NOTIFY_LINGER_S", "1.5"))
    exit_on_error = os.environ.get("MYLONITE_TEST_NOTIFY_EXIT_ON_WRITE_ERROR") == "1"

    async with stdio_server() as (read_stream, write_stream):
        notifier = asyncio.create_task(_notify_loop(interval_s, exit_on_error))
        await app.run(read_stream, write_stream, app.create_initialization_options())
        # The client's read of stdin just hit EOF (it closed its write side),
        # but this server's own timer keeps running on its own schedule --
        # modeling a server never told, or that ignores, "the client is
        # going away". The repro's race window is here.
        await asyncio.sleep(linger_s)
        notifier.cancel()


if __name__ == "__main__":
    asyncio.run(_main())
