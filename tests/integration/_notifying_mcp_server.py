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
* ``MYLONITE_TEST_TOGGLE_STARTS_NOTIFY`` -- "1" adds a ``toggle_logging``
  tool. The notifier does NOT run from server start; calling
  ``toggle_logging`` fires it off with ``asyncio.create_task`` -- NOT
  awaited -- and only THEN returns the tool call's own result, so the
  first notification write and this request's own response write are
  racing each other on the same transport, through the exact client path
  (``MCPSessionAsServerLike.call_tool``) the real planner drives a
  consequential "turn this on" tool through. Models a server whose
  state-toggling tool starts unsolicited sends mid-session rather than
  from the first byte.
* ``MYLONITE_TEST_NOTIFY_KIND`` -- which notification the timer sends:
  ``log`` (default, ``notifications/message``) or ``resource``
  (``notifications/resources/updated``).
* ``MYLONITE_TEST_NOTIFY_ON_EOF`` -- "1" makes the server write one raw
  notification line straight to stdout the moment the client closes its
  side of stdin, i.e. while the client is tearing the session down.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

app: Server = Server("notifying-mylonite-test")

#: Populated from inside a request handler, where ``app.request_context``
#: is valid -- there is no public hook to grab the live ``ServerSession``
#: any other way from outside ``Server.run()``.
_session_holder: list[object] = []


#: True once ``toggle_logging`` has fired the notifier -- lets a second
#: call (and the test's own completion script) be a no-op.
_toggled: list[bool] = []
#: Keeps the fire-and-forget notifier task referenced (never awaited by
#: design -- that is the race under test) so it is not garbage-collected
#: mid-flight.
_background_tasks: list[asyncio.Task[None]] = []


@app.list_tools()
async def _list_tools() -> list[types.Tool]:
    if not _session_holder:
        _session_holder.append(app.request_context.session)
    tools = [
        types.Tool(
            name="ping",
            description="ping",
            inputSchema={"type": "object", "properties": {}},
        )
    ]
    if os.environ.get("MYLONITE_TEST_TOGGLE_STARTS_NOTIFY") == "1":
        tools.append(
            types.Tool(
                name="toggle_logging",
                description="turn on simulated logging notifications",
                inputSchema={"type": "object", "properties": {}},
            )
        )
    return tools


@app.call_tool()
async def _call_tool(name: str, arguments: dict[str, object]) -> list[types.TextContent]:
    del arguments
    if os.environ.get("MYLONITE_TEST_CRASH_ON_CALL_TOOL") == "1":
        os._exit(1)
    if name == "toggle_logging" and not _toggled:
        _toggled.append(True)
        interval_s = float(os.environ.get("MYLONITE_TEST_NOTIFY_INTERVAL_S", "0.0"))
        exit_on_error = os.environ.get("MYLONITE_TEST_NOTIFY_EXIT_ON_WRITE_ERROR") == "1"
        # Fire-and-forget, deliberately NOT awaited: the handler's own
        # response write (below, once this coroutine returns) and the
        # notifier's first write race each other on the SAME transport.
        _background_tasks.append(asyncio.create_task(_notify_loop(interval_s, exit_on_error)))
        return [types.TextContent(type="text", text="logging on")]
    return [types.TextContent(type="text", text="pong")]


async def _send_one(session: object) -> None:
    """Send one notification of the kind ``MYLONITE_TEST_NOTIFY_KIND`` names."""
    if os.environ.get("MYLONITE_TEST_NOTIFY_KIND", "log") == "resource":
        from pydantic import AnyUrl

        await session.send_resource_updated(AnyUrl("memo://tick"))  # type: ignore[attr-defined]
    else:
        await session.send_log_message(  # type: ignore[attr-defined]
            level="info", data="tick", logger="timer"
        )


def _write_raw_notification() -> None:
    """Write one log notification line straight to stdout, bypassing the
    (already closed) server session -- a server that still has something to
    say while the client is closing."""
    line = {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": "info", "logger": "timer", "data": "closing"},
    }
    sys.stdout.write(json.dumps(line) + "\n")
    sys.stdout.flush()


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
            await _send_one(session)
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

    toggle_mode = os.environ.get("MYLONITE_TEST_TOGGLE_STARTS_NOTIFY") == "1"

    async with stdio_server() as (read_stream, write_stream):
        notifier = (
            None if toggle_mode else asyncio.create_task(_notify_loop(interval_s, exit_on_error))
        )
        await app.run(read_stream, write_stream, app.create_initialization_options())
        if os.environ.get("MYLONITE_TEST_NOTIFY_ON_EOF") == "1":
            _write_raw_notification()
        # The client's read of stdin just hit EOF (it closed its write side),
        # but this server's own timer keeps running on its own schedule --
        # modeling a server never told, or that ignores, "the client is
        # going away". The repro's race window is here.
        await asyncio.sleep(linger_s)
        if notifier is not None:
            notifier.cancel()


if __name__ == "__main__":
    asyncio.run(_main())
