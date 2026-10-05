"""MYL-NT-002 root cause: a consequential tool call that turns ON a server's
unsolicited-notification timer mid-session reliably crashes Mylonite's
stdio session, losing the whole attempt with no retry.

Field evidence (the official "everything" reference server, Node stdio): 4
of 6 third-party runs skip ``synth-w1-rug-pull`` as
``[MYL-NT-002] subprocess_crash on synth-w1-rug-pull: BrokenResourceError()``;
``write EPIPE`` appears in exactly those 4 crashed runs' Node stderr and in
neither of the 2 clean runs; the crashed runs' ``tool_call_trace`` is empty
(the session died before `invoke()` ever returned, so nothing was persisted
-- it does not mean zero MCP calls happened); and the run plan's
consequential tools (scan.log) include state-toggling tools
(``toggle-simulated-logging``, ``toggle-subscriber-updates``) -- exactly the
shape "a tool call that starts timed sends".

## Repro history

An EARLIER repro attempt (a server whose notification timer ran from
process start, independent of any tool call) did NOT reproduce this --
negative results are kept below as
``test_a_periodic_notification_timer_does_not_crash_the_attempt`` and
``test_a_notification_at_the_close_instant_does_not_crash_the_attempt``.
Starting the timer from a TOOL CALL instead (this module's main repro)
reproduces it reliably (every run observed while writing this test): same
exception type (``anyio.BrokenResourceError``), same classification
(``subprocess_crash``, ``_session_adapter.py``'s ``_classify_failure``) and
the same free-text detail Mylonite's own logs shows
(``subprocess_crash on synth-w1-rug-pull: BrokenResourceError()``) as the
field evidence, byte for byte.

## Mechanism (confirmed via the raised exception's own traceback)

``anyio.BrokenResourceError`` is raised from
``mcp/client/stdio/__init__.py``'s ``stdout_reader`` task, inside
``await read_stream_writer.send(session_message)`` -- i.e. while FORWARDING
an already-read line from the child's stdout into the memory-object stream
``mcp.ClientSession`` reads from. ``send()`` only raises
``BrokenResourceError`` (not ``WouldBlock``) when the receiving end has
already been closed. ``ClientSession`` and the ``stdio_client`` transport
are two SEPARATE, nested async context managers
(``async with (stdio_client(...) as streams, ClientSession(...) as
session):`` in ``stdio_adapter._open_mcp_session``) that do not close
atomically: ``ClientSession.__aexit__`` (closing its handle on the shared
read stream) runs, then a few event-loop ticks pass, THEN
``stdio_client``'s own task group tears down ``stdout_reader``. Any message
the still-alive server writes that lands in that gap crashes the forwarding
task with ``BrokenResourceError``, which escapes ``stdio_client``'s task
group and propagates out of
``MCPSessionAdapterBase.invoke``'s ``async with self._session(...)``
exactly like a failure in the attempt's own body would.

A notification timer running from the first byte (the earlier, negative
repro) rarely lands a write in that few-millisecond gap, because the WHOLE
session typically finishes and tears down long before the timer's first
tick. A timer a TOOL CALL starts mid-session fires its first tick almost
immediately (no warm-up delay) -- right as the attempt's own remaining work
(the rug-pull re-list, then teardown) is ALSO finishing -- which is why it
lands in the gap reliably instead of by chance.

## General mechanism (not server-specific)

ANY server where a tool call starts pushing unsolicited notifications
(logging messages, resource updates, anything) independently of
request/response traffic can have its first push land in this
client-library close-sequencing gap, at a point in an attempt's lifetime
Mylonite does not control and cannot predict. The crash has nothing to do
with whether the probe landed or failed -- the attempt's own business logic
(the tool call, the rug-pull comparison) can have already fully succeeded.

## Verdict: MYLONITE

General, not server-specific. The race lives in how the ``mcp`` client
library composes two nested context managers (arguably a defect worth
reporting upstream), but Mylonite is what drives this exact code path with
no resilience to it: on a transport-crash classification
(``subprocess_crash`` et al.), the whole seed is lost for the run with no
retry, misattributed as third-party flakiness. The field evidence's
"Consequential tools this run may drive: ... toggle-simulated-logging,
toggle-subscriber-updates" (the crashed runs' own scan.log line) is almost
certainly what the planner called right before four of six runs crashed:
the SAME shape this module's main repro forces deterministically.

A retry alone is still not a full fix for every shape of this bug (a server
that crashes outright, rather than just racing a client-library teardown
gap, cannot be retried into success) -- but it is the correct response to
THIS mechanism specifically, because the server here never dies: only the
CLIENT's own close sequencing loses a message. Described, not implemented
(per the task): the general root-cause fix is to retry the attempt once,
against a fresh subprocess, on a transport-crash classification for an
attempt whose planner had not yet produced a final result -- the same
one-shot shape already used for a provider ``rate_limit`` in
``_classify_failure``'s own docstring. A more complete fix would also close
``ClientSession`` and the ``stdio_client`` transport in a way that drains or
ignores a message arriving during this specific shutdown window, but that
is a change to how the adapter composes the MCP SDK's own context managers,
not described further here.
"""

from __future__ import annotations

import dataclasses
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp import stdio_adapter, target_registry
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter, _open_mcp_session
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
from mylonite.scan._types import AdapterInvocationSkipped

FAMILY = "timed-notify"
_SERVER = Path(__file__).resolve().parents[1] / "integration" / "_notifying_mcp_server.py"

_PAYLOAD = Payload(
    pattern_id="synth-w1-rug-pull",
    channel="user-message",
    body="what is the weather",
    metadata={"setup": "no_setup", "drive": "unknown", "seed_id": "synth-w1-rug-pull"},
)


async def _one_shot_done(**kwargs: Any) -> SimpleNamespace:
    """The planner's only completion call: no tool call, done immediately."""
    del kwargs
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
    )


def _tool_call_then_done(tool_name: str) -> Any:
    """A completion_fn that calls ``tool_name`` once, then finishes -- the
    SAME planner call shape ``LLMPlanner`` drives any consequential tool
    through (``_RecordingServerShim.call_tool`` ->
    ``MCPSessionAsServerLike.call_tool`` -> ``session.call_tool(...)``)."""

    async def _completion(**kwargs: Any) -> SimpleNamespace:
        messages = kwargs.get("messages", [])
        if len(messages) <= 2:
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content="",
                            tool_calls=[
                                SimpleNamespace(
                                    id="c",
                                    function=SimpleNamespace(name=tool_name, arguments="{}"),
                                )
                            ],
                        )
                    )
                ]
            )
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
        )

    return _completion


def _register(extra_env: dict[str, str]) -> target_registry.TargetSpec:
    target_registry.clear_runtime_targets()
    spec = dataclasses.replace(
        build_target_spec(
            TargetFile(
                family=FAMILY,
                command=sys.executable,
                args=[str(_SERVER)],
                weakness_classes=["W1"],
            )
        ),
        extra_env=extra_env,
    )
    target_registry.register_target(spec)
    return spec


@pytest.fixture
def _notifying_target() -> Iterator[target_registry.TargetSpec]:
    """Registers ``FAMILY`` against the real notifying-server subprocess with
    a periodic timer (every 0.1s) running from process start, lingering 1.0s
    past ``Server.run()`` returning."""
    yield _register(
        {
            "MYLONITE_TEST_NOTIFY_INTERVAL_S": "0.1",
            "MYLONITE_TEST_NOTIFY_LINGER_S": "1.0",
        }
    )
    target_registry.clear_runtime_targets()


@pytest.fixture
def _toggle_target() -> Iterator[target_registry.TargetSpec]:
    """Registers ``FAMILY`` against a server that exposes a second tool,
    ``toggle_logging``: the notifier does NOT run until that tool is called,
    at which point it fires (unawaited) with a near-zero interval, racing
    the tool call's own response -- the shape the controller's follow-up
    evidence points at (a consequential "toggle" tool starting timed sends).

    The env vars reach the child through ``TargetSpec.extra_env`` -- the
    SAME documented mechanism a custom target file's ``env:`` block uses
    (``_compose_child_env`` only inherits a narrow OS-plumbing allowlist
    from the parent otherwise, DCR-0012).
    """
    yield _register(
        {
            "MYLONITE_TEST_TOGGLE_STARTS_NOTIFY": "1",
            "MYLONITE_TEST_NOTIFY_INTERVAL_S": "0.0",
            "MYLONITE_TEST_NOTIFY_LINGER_S": "1.0",
        }
    )
    target_registry.clear_runtime_targets()


# --- Negative repro 1: periodic timer from process start, natural overlap --


@pytest.mark.asyncio
async def test_a_periodic_notification_timer_does_not_crash_the_attempt(
    _notifying_target: target_registry.TargetSpec,
) -> None:
    """Negative result: a timer running since process start rarely lands a
    write in the client's close-sequencing gap, because the whole session
    typically finishes long before its first tick."""
    adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_one_shot_done)
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


# --- Negative repro 2: one notification synchronized to the close instant --


@pytest.mark.asyncio
async def test_a_notification_at_the_close_instant_does_not_crash_the_attempt(
    _notifying_target: target_registry.TargetSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Narrower variant: one extra unsolicited write synchronized to exactly
    the moment ``self._session(...)`` starts to exit. Also a negative
    result -- a single notification AFTER the planner-facing ``yield``
    returns is not early enough to land in the gap this module's main repro
    hits (see that test's docstring for exactly where the gap is)."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _session_then_ping(*args: Any, **kwargs: Any) -> Any:
        async with _open_mcp_session(*args, **kwargs) as session:
            yield session
            await session.send_ping()

    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", _session_then_ping)
    adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_one_shot_done)
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


# --- Main repro: a tool call turns ON timed sends mid-session --------------


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason=(
        "MYL-NT-002: a consequential tool call that starts a server's "
        "notification timer mid-session reliably races mcp.ClientSession's "
        "and stdio_client's non-atomic shutdown, raising "
        "anyio.BrokenResourceError (classified subprocess_crash) and losing "
        "the whole attempt with no retry -- general, not server-specific. "
        "Fix: retry the attempt once against a fresh subprocess on a "
        "transport-crash classification before giving up on the seed (see "
        "this module's docstring)."
    ),
)
async def test_a_tool_call_that_starts_timed_sends_does_not_crash_the_attempt(
    _toggle_target: target_registry.TargetSpec,
) -> None:
    adapter = MCPStdioAdapter(
        family=FAMILY, scope=None, completion_fn=_tool_call_then_done("toggle_logging")
    )
    # Today: reliably raises AdapterInvocationSkipped(reason=subprocess_crash,
    # exception=BrokenResourceError) -- byte-identical to the field evidence's
    # own "[MYL-NT-002] subprocess_crash on synth-w1-rug-pull:
    # BrokenResourceError()" -- and the seed is gone for the whole scan. The
    # fix should make this line return a normal AdapterResponse instead (a
    # transparent one-shot retry).
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


def test_a_tool_call_that_starts_timed_sends_is_classified_subprocess_crash(
    _toggle_target: target_registry.TargetSpec,
) -> None:
    """Documents today's actual (non-xfail) behaviour precisely: the EXACT
    exception/reason pair the field evidence shows, not an approximation --
    so the xfail test above is read as "no retry exists yet", not "nothing
    is classified" (#319 already gets the label right)."""
    import asyncio

    adapter = MCPStdioAdapter(
        family=FAMILY, scope=None, completion_fn=_tool_call_then_done("toggle_logging")
    )
    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        asyncio.run(adapter.invoke(_PAYLOAD))
    assert excinfo.value.attempt_metadata["reason"] == "subprocess_crash"
    assert excinfo.value.attempt_metadata["exception"] == "BrokenResourceError"
