"""MYL-NT-002 root cause: a target subprocess that dies mid-attempt (a
background-timer notification is one way this happens) loses the WHOLE
attempt with no retry, misattributed as third-party flakiness.

Field evidence (the official "everything" reference server, Node stdio): 4
of 6 third-party runs skip ``synth-w1-rug-pull`` as
``[MYL-NT-002] subprocess_crash on synth-w1-rug-pull: BrokenResourceError()``,
and the Node process then prints ``write EPIPE`` from
``listOnTimeout -> StdioServerTransport.send`` -- its own logging-notification
timer writing into a pipe that is already gone. "Third-party target
flakiness" was the published (unverified) cause.

Three repro attempts against a small Python stdio server
(``tests/integration/_notifying_mcp_server.py``), using the real ``mcp`` SDK
+ a fake (offline) planner completion, through ``MCPStdioAdapter.invoke()``
directly (the same code path ``scan``'s rug-pull probe drives):

1. **Periodic timer, natural overlap** (notification every 0.1s, server
   lingers 1.0s past ``Server.run()`` returning, same shape as the Node
   server's ``setInterval``) -- does NOT reproduce. The attempt completes
   cleanly; ``mcp.ClientSession``'s own close does not race
   ``stdio_client``'s background ``stdout_reader`` task the way a naive
   reading of the teardown code suggests it might.
2. **One notification synchronized to the exact close instant** (an extra
   ``session.send_ping()`` right as ``self._session(...)`` starts to exit)
   -- also does NOT reproduce, for the same reason.
3. **The server process dying mid-attempt** (deterministic: ``call_tool``
   hard-exits instead of answering) -- DOES reproduce: ``invoke()`` raises
   ``AdapterInvocationSkipped`` (here classified ``mcp_protocol_error`` --
   a dead process with a request in flight surfaces as
   ``McpError('Connection closed')`` rather than the field evidence's raw
   ``anyio.BrokenResourceError`` / ``subprocess_crash``, because the crash
   lands at a different point in the request lifecycle; both reach the
   SAME catch-all in ``_session_adapter.py`` and are both unretried), and
   NOTHING about the attempt is retried or salvaged, even though the crash
   has nothing to do with what was being tested.

Read together: the Python MCP client is not provably buggy about
notification-vs-teardown races (1 and 2 could not land it), so the Node
server's uncaught 'error' event on its own stdout write is a defect in that
transport, not evidence of a Mylonite race condition. But (3) is the
PORTABLE, Mylonite-side half of the bug the field evidence actually needs
fixed: a server that pushes unsolicited notifications on its own schedule is
measurably more likely to self-crash this way (an EventEmitter-unhandled-
error footgun common to Node MCP servers, not unique to this one) at some
UNPREDICTABLE point in an attempt's lifetime -- and whenever that happens,
Mylonite today loses the entire seed for the whole scan with no retry,
labelled with a generic reason that sends the operator to re-run the whole
scan rather than "the target process died mid-probe, once."

Verdict: MYLONITE for the missing-resilience half (general, not
server-specific: any stdio target whose subprocess dies mid-attempt, from
any cause, permanently loses that seed for the run). The Node-side 'error'
handling is a separate, target-side defect this task does not fix.

General fix (not implemented here; see this module's docstring and the task
report): on a transport-crash classification (``subprocess_crash`` /
``init_failure`` / ``mcp_protocol_error``) for an attempt whose planner had
not yet produced a result, retry the attempt once against a FRESH
subprocess before giving up -- the same one-shot retry shape other
transient-failure paths in this codebase already use (e.g. the provider
``rate_limit`` retry noted in ``_classify_failure``'s own docstring)
-- and only report the seed NOT TESTED if the retry also fails to produce a
result.
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


async def _call_ping_then_done(**kwargs: Any) -> SimpleNamespace:
    """Call ``ping`` once, then finish -- for the crash-on-call-tool variant."""
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
                                function=SimpleNamespace(name="ping", arguments="{}"),
                            )
                        ],
                    )
                )
            ]
        )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
    )


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
    a periodic timer (every 0.1s) that lingers 1.0s past ``Server.run()``
    returning -- the same shape as the Node server's ``setInterval``-driven
    logging notification.

    The env vars reach the child through ``TargetSpec.extra_env`` -- the
    SAME documented mechanism a custom target file's ``env:`` block uses
    (``_compose_child_env`` only inherits a narrow OS-plumbing allowlist
    from the parent otherwise, DCR-0012).
    """
    yield _register(
        {
            "MYLONITE_TEST_NOTIFY_INTERVAL_S": "0.1",
            "MYLONITE_TEST_NOTIFY_LINGER_S": "1.0",
        }
    )
    target_registry.clear_runtime_targets()


@pytest.fixture
def _crashing_target() -> Iterator[target_registry.TargetSpec]:
    """Registers ``FAMILY`` against a server whose ``call_tool`` hard-exits
    the moment it is invoked -- deterministically modeling a mid-attempt
    process death from any cause (a timer-notification race is one;
    unrelated request-handling bugs are others)."""
    yield _register({"MYLONITE_TEST_CRASH_ON_CALL_TOOL": "1"})
    target_registry.clear_runtime_targets()


# --- Repro 1: periodic timer, natural overlap with teardown -----------------


@pytest.mark.asyncio
async def test_a_periodic_notification_timer_does_not_crash_the_attempt(
    _notifying_target: target_registry.TargetSpec,
) -> None:
    """Negative result: the Python client tolerates a server that keeps
    pushing notifications for a full second after the attempt finished."""
    adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_one_shot_done)
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


# --- Repro 2: one notification synchronized to the close instant ------------


@pytest.mark.asyncio
async def test_a_notification_at_the_close_instant_does_not_crash_the_attempt(
    _notifying_target: target_registry.TargetSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Narrower variant: one extra unsolicited write synchronized to exactly
    the moment ``self._session(...)`` starts to exit, instead of relying on
    a periodic timer's natural overlap. Also a negative result."""
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


# --- Repro 3: the subprocess dies mid-attempt -- THIS reproduces ------------


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason=(
        "MYL-NT-002: a target subprocess that dies mid-attempt (a "
        "background-notification-timer race is one cause; this test forces "
        "it deterministically via a different one) loses the WHOLE attempt "
        "with no retry -- general, not server-specific. Fix: retry a "
        "transport-crash classification once against a fresh subprocess "
        "before giving up on the seed (see this module's docstring)."
    ),
)
async def test_a_subprocess_death_mid_attempt_is_retried_not_lost(
    _crashing_target: target_registry.TargetSpec,
) -> None:
    adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_call_ping_then_done)
    # Today: raises AdapterInvocationSkipped(reason=subprocess_crash) and the
    # seed is gone for the whole scan. The fix should make this line return a
    # normal AdapterResponse instead (a transparent one-shot retry).
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


def test_a_subprocess_death_mid_attempt_is_classified_and_skipped(
    _crashing_target: target_registry.TargetSpec,
) -> None:
    """Documents today's actual (non-xfail) behaviour precisely, so the
    xfail test above is read as "no retry exists yet", not "nothing is
    classified". This particular crash shape (the subprocess dies with no
    reply mid-request) surfaces as ``McpError('Connection closed')`` ->
    ``mcp_protocol_error``, not ``subprocess_crash`` -- a different exact
    exception/reason than the field evidence's raw
    ``anyio.BrokenResourceError`` -> ``subprocess_crash``, because the two
    tests kill the process at a different point in the request lifecycle.
    Both land in ``MCPSessionAdapterBase.invoke``'s SAME catch-all
    (``_session_adapter.py``), are correctly labelled (#319), and are
    skipped with zero retry either way -- that structural gap, not the
    exact label, is what this task's fix targets.
    """
    import asyncio

    adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_call_ping_then_done)
    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        asyncio.run(adapter.invoke(_PAYLOAD))
    assert excinfo.value.attempt_metadata["reason"] in {
        "subprocess_crash",
        "mcp_protocol_error",
        "init_failure",
    }
