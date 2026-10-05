"""A server notification that arrives while Mylonite closes an MCP session
must not fail an attempt whose calls all returned.

Field evidence: against a stdio server whose tools can turn on timed
notifications (simulated logging, resource-subscription updates), 4 of 6
runs skipped an attempt as ``[MYL-NT-002] subprocess_crash ...:
BrokenResourceError()`` although the server never died.

Mechanism: the SDK transport (``stdio_client``) and ``ClientSession`` are
two separate context managers that do not close together.
``ClientSession`` closes its end of the read stream first; the transport's
``stdout_reader`` task is torn down a little later. A message the server
writes in that gap makes ``read_stream_writer.send(...)`` raise
``anyio.BrokenResourceError`` out of the transport's exit. A timer started by
a tool call mid-session fires its first tick right as the attempt finishes,
so it lands in the gap reliably; a timer running from process start rarely
does (kept below as two negative repros).

The fix (``_session_adapter._open_client_session``) is structural: a
closed-stream error raised only after the attempt's own body returned is a
clean close. One raised while a call is still in flight still propagates
and is still classified ``subprocess_crash``. A retry was rejected: it would
re-run the attack and hide the defect.
"""

from __future__ import annotations

import dataclasses
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import anyio
import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp import stdio_adapter, target_registry
from mylonite.plugins._mcp._session_adapter import (
    MCPSessionAdapterBase,
    _MCPAttackSession,
    _only_closed_stream_errors,
    _open_client_session,
    _unwrap_sole_exception,
)
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
async def test_a_tool_call_that_starts_timed_sends_does_not_crash_the_attempt(
    _toggle_target: target_registry.TargetSpec,
) -> None:
    adapter = MCPStdioAdapter(
        family=FAMILY, scope=None, completion_fn=_tool_call_then_done("toggle_logging")
    )
    # Before the fix this reliably raised AdapterInvocationSkipped
    # (subprocess_crash, BrokenResourceError) and the seed was lost.
    response = await adapter.invoke(_PAYLOAD)
    assert response.payload_pattern_id == "synth-w1-rug-pull"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["log", "resource"])
async def test_each_notification_shape_started_by_a_tool_call_leaves_the_attempt_intact(
    kind: str,
) -> None:
    """A logging message and a resource-updated push both race the close the
    same way; neither may cost the attempt."""
    _register(
        {
            "MYLONITE_TEST_TOGGLE_STARTS_NOTIFY": "1",
            "MYLONITE_TEST_NOTIFY_INTERVAL_S": "0.0",
            "MYLONITE_TEST_NOTIFY_LINGER_S": "1.0",
            "MYLONITE_TEST_NOTIFY_KIND": kind,
        }
    )
    try:
        adapter = MCPStdioAdapter(
            family=FAMILY, scope=None, completion_fn=_tool_call_then_done("toggle_logging")
        )
        response = await adapter.invoke(_PAYLOAD)
    finally:
        target_registry.clear_runtime_targets()
    assert response.payload_pattern_id == "synth-w1-rug-pull"


@pytest.mark.asyncio
async def test_a_notification_written_while_the_client_closes_leaves_the_attempt_intact() -> None:
    """The server writes one notification the moment the client closes its
    stdin, i.e. inside the client's own teardown."""
    _register({"MYLONITE_TEST_NOTIFY_ON_EOF": "1", "MYLONITE_TEST_NOTIFY_LINGER_S": "0"})
    try:
        adapter = MCPStdioAdapter(
            family=FAMILY, scope=None, completion_fn=_tool_call_then_done("ping")
        )
        response = await adapter.invoke(_PAYLOAD)
    finally:
        target_registry.clear_runtime_targets()
    assert response.payload_pattern_id == "synth-w1-rug-pull"


@pytest.mark.asyncio
async def test_a_server_that_sends_no_notifications_is_unchanged() -> None:
    _register({"MYLONITE_TEST_TOGGLE_STARTS_NOTIFY": "0", "MYLONITE_TEST_NOTIFY_LINGER_S": "0"})
    try:
        adapter = MCPStdioAdapter(
            family=FAMILY, scope=None, completion_fn=_tool_call_then_done("ping")
        )
        response = await adapter.invoke(_PAYLOAD)
    finally:
        target_registry.clear_runtime_targets()
    assert response.payload_pattern_id == "synth-w1-rug-pull"
    assert "ping" in response.tool_calls


@pytest.mark.asyncio
async def test_a_server_that_dies_mid_call_still_skips_the_attempt() -> None:
    """The teardown rule must not swallow a real crash: the server exits
    while answering the planner's tool call."""
    _register({"MYLONITE_TEST_CRASH_ON_CALL_TOOL": "1", "MYLONITE_TEST_NOTIFY_LINGER_S": "0"})
    try:
        adapter = MCPStdioAdapter(
            family=FAMILY, scope=None, completion_fn=_tool_call_then_done("ping")
        )
        with pytest.raises(AdapterInvocationSkipped):
            await adapter.invoke(_PAYLOAD)
    finally:
        target_registry.clear_runtime_targets()


# --- The rule itself, on a fake transport -----------------------------------


class _FakeSession:
    """Stands in for ``ClientSession``; optionally sets ``on_exit`` and yields
    to the loop while closing, the way the real one does."""

    def __init__(self, on_exit: anyio.Event | None = None) -> None:
        self._on_exit = on_exit

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._on_exit is not None:
            self._on_exit.set()
            await anyio.sleep(0.05)

    async def initialize(self) -> None:
        return None


def _transport_whose_reader_breaks(fire: anyio.Event, error: BaseException) -> Any:
    """A transport whose background reader raises ``error`` once ``fire`` is
    set -- the SDK's ``stdout_reader`` forwarding into a closed stream."""

    @asynccontextmanager
    async def _transport() -> AsyncIterator[tuple[None, None]]:
        async def _reader() -> None:
            await fire.wait()
            raise error

        async with anyio.create_task_group() as tg:
            tg.start_soon(_reader)
            yield (None, None)
            await anyio.sleep(0.05)  # the transport's own close takes a moment
            tg.cancel_scope.cancel()

    return _transport()


@pytest.mark.asyncio
async def test_a_closed_stream_error_during_teardown_is_a_clean_close() -> None:
    fire = anyio.Event()
    async with _open_client_session(
        _transport_whose_reader_breaks(fire, anyio.BrokenResourceError()),
        lambda r, w: _FakeSession(on_exit=fire),
    ):
        pass


@pytest.mark.asyncio
async def test_a_closed_stream_error_while_a_call_is_in_flight_is_still_a_crash() -> None:
    fire = anyio.Event()
    with pytest.raises(BaseException) as excinfo:
        async with _open_client_session(
            _transport_whose_reader_breaks(fire, anyio.BrokenResourceError()),
            lambda r, w: _FakeSession(),
        ):
            fire.set()
            await anyio.sleep(5)  # a call still awaiting its reply
    leaf = _unwrap_sole_exception(excinfo.value)
    assert isinstance(leaf, anyio.BrokenResourceError)
    assert MCPSessionAdapterBase._classify_failure(leaf) == "subprocess_crash"


@pytest.mark.asyncio
async def test_a_different_error_during_teardown_still_propagates() -> None:
    fire = anyio.Event()
    with pytest.raises(BaseException) as excinfo:
        async with _open_client_session(
            _transport_whose_reader_breaks(fire, BrokenPipeError()),
            lambda r, w: _FakeSession(on_exit=fire),
        ):
            pass
    assert isinstance(_unwrap_sole_exception(excinfo.value), BrokenPipeError)


@pytest.mark.asyncio
async def test_an_error_from_the_body_itself_is_never_swallowed() -> None:
    fire = anyio.Event()
    with pytest.raises(BaseException) as excinfo:
        async with _open_client_session(
            _transport_whose_reader_breaks(fire, anyio.BrokenResourceError()),
            lambda r, w: _FakeSession(),
        ):
            raise anyio.BrokenResourceError
    assert isinstance(_unwrap_sole_exception(excinfo.value), anyio.BrokenResourceError)


@pytest.mark.asyncio
async def test_end_of_stream_during_teardown_is_a_clean_close() -> None:
    fire = anyio.Event()
    async with _open_client_session(
        _transport_whose_reader_breaks(fire, anyio.EndOfStream()),
        lambda r, w: _FakeSession(on_exit=fire),
    ):
        pass


@pytest.mark.asyncio
async def test_end_of_stream_while_a_call_is_in_flight_is_still_a_crash() -> None:
    fire = anyio.Event()
    with pytest.raises(BaseException) as excinfo:
        async with _open_client_session(
            _transport_whose_reader_breaks(fire, anyio.EndOfStream()),
            lambda r, w: _FakeSession(),
        ):
            fire.set()
            await anyio.sleep(5)
    leaf = _unwrap_sole_exception(excinfo.value)
    assert isinstance(leaf, anyio.EndOfStream)
    assert MCPSessionAdapterBase._classify_failure(leaf) == "subprocess_crash"


# --- The stateful attack session (opened, used and closed by hand) ---------


class _SessionWhoseCallBreaks(_FakeSession):
    """A session whose tool call fails as a dead transport does."""

    async def call_tool(self, name: str, arguments: Any) -> Any:
        raise anyio.BrokenResourceError


class _UnboundedAdapter:
    async def _bounded(self, coro: Any) -> Any:
        return await coro

    _completion_fn = None


async def _attack_session(fire: anyio.Event) -> _MCPAttackSession:
    cm = _open_client_session(
        _transport_whose_reader_breaks(fire, anyio.BrokenResourceError()),
        lambda r, w: _SessionWhoseCallBreaks(on_exit=fire),
    )
    session = await cm.__aenter__()
    return _MCPAttackSession(cast(Any, _UnboundedAdapter()), cm, session)


@pytest.mark.asyncio
async def test_closing_an_attack_session_whose_call_failed_is_not_a_clean_close() -> None:
    """``close()`` must not tell the opener the body returned normally when a
    call in this session already failed: the teardown race then surfaces
    instead of being swallowed."""
    fire = anyio.Event()
    attack = await _attack_session(fire)
    with pytest.raises(anyio.BrokenResourceError):
        await attack.call_tool("ping", {})
    with pytest.raises(BaseException) as excinfo:
        await attack.close()
    assert _only_closed_stream_errors(excinfo.value)


@pytest.mark.asyncio
async def test_closing_an_attack_session_whose_work_succeeded_is_a_clean_close() -> None:
    fire = anyio.Event()
    attack = await _attack_session(fire)
    await attack.close()
