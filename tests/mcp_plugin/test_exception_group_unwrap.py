"""#319: an exception wrapped in nested ``asyncio.TaskGroup`` groups must be
unwrapped before it is classified.

``asyncio.TaskGroup`` (used by the MCP SDK's own session plumbing, and by any
nested ``TaskGroup`` such as calibration's plant/recall) wraps whatever
escapes it in an ``ExceptionGroup``, one layer per enclosing task group. A
``SeedArmUnavailable`` raised two task groups deep therefore reached
``invoke()``'s catch-all as ``ExceptionGroup(ExceptionGroup(SeedArmUnavailable))``
-- which matched neither the control-flow allowlist (it is a group
CONTAINING a ``SeedArmUnavailable``, not an instance of one) nor named
correctly in ``_classify_failure`` (``type(exc).__name__`` was just
``"ExceptionGroup"``) -- so the designed skip read as a generic
``planner_exception`` with no reason code of its own. The same shape hid a
target/transport crash (a broken pipe / closed connection raised inside the
same task groups) behind the identical "planner_exception" label, which sent
the operator to debug their planner instead of the target.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp._session_adapter import MCPSessionAdapterBase, _unwrap_sole_exception
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.scan._types import AdapterInvocationSkipped, SeedArmUnavailable


class _RaisingSessionCM:
    """A fake ``self._session(...)`` context manager whose ``__aenter__`` raises
    whatever exception the test hands it -- the same shape a real nested
    ``asyncio.TaskGroup`` failure (the MCP SDK's own session setup, or a
    nested task group one layer further in) surfaces as."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def __aenter__(self) -> Any:
        raise self._exc

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class BrokenResourceError(Exception):
    """A LOCAL stand-in for ``anyio.BrokenResourceError``, named identically
    (no leading underscore) so ``type(exc).__name__`` matches what
    ``_classify_failure`` checks for -- that function is name-based, like
    every other branch there, and does not import anyio."""


def _nested_group(leaf: BaseException, depth: int) -> BaseException:
    """``ExceptionGroup("unhandled errors in a TaskGroup", [...])``, nested
    ``depth`` times -- exactly what ``depth`` enclosing ``asyncio.TaskGroup``s
    produce when a single task inside the innermost one raises ``leaf``."""
    exc: BaseException = leaf
    for _ in range(depth):
        exc = ExceptionGroup("unhandled errors in a TaskGroup", [exc])
    return exc


# --- _unwrap_sole_exception, in isolation -----------------------------------


def test_unwrap_passes_through_a_bare_exception() -> None:
    bare = ValueError("boom")
    assert _unwrap_sole_exception(bare) is bare


def test_unwrap_peels_one_layer() -> None:
    leaf = SeedArmUnavailable("no arm")
    group = ExceptionGroup("unhandled errors in a TaskGroup", [leaf])
    assert _unwrap_sole_exception(group) is leaf


def test_unwrap_peels_nested_single_child_groups() -> None:
    leaf = SeedArmUnavailable("no arm")
    group = _nested_group(leaf, depth=2)
    assert _unwrap_sole_exception(group) is leaf


def test_unwrap_leaves_a_multi_child_group_alone() -> None:
    """A group with more than one leaf has no single cause to attribute the
    attempt to -- it must NOT be collapsed to either child."""
    group = ExceptionGroup(
        "unhandled errors in a TaskGroup", [ValueError("a"), SeedArmUnavailable("b")]
    )
    assert _unwrap_sole_exception(group) is group


# --- invoke(): the designed skip survives nested task groups ---------------


@pytest.mark.asyncio
async def test_seed_arm_unavailable_nested_in_task_groups_is_a_designed_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``SeedArmUnavailable`` raised inside nested task groups must still
    propagate as ``SeedArmUnavailable`` -- the designed, undelivered-payload
    skip -- not fall through to the generic ``planner_exception`` catch-all."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    leaf = SeedArmUnavailable("seed_arm tool 'remember' is not among the server's tools")
    monkeypatch.setattr(
        adapter, "_session", lambda **_: _RaisingSessionCM(_nested_group(leaf, depth=2))
    )

    payload = Payload(pattern_id="p", channel="tool-result", body="x")
    with pytest.raises(SeedArmUnavailable) as excinfo:
        await adapter.invoke(payload)
    assert "not among the server's tools" in excinfo.value.reason


@pytest.mark.asyncio
async def test_transport_failure_nested_in_task_groups_reads_as_subprocess_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target/transport crash (a broken pipe, a closed connection) raised
    inside nested task groups must read as a target failure, never as a
    ``planner_exception`` -- that label is reserved for genuine planner/LLM
    errors and sends the operator to debug the wrong thing."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    leaf = BrokenResourceError()
    monkeypatch.setattr(
        adapter, "_session", lambda **_: _RaisingSessionCM(_nested_group(leaf, depth=2))
    )

    payload = Payload(pattern_id="p", channel="tool-result", body="x")

    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(payload)

    assert excinfo.value.attempt_metadata["reason"] == "subprocess_crash"
    assert excinfo.value.attempt_metadata["exception"] == "BrokenResourceError"
    assert "planner_exception" not in excinfo.value.reason
    # Still reported as a skip the engine classes NOT TESTED, never resisted --
    # this test only proves the LABEL changed, not the outcome's severity.


@pytest.mark.asyncio
async def test_a_mixed_exception_group_still_reads_as_planner_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A group that does NOT collapse to one leaf (more than one sub-exception)
    has no single cause to name -- it must keep reading as the generic,
    unclassified ``planner_exception``, exactly as before this fix."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    mixed = ExceptionGroup(
        "unhandled errors in a TaskGroup",
        [ValueError("unrelated"), SeedArmUnavailable("no arm")],
    )
    monkeypatch.setattr(adapter, "_session", lambda **_: _RaisingSessionCM(mixed))

    payload = Payload(pattern_id="p", channel="tool-result", body="x")

    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(payload)

    assert excinfo.value.attempt_metadata["reason"] == "planner_exception"


def test_classify_failure_names_anyio_transport_errors_as_subprocess_crash() -> None:
    assert MCPSessionAdapterBase._classify_failure(BrokenResourceError()) == "subprocess_crash"
