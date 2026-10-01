"""A failed mid-session re-list must never read as a stable tool surface.

After the planner runs, the session adapter lists the tools again and diffs
them against what the planner first saw, to catch a server that swaps its tool
descriptions mid-session. When that second listing raises, nothing was
compared, so the attempt must come out inconclusive (NOT TESTED under its own
reason code), never as a confident "the surface was stable".
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool

from mylonite import reason_codes
from mylonite.contracts import Payload
from mylonite.contracts._types import AdapterResponse, ScanAttempt
from mylonite.plugins._mcp import stdio_adapter, target_registry
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
from mylonite.scan import coverage
from mylonite.scan.predicates import lookup_predicate

FAMILY = "relist-app"


class _Session:
    """A fake ``mcp.ClientSession`` whose tool listing fails after ``ok_lists`` calls."""

    def __init__(
        self, *, ok_lists: int | None, hang: bool = False, stuck_cursor: bool = False
    ) -> None:
        self.ok_lists = ok_lists
        self.hang = hang
        #: Every page hands back the same cursor, so the listing stops early.
        self.stuck_cursor = stuck_cursor
        self.list_calls = 0

    async def initialize(self) -> None:
        return None

    async def list_tools(self, *args: Any, **kwargs: Any) -> Any:
        self.list_calls += 1
        if self.ok_lists is not None and self.list_calls > self.ok_lists:
            if self.hang:
                await asyncio.sleep(30)
            raise RuntimeError("server went away")
        return SimpleNamespace(
            tools=[MCPTool(name="get_weather", description="weather", inputSchema={})],
            nextCursor="again" if self.stuck_cursor else None,
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)


def _launcher(session: _Session) -> Any:
    def _open(*args: Any, **kwargs: Any) -> Any:
        @asynccontextmanager
        async def _ctx() -> Any:
            yield session

        return _ctx()

    return _open


async def _done(**kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
    )


@pytest.fixture(autouse=True)
def _registered() -> Iterator[None]:
    target_registry.clear_runtime_targets()
    target_registry.register_target(
        build_target_spec(
            TargetFile(
                family=FAMILY,
                command="python",
                args=["-m", "srv"],
                weakness_classes=["W1"],
            )
        )
    )
    yield
    target_registry.clear_runtime_targets()


async def _invoke(session: _Session, **adapter_kwargs: Any) -> dict[str, str]:
    payload = Payload(
        pattern_id="relist",
        channel="user-message",
        body="what is the weather",
        metadata={"setup": "no_setup", "drive": "unknown", "seed_id": "relist"},
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _launcher(session))
        adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_done, **adapter_kwargs)
        response = await adapter.invoke(payload)
    return dict(response.metadata)


def _verdict_for(metadata: dict[str, str]) -> Any:
    fn = lookup_predicate("tool_surface_mutated_mid_session")
    payload = Payload(pattern_id="synth-w1", channel="user-message", body="x")
    response = AdapterResponse(
        payload_pattern_id="x", raw_response="", tool_calls=[], metadata=metadata
    )
    return fn(payload, response)


@pytest.mark.asyncio
async def test_a_failed_relist_is_stamped_errored_not_stable() -> None:
    session = _Session(ok_lists=1)
    meta = await _invoke(session)
    assert session.list_calls == 2
    assert meta["tool_surface_mutated"] == "errored"


@pytest.mark.asyncio
async def test_a_failed_relist_reads_as_inconclusive_never_clean() -> None:
    meta = await _invoke(_Session(ok_lists=1))
    verdict = _verdict_for(meta)
    assert verdict is not None
    assert verdict.success is False
    assert verdict.fallback_cause == reason_codes.INC_RELIST_FAILED

    attempt = ScanAttempt(
        seed_id="relist",
        pattern_id="relist",
        outcome="undecided",
        verdict_mechanism="predicate",
        verdict_reason=verdict.reason,
        judge_evidence={k: str(v) for k, v in verdict.evidence.items()},
    )
    assert coverage.attempt_reached_no_verdict(attempt)
    assert coverage.reason_code_for_attempt(attempt) == reason_codes.INC_RELIST_FAILED
    assert reason_codes.get(reason_codes.INC_RELIST_FAILED).category == (
        reason_codes.CATEGORY_INCONCLUSIVE
    )


@pytest.mark.asyncio
async def test_a_stable_relist_still_reads_as_resisted() -> None:
    meta = await _invoke(_Session(ok_lists=None))
    assert meta["tool_surface_mutated"] == "false"
    verdict = _verdict_for(meta)
    assert verdict is not None and verdict.success is False
    assert verdict.fallback_cause is None


def test_an_unknown_marker_is_inconclusive_too() -> None:
    verdict = _verdict_for({"tool_surface_mutated": "maybe"})
    assert verdict is not None
    assert verdict.fallback_cause == reason_codes.INC_RELIST_FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timeouts",
    [
        {"planner_timeout_s": 0.5},  # the whole re-list is bounded
        {"mcp_read_timeout_s": 0.3},  # and so is each page
    ],
)
async def test_a_relist_that_hangs_times_out_and_reads_errored(timeouts: dict[str, float]) -> None:
    meta = await _invoke(_Session(ok_lists=1, hang=True), **timeouts)
    assert meta["tool_surface_mutated"] == "errored"


@pytest.mark.asyncio
async def test_a_partial_tool_list_is_stamped_on_the_response() -> None:
    meta = await _invoke(_Session(ok_lists=None, stuck_cursor=True))
    assert meta["tool_list_truncated"] == "true"


@pytest.mark.asyncio
async def test_a_complete_tool_list_is_not_stamped() -> None:
    meta = await _invoke(_Session(ok_lists=None))
    assert "tool_list_truncated" not in meta
