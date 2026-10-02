"""The scaffold names a readback tool as the effect_probe candidate when the
surface has one.

server-memory has no tool whose name reads like an outbox or a status report,
so the scaffold used to print "no side-effect-reporting tool auto-detected" even
though ``read_graph`` reads the whole store back. A first W4 scan then ran with
no probe. A readback that needs no argument is now written as a live
effect_probe (see test_scaffold_live_blocks.py).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import yaml
from tests.mcp_plugin.fakes.neutral_servers import filesystem_tools, memory_tools

from mylonite.plugins._mcp.scaffold import _render_target_scaffold
from mylonite.plugins._mcp.target_file import TargetFile
from mylonite.scan.tool_roles import _classify_tools


def _tool(name: str, required: list[str], read_only: bool | None = None) -> SimpleNamespace:
    props = {r: {"type": "string"} for r in required}
    annotations = {} if read_only is None else {"readOnlyHint": read_only}
    return SimpleNamespace(
        name=name,
        description="",
        json_schema={"type": "object", "properties": props, "required": required},
        annotations=annotations,
    )


def _render(tools: list[Any]) -> str:
    return _render_target_scaffold(
        tf=SimpleNamespace(family="custom", command="npx", args=[], env={}, scope=None),
        tool_names=[t.name for t in tools],
        suggested_weaknesses=["W2", "W4"],
        system_prompt_file=None,
        roles=_classify_tools(tools),
        tools=tools,
    )


def test_memory_server_gets_read_graph_as_the_verify_candidate() -> None:
    assert _classify_tools(memory_tools()).verify_tool == "read_graph"


def test_an_observe_named_tool_still_wins_over_the_readback_fallback() -> None:
    assert _classify_tools(filesystem_tools()).verify_tool == "list_directory"


def test_readback_fallback_prefers_a_tool_with_no_required_arguments() -> None:
    tools = [
        _tool("send_message", ["to", "body"]),
        _tool("search_messages", ["query"]),
        _tool("read_mailbox", []),
    ]
    assert _classify_tools(tools).verify_tool == "read_mailbox"


def test_readback_fallback_skips_a_read_that_needs_an_id() -> None:
    tools = [_tool("send_message", ["to", "body"]), _tool("read_message", ["message_id"])]
    assert _classify_tools(tools).verify_tool is None


def test_readback_fallback_never_picks_a_tool_marked_not_read_only() -> None:
    tools = [_tool("send_message", ["to", "body"]), _tool("read_and_archive", [], read_only=False)]
    assert _classify_tools(tools).verify_tool is None


def test_readback_fallback_never_picks_a_tool_whose_name_writes() -> None:
    """The probe calls verify_tool before and after every attempt, so a write
    picked here would run over and over. A read verb in the name is not enough."""
    writes = [
        _tool("execute_query", []),
        _tool("search_and_delete", []),
        _tool("open_pull_request", []),
        _tool("get_or_create_user", []),
    ]
    assert _classify_tools(writes).verify_tool is None
    # A real readback after them still wins, whatever the listing order.
    assert _classify_tools([*writes, _tool("read_graph", [])]).verify_tool == "read_graph"


def test_readback_fallback_ignores_a_read_only_claim_on_a_write_name() -> None:
    tools = [_tool("send_message", ["to", "body"]), _tool("delete_all", [], read_only=True)]
    assert _classify_tools(tools).verify_tool is None


def test_scaffold_writes_a_no_argument_readback_as_a_live_probe() -> None:
    rendered = _render(memory_tools())
    assert "# auto-detected: read_graph reads the target's state back." in rendered
    loaded = TargetFile.model_validate(yaml.safe_load(rendered))
    assert loaded.effect_probe is not None
    assert loaded.effect_probe.verify_tool == "read_graph"
