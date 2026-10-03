"""The scaffold writes every tool into target.yaml with its role and that role's source.

The block is comments only, so the file the scan reads is unchanged; the lines
come from the same inventory `mylonite check` prints.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import yaml
from tests.mcp_plugin.fakes.neutral_servers import memory_tools

from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp.scaffold import _render_target_scaffold, _suggest_weakness_classes
from mylonite.plugins._mcp.target_file import TargetFile
from mylonite.scan.tool_inventory import inventory_comment_lines, tool_inventory
from mylonite.scan.tool_roles import _classify_tools


def _render(tools: list[Any]) -> str:
    return _render_target_scaffold(
        tf=SimpleNamespace(family="custom", command="npx", args=[], env={}, scope=None),
        tool_names=[t.name for t in tools],
        suggested_weaknesses=_suggest_weakness_classes(tools),
        system_prompt_file=None,
        roles=_classify_tools(tools),
        tools=tools,
    )


def _tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="send_email", description="Send.", json_schema={"properties": {}}),
        ToolSpec(name="frobnicate_thing", description="Thing.", json_schema={"properties": {}}),
    ]


def test_scaffold_writes_every_tool_with_role_and_source() -> None:
    tools = _tools()
    rendered = _render(tools)
    for line in inventory_comment_lines(tool_inventory(tools)):
        assert line in rendered
    assert "#   send_email: consequential (name)" in rendered
    assert "#   frobnicate_thing: unknown; consequential: yes (fail-closed default)" in rendered
    assert "1 tool(s) have an unknown role" in rendered


def test_inventory_block_leaves_the_parsed_file_unchanged() -> None:
    tools = memory_tools()
    rendered = _render(tools)
    stripped = "\n".join(
        line
        for line in rendered.splitlines()
        if line not in set(inventory_comment_lines(tool_inventory(tools)))
    )
    assert yaml.safe_load(rendered) == yaml.safe_load(stripped)
    TargetFile.model_validate(yaml.safe_load(rendered))


def test_annotated_server_lists_annotation_sources() -> None:
    tools = memory_tools()
    rendered = _render(tools)
    assert "(annotation)" in rendered
    # The inventory lines are plain ASCII, so a cp1252 console can print them.
    "\n".join(inventory_comment_lines(tool_inventory(tools))).encode("ascii")
