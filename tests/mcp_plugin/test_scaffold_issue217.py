"""#217 cause 3 + the verify-args ``{}`` bug, against the real tool surfaces
of the two official reference servers the false-clean bug was found on
(server-memory, server-filesystem — see ``tests/mcp_plugin/fakes/neutral_servers.py``
and ``tests/fixtures/issue217/``).

Two scaffold defects, fixed here (task T14 of
``docs/superpowers/plans/2026-09-30-no-false-clean.md``):

* The scaffold's "Consequential-action tools detected" hint used a SEPARATE,
  weaker name-hint heuristic (``tool_roles._classify_tools().sink_tools``)
  than the one the live W4 control and ``mylonite check`` actually use
  (``control_shim.consequential_tool_names``). The two disagreed — on
  server-filesystem the hint found NOTHING, on server-memory it missed half
  the real consequential tools — so a first-time user copying the hint into
  ``control_config.consequential_tools`` under-declared what the runtime
  would gate. The scaffold must show the SAME list ``scan``/``check`` use.
* The scaffold's effect-probe example hard-coded ``verify_args_template: {}``,
  which a first-time user carries into a real verify tool that requires
  arguments (e.g. ``read_text_file(path)``, ``search_nodes(query)``) — the
  verify call then errors before it can confirm anything (#217). The
  scaffold must instead emit the verify tool's OWN required arguments,
  stubbed to a schema-valid placeholder.

These tests do not assert a scan verdict (that needs T7's judge fix and
lands with T13's integration test) — only that the scaffold's two outputs
are internally consistent with what the runtime actually does.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from tests.mcp_plugin.fakes.neutral_servers import filesystem_tools, memory_tools

from mylonite.plugins._mcp import calibration
from mylonite.plugins._mcp.scaffold import _render_target_scaffold, _verify_args_stub
from mylonite.scan.control_shim import consequential_tool_names
from mylonite.scan.tool_roles import _classify_tools


def _fake_tf(*, family: str, command: str, args: list[str]) -> Any:
    """A minimal stand-in for the ``TargetFile`` fields ``_render_target_scaffold``
    reads (``family``/``command``/``args``/``env``/``scope``) — a real
    ``TargetFile`` works too, but its extra validation is irrelevant here."""
    from types import SimpleNamespace

    return SimpleNamespace(family=family, command=command, args=args, env={}, scope=None)


def _render(tools: list[Any], *, command: str, args: list[str]) -> str:
    roles = _classify_tools(tools)
    return _render_target_scaffold(
        tf=_fake_tf(family="custom", command=command, args=args),
        tool_names=[t.name for t in tools],
        suggested_weaknesses=["W4"],
        system_prompt_file=None,
        roles=roles,
        tools=tools,
    )


def _hinted_consequential_tools(rendered: str) -> list[str]:
    """Parse the scaffold's own "Consequential-action tools detected" line."""
    m = re.search(r"Consequential-action tools detected \(W4 candidates\): (.+)\.\n", rendered)
    assert m is not None, rendered
    if m.group(1).strip() == "":
        return []
    return [name.strip() for name in m.group(1).split(",")]


@pytest.mark.parametrize(
    "server_tools",
    [memory_tools(), filesystem_tools()],
    ids=["server-memory", "server-filesystem"],
)
def test_scaffold_consequential_hint_matches_runtime_list(server_tools: list[Any]) -> None:
    """The scaffold's hint and the runtime classifier must name the exact same
    tools, in the exact same order — #217 cause 3. Before the fix this failed
    outright for server-filesystem (the old heuristic hint found none of the
    four real consequential tools) and under-reported for server-memory."""
    rendered = _render(server_tools, command="npx", args=["-y", "@modelcontextprotocol/x"])
    hinted = _hinted_consequential_tools(rendered)
    runtime = [name for name, _reason in consequential_tool_names(server_tools)]
    assert hinted == runtime
    assert hinted  # both servers have at least one consequential tool


def test_scaffold_consequential_hint_was_wrong_on_the_old_sink_tools_heuristic() -> None:
    """Pin the regression: the OLD source for the hint (``_classify_tools``'s
    name-hint ``sink_tools``) genuinely disagreed with the runtime classifier
    on these exact servers — this is why #217 cause 3 was real, not
    hypothetical."""
    fs_roles = _classify_tools(filesystem_tools())
    mem_roles = _classify_tools(memory_tools())
    fs_runtime = {name for name, _reason in consequential_tool_names(filesystem_tools())}
    mem_runtime = {name for name, _reason in consequential_tool_names(memory_tools())}

    assert set(fs_roles.sink_tools) != fs_runtime
    assert set(fs_roles.sink_tools) == set()  # the old hint found NOTHING
    assert fs_runtime == {"write_file", "edit_file", "create_directory", "move_file"}

    assert set(mem_roles.sink_tools) != mem_runtime
    assert set(mem_roles.sink_tools) < mem_runtime  # the old hint under-reported
    assert mem_runtime == {
        "create_entities",
        "create_relations",
        "add_observations",
        "delete_entities",
        "delete_observations",
        "delete_relations",
    }


@pytest.mark.parametrize(
    ("server_tools", "verify_tool_name"),
    [(memory_tools(), "search_nodes"), (filesystem_tools(), "read_text_file")],
    ids=["server-memory:search_nodes", "server-filesystem:read_text_file"],
)
def test_verify_args_stub_validates_against_the_tools_own_schema(
    server_tools: list[Any], verify_tool_name: str
) -> None:
    """``_verify_args_stub`` must emit an args dict the verify tool's OWN
    schema accepts — the T6 calibration validator (``calibration.validate_args``)
    is the same check a live calibration run applies to a declared
    ``verify_args_template``."""
    tool = next(t for t in server_tools if t.name == verify_tool_name)
    stub = _verify_args_stub(tool)

    # Both real verify tools here require at least one argument, so a stub
    # that is trivially `{}` would not exercise anything.
    assert stub != {}
    assert calibration.validate_args(tool.json_schema, stub) == []

    # The bug this replaces: `{}` against a tool with required args does NOT
    # validate — this is exactly what made the effect probe's verify call
    # error (#217).
    assert calibration.validate_args(tool.json_schema, {}) != []


@pytest.mark.parametrize(
    ("server_tools", "command", "args", "verify_tool_name"),
    [
        (memory_tools(), "npx", ["-y", "@modelcontextprotocol/server-memory"], "search_nodes"),
        (
            filesystem_tools(),
            "npx",
            ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/sandbox"],
            "read_text_file",
        ),
    ],
    ids=["server-memory", "server-filesystem"],
)
def test_rendered_verify_args_template_is_never_bare_empty_for_a_tool_with_required_args(
    server_tools: list[Any], command: str, args: list[str], verify_tool_name: str
) -> None:
    """End-to-end through the actual rendered YAML text: when the scaffold's
    OWN auto-detected verify_tool (or, absent one, a hand-substituted tool —
    exercised via ``_verify_args_stub`` directly above) requires arguments,
    the rendered ``verify_args_template`` line is not the bare ``{}`` that
    silently breaks the verify call."""
    roles = _classify_tools(server_tools)
    by_name = {t.name: t for t in server_tools}
    # Force the role onto the specific verify tool under test so the assertion
    # is meaningful regardless of what the name-hint auto-detection happened
    # to pick for this particular surface.
    roles = roles._replace(verify_tool=verify_tool_name)
    rendered = _render_target_scaffold(
        tf=_fake_tf(family="custom", command=command, args=args),
        tool_names=[t.name for t in server_tools],
        suggested_weaknesses=["W4"],
        system_prompt_file=None,
        roles=roles,
        tools=server_tools,
    )
    m = re.search(r"verify_args_template: (\{.*\})\n", rendered)
    assert m is not None, rendered
    assert m.group(1) != "{}"

    import yaml

    rendered_args = yaml.safe_load(m.group(1))
    assert calibration.validate_args(by_name[verify_tool_name].json_schema, rendered_args) == []
