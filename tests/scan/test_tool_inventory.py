"""The static tool inventory: every tool's role and the source of that role.

The inventory must agree with what the live boundary controls decide, so the
parity tests below run the real controls over the same tools.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts import ToolSpec
from mylonite.scan.control_shim import make_control
from mylonite.scan.tool_inventory import (
    InventoryEntry,
    inventory_comment_lines,
    role_text,
    tool_inventory,
    treated_as_text,
)


def _tool(name: str, props: dict[str, Any] | None = None, **ann: Any) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=f"{name} tool",
        json_schema={"properties": props or {}},
        annotations=ann or None,
    )


def _by_name(entries: list[InventoryEntry]) -> dict[str, InventoryEntry]:
    return {e.name: e for e in entries}


def _roles(entry: InventoryEntry) -> dict[str, str]:
    return {r.role: r.source for r in entry.roles}


def test_name_hint_roles_carry_the_name_source() -> None:
    inv = _by_name(
        tool_inventory(
            [
                _tool("send_email", {"to": {"type": "string"}}),
                _tool("list_notes"),
            ]
        )
    )
    assert _roles(inv["send_email"])["consequential"] == "name"
    assert inv["send_email"].consequential is True
    assert inv["send_email"].consequential_source == "name"
    assert _roles(inv["list_notes"])["read"] == "name"
    assert not inv["list_notes"].unknown


def test_an_unrecognised_tool_is_unknown_and_counts_as_consequential() -> None:
    inv = _by_name(tool_inventory([_tool("frobnicate_thing")]))
    entry = inv["frobnicate_thing"]
    assert entry.roles == ()
    assert entry.unknown
    assert entry.consequential is True
    assert entry.consequential_source == "unknown"
    assert role_text(entry) == "unknown"
    assert "fail-closed" in treated_as_text(entry)


def test_annotations_are_the_source_when_the_server_declares_them() -> None:
    inv = _by_name(
        tool_inventory(
            [
                _tool("frobnicate_thing", readOnlyHint=True),
                _tool("zap_widget", readOnlyHint=False, destructiveHint=True),
                _tool("reach_out", openWorldHint=True, readOnlyHint=True),
            ]
        )
    )
    reader = inv["frobnicate_thing"]
    assert _roles(reader) == {"read": "annotation"}
    assert reader.consequential is False
    assert reader.consequential_source == "annotation"
    assert _roles(inv["zap_widget"])["consequential"] == "annotation"
    assert _roles(inv["reach_out"])["egress"] == "annotation"


def test_a_destination_parameter_is_schema_evidence_for_egress() -> None:
    inv = _by_name(tool_inventory([_tool("notify", {"webhook_url": {"type": "string"}})]))
    assert _roles(inv["notify"])["egress"] == "schema"


def test_declared_lists_win_and_a_declared_exclusion_is_not_unknown() -> None:
    cc = SimpleNamespace(
        consequential_tools=["frobnicate_thing"],
        egress_tools=[],
        read_tool_names=[],
    )
    inv = _by_name(
        tool_inventory([_tool("frobnicate_thing"), _tool("other_thing")], control_config=cc)
    )
    assert _roles(inv["frobnicate_thing"])["consequential"] == "declared"
    other = inv["other_thing"]
    assert other.consequential is False
    assert other.consequential_source == "declared"
    assert not other.unknown
    assert "declared" in role_text(other)


def test_store_and_recall_come_from_the_scan_auto_wire_classifier() -> None:
    inv = _by_name(
        tool_inventory(
            [
                _tool("save_note", {"content": {"type": "string"}}),
                _tool("recall_notes"),
            ]
        )
    )
    assert _roles(inv["save_note"])["store"] == "name"
    assert _roles(inv["recall_notes"])["recall"] == "name"


@pytest.mark.parametrize(
    "tools",
    [
        [_tool("send_email"), _tool("list_notes"), _tool("frobnicate_thing")],
        [_tool("zap", readOnlyHint=False), _tool("peek", readOnlyHint=True), _tool("write_x")],
    ],
)
@pytest.mark.parametrize("declared", [None, frozenset({"list_notes", "zap"})])
def test_consequential_column_matches_the_live_confirm_gate(
    tools: list[ToolSpec], declared: frozenset[str] | None
) -> None:
    control = make_control("W4", consequential_tools=declared)
    for t in tools:
        control.observe_description(
            SimpleNamespace(name=t.name, annotations=t.annotations)  # type: ignore[arg-type]
        )
    cc = SimpleNamespace(
        consequential_tools=sorted(declared or []), egress_tools=[], read_tool_names=[]
    )
    for entry in tool_inventory(tools, control_config=cc):
        live_applies, _reason = control._classify(entry.name)  # type: ignore[attr-defined]
        assert entry.consequential is live_applies, entry.name


def test_comment_lines_are_plain_ascii_and_name_every_tool() -> None:
    tools = [_tool("send_email"), _tool("frobnicate_thing"), _tool("peek", readOnlyHint=True)]
    lines = inventory_comment_lines(tool_inventory(tools))
    text = "\n".join(lines)
    text.encode("ascii")
    for t in tools:
        assert t.name in text
    assert all(line.startswith("#") for line in lines)
    assert "unknown" in text


def test_read_role_matches_the_live_information_flow_control() -> None:
    tools = [
        _tool("list_notes"),
        _tool("peek", readOnlyHint=True),
        _tool("poke", readOnlyHint=False),
        _tool("frobnicate_thing"),
    ]
    control = make_control("W2")
    for t in tools:
        control.observe_description(
            SimpleNamespace(name=t.name, annotations=t.annotations)  # type: ignore[arg-type]
        )
    for entry in tool_inventory(tools):
        live_applies, live_reason = control._is_read_tool(entry.name)  # type: ignore[attr-defined]
        has_read_role = any(r.role == "read" for r in entry.roles)
        assert has_read_role is (live_applies and live_reason != "fail-closed default"), entry.name


def test_a_gate_and_verdict_disagreement_is_shown_not_hidden() -> None:
    """`budget_report` has no whole-word hint, so the confirm gate guards it by
    the fail-closed default, while the verdict's substring read check counts its
    calls as reads. The inventory says both."""
    entry = _by_name(tool_inventory([_tool("budget_report")]))["budget_report"]
    assert entry.consequential is True
    assert entry.verdict_read is True
    assert "verdict counts its calls as reads" in treated_as_text(entry)


def test_a_declared_consequential_tool_is_never_a_verdict_read() -> None:
    cc = SimpleNamespace(consequential_tools=["list_notes"], egress_tools=[], read_tool_names=[])
    entry = _by_name(tool_inventory([_tool("list_notes")], control_config=cc))["list_notes"]
    assert entry.verdict_read is False
    assert treated_as_text(entry) == "yes (declared)"
