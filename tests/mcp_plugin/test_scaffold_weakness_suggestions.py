"""R2c (#181b): `mylonite scan --scaffold` must not suggest a weakness class
its own tool surface can't cover — otherwise a fresh scaffold user's first
`scan` immediately hits the R2 pre-flight refusal on the very target.yaml
the scaffold just handed them.

`_suggest_weakness_classes`'s raw keyword-blob hints are gated through the
same `scan.seeds.seed_coverage` helper the engine's seed selection uses.
"""

from __future__ import annotations

from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp.scaffold import _suggest_weakness_classes


def _tool(name: str, description: str, props: dict[str, object] | None = None) -> ToolSpec:
    return ToolSpec(name=name, description=description, json_schema={"properties": props or {}})


def test_w2_dropped_with_no_plant_recall_pair_and_no_content_processor() -> None:
    """A read-only surface with a URL-shaped and an action-shaped tool, but
    nothing that could plant untrusted content for later recall — W2 must
    not be suggested even though the naive baseline (any tools at all) would."""
    tools = [
        _tool("get_status", "Report the current status."),
        _tool("web_fetch", "Fetch a resource.", {"url": {"type": "string"}}),
        _tool("send_email", "Send an email.", {"to": {"type": "string"}}),
    ]
    got = _suggest_weakness_classes(tools)
    assert "W2" not in got
    # W1 always survives when tools exist (the rug-pull probe needs no
    # plant/recall pair at all — see seed_synth._w1_rugpull_seed).
    assert "W1" in got
    assert "W3" in got
    assert "W4" in got


def test_w2_kept_with_a_genuine_plant_recall_pair() -> None:
    tools = [
        _tool("write_note", "Store a note.", {"body": {"type": "string"}}),
        _tool("read_note", "Read a stored note."),
    ]
    got = _suggest_weakness_classes(tools)
    assert "W2" in got


def test_w2_kept_via_a_content_processor_tool_with_no_seed_arm_at_all() -> None:
    """The direct_content channel needs no plant/recall pair — a
    content-processing tool alone is enough (seed_synth._w2_seed)."""
    tools = [_tool("summarize_document", "Summarise the given text.", {"text": {"type": "string"}})]
    got = _suggest_weakness_classes(tools)
    assert "W2" in got


def test_w3_dropped_when_no_tool_is_actually_egress_shaped() -> None:
    """A tool whose description merely CONTAINS an egress-hint substring
    (naive keyword match) but whose schema/name the stricter live classifier
    does not recognise as a destination-taking tool."""
    tools = [_tool("get_webhook_status", "Reports whether the webhook config is valid.")]
    got = _suggest_weakness_classes(tools)
    assert "W3" not in got


def test_w4_dropped_when_no_tool_is_actually_consequential() -> None:
    tools = [_tool("get_publish_status", "Reports whether publishing is enabled.")]
    got = _suggest_weakness_classes(tools)
    assert "W4" not in got


def test_no_tools_suggests_nothing() -> None:
    assert _suggest_weakness_classes([]) == []
