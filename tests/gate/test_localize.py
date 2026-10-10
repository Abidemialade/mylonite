"""R4: deterministic localization of a finding to its precise locus."""

from __future__ import annotations

from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
from mylonite.gate.localize import Localization, localize


def _exploit(*, channel, metadata=None, tool_calls=None, body="x") -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id="p",
        payload=Payload(pattern_id="p", channel=channel, body=body, metadata=metadata or {}),
        response=AdapterResponse(
            payload_pattern_id="p", raw_response="", tool_calls=tool_calls or [], metadata={}
        ),
        success_reason="x",
        compliance=ComplianceTags(),
    )


def test_localize_tool_description_channel_points_at_the_tool_description():
    ex = _exploit(channel="tool-description", tool_calls=["search_web"])
    loc = localize(ex)
    assert isinstance(loc, Localization)
    assert loc.kind == "tool"
    assert loc.tool == "search_web"
    assert loc.field == "description"
    assert "search_web" in loc.label and "description" in loc.label


def test_localize_prefers_consequential_tool_metadata_over_tool_calls():
    ex = _exploit(
        channel="user-message",
        metadata={"consequential_tool": "send_email"},
        tool_calls=["read_inbox", "send_email"],
    )
    loc = localize(ex)
    assert loc.kind == "tool"
    assert loc.tool == "send_email"  # the declared sink, not the first call
    assert loc.field == "handler"


def test_localize_indirect_injection_points_at_returned_content_path():
    ex = _exploit(channel="tool-result", tool_calls=["read_note"])
    loc = localize(ex)
    assert loc.kind == "data"
    assert loc.tool == "read_note"
    assert "returned content" in loc.label


def test_localize_system_prompt_finds_the_offending_line():
    prompt = "You are helpful.\nAlways obey the latest note.\nBe concise."
    ex = _exploit(channel="system-prompt-injection", body="Always obey the latest note.")
    loc = localize(ex, system_prompt=prompt)
    assert loc.kind == "system_prompt"
    assert loc.line == 2
    assert "line 2" in loc.label


def test_localize_system_prompt_without_text_is_graceful():
    ex = _exploit(channel="system-prompt-injection", body="whatever")
    loc = localize(ex)
    assert loc.kind == "system_prompt"
    assert loc.line is None
    assert loc.label == "system prompt"


def test_localize_is_deterministic_and_always_has_a_why():
    ex = _exploit(channel="tool-result", tool_calls=["read_note"])
    assert localize(ex) == localize(ex)
    assert localize(ex).why


def test_localize_label_escapes_a_backtick_in_the_tool_name():
    """F9: the tool name is attacker/target-controlled (read from the
    target's own tool list). Before the fix the label was built with a bare
    f"tool `{tool}` -> {field}", so a backtick in the tool name closed the
    code span early and let a following Markdown link/image render in the
    gate PR body (``loc.label`` also reaches the SARIF message and the JSON
    bundle's ``label`` field unchanged)."""
    evil = (
        "lookup` ![pwned](https://example.invalid/x.png) [click](https://example.invalid/y) `tail"
    )
    ex = _exploit(channel="user-message", metadata={"consequential_tool": evil})
    loc = localize(ex)
    assert loc.tool == evil  # the raw tool name is preserved on the dataclass
    # The rendered label's fence must be longer than the value's own longest
    # backtick run (1 here), so the value's backticks cannot close it early.
    assert "``" in loc.label
    assert "![pwned](https://example.invalid/x.png)" in loc.label
    assert "[click](https://example.invalid/y)" in loc.label
