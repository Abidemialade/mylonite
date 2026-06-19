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
