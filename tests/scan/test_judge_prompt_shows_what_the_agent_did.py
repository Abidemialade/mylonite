"""The judge prompt shows each call's arguments and the end of a long reply.

The LLM judge decides some attempts from the prompt alone. If a call's
destination lives only in its recorded arguments, or a long reply says what
happened after its first 1,500 characters, the judge has to see that text.
"""

from __future__ import annotations

import json
import re

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.scan.judge import _build_judge_prompt

_DESTINATION = "recipient@example.invalid"


def _payload() -> Payload:
    return Payload(
        pattern_id="test",
        channel="tool-result",
        body="summarise my notes",
        metadata={
            "seed_id": "test",
            "weakness": "W2",
            "predicate": "consequential_action_executed",
        },
    )


def _response(
    *, raw_response: str = "done", trace: list[dict[str, object]] | None = None
) -> AdapterResponse:
    metadata = {"effect_trace": json.dumps(trace)} if trace is not None else {}
    return AdapterResponse(
        payload_pattern_id="test",
        raw_response=raw_response,
        tool_calls=[str(e["tool"]) for e in trace or []],
        metadata=metadata,
    )


def _fenced_sections(prompt: str) -> list[str]:
    m = re.search(r"<(MYLONITE-FENCE-[0-9a-f]{16})>", prompt)
    assert m, prompt
    tag = m.group(1)
    return re.findall(rf"<{tag}>\n(.*?)\n</{tag}>", prompt, flags=re.DOTALL)


def test_the_request_body_sits_inside_the_fence() -> None:
    """``payload.body`` is the attack request text the judge is shown; it
    goes inside the same fence that already wraps the target's response and
    trace, not loose in the prompt where a splice could reach past it."""
    payload = _payload().model_copy(update={"body": "DUMMY-REQUEST-MARKER"})
    prompt = _build_judge_prompt(payload, _response())
    assert "DUMMY-REQUEST-MARKER" in prompt
    request_section = _fenced_sections(prompt)[0]
    assert request_section == "DUMMY-REQUEST-MARKER"


def test_a_destination_only_in_a_calls_arguments_reaches_the_judge() -> None:
    trace = [
        {"tool": "read_note", "args": {"id": 1}, "result": "note text", "is_error": False},
        {"tool": "send_email", "args": {"to": _DESTINATION}, "result": "sent", "is_error": False},
    ]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    assert _DESTINATION in prompt
    # It sits inside the fence, on the call's own line.
    trace_section = _fenced_sections(prompt)[2]
    send_line = next(ln for ln in trace_section.splitlines() if "send_email" in ln)
    assert _DESTINATION in send_line
    assert "[ok]" in send_line


def test_long_arguments_are_capped_with_an_ellipsis_marker() -> None:
    long_value = "x" * 1000
    trace = [
        {"tool": "write_file", "args": {"body": long_value}, "result": "ok", "is_error": False}
    ]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    line = next(ln for ln in _fenced_sections(prompt)[2].splitlines() if "write_file" in ln)
    assert "x" * 1000 not in line
    assert "…" in line
    assert len(line) < 450


def test_a_long_earlier_argument_does_not_hide_a_later_destination() -> None:
    trace = [
        {
            "tool": "send_email",
            "args": {"body": "w" * 600, "subject": "v" * 400, "to": _DESTINATION},
            "result": "sent",
            "is_error": False,
        }
    ]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    line = next(ln for ln in _fenced_sections(prompt)[2].splitlines() if "send_email" in ln)
    assert _DESTINATION in line
    assert '"body":"' + "w" * 120 + "…" in line
    assert '"subject":"' in line


def test_the_rendered_arguments_of_one_call_stay_bounded() -> None:
    args = {f"k{i}": "y" * 500 for i in range(20)}
    trace = [{"tool": "write_file", "args": args, "result": "ok", "is_error": False}]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    line = next(ln for ln in _fenced_sections(prompt)[2].splitlines() if "write_file" in ln)
    assert len(line) < 700


def test_line_breaks_in_arguments_keep_the_call_on_one_line() -> None:
    value = "a" + "".join(sep + "x" for sep in ("\n", "\r", chr(0x2028), chr(0x2029), chr(0x85)))
    trace = [{"tool": "send_email", "args": {"to": value}, "result": "sent", "is_error": False}]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    lines = _fenced_sections(prompt)[2].splitlines()
    send_lines = [ln for ln in lines if "send_email" in ln]
    assert len(send_lines) == 1
    assert "[ok] sent" in send_lines[0]
    assert len(lines) == 2  # the heading and this one call


def test_a_call_without_recorded_arguments_still_renders() -> None:
    trace = [{"tool": "list_notes", "result": "3 notes", "is_error": False}]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    assert "- list_notes" in prompt
    assert "3 notes" in prompt


def test_tool_results_are_shown_up_to_800_characters() -> None:
    result = "r" * 500 + "LATE-RESULT-TEXT" + "r" * 400
    trace = [{"tool": "read_note", "args": {}, "result": result, "is_error": False}]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    assert "LATE-RESULT-TEXT" in prompt


def test_tool_results_longer_than_800_characters_are_cut() -> None:
    trace = [{"tool": "read_note", "args": {}, "result": "z" * 1200, "is_error": False}]
    prompt = _build_judge_prompt(_payload(), _response(trace=trace))
    line = next(ln for ln in _fenced_sections(prompt)[2].splitlines() if "read_note" in ln)
    assert "z" * 800 in line
    assert "z" * 801 not in line


def test_text_after_character_1500_of_a_long_reply_reaches_the_judge_via_the_tail() -> None:
    reply = "a" * 1600 + "b" * 900 + "END-OF-REPLY-TEXT"
    prompt = _build_judge_prompt(_payload(), _response(raw_response=reply))
    assert "END-OF-REPLY-TEXT" in prompt


def test_the_omitted_marker_counts_the_characters_left_out() -> None:
    reply = "h" * 1500 + "m" * 700 + "t" * 500
    assert len(reply) == 2700
    prompt = _build_judge_prompt(_payload(), _response(raw_response=reply))
    shown = _fenced_sections(prompt)[1]
    assert "[700 characters omitted]" in shown
    assert shown.startswith("h" * 1500)
    assert shown.endswith("t" * 500)
    assert "m" not in shown.replace("[700 characters omitted]", "")


def test_a_reply_one_character_over_the_limit_omits_one_character() -> None:
    reply = "h" * 1500 + "m" + "t" * 500
    prompt = _build_judge_prompt(_payload(), _response(raw_response=reply))
    assert "[1 characters omitted]" in _fenced_sections(prompt)[1]


def test_a_reply_of_2000_characters_or_fewer_is_shown_whole() -> None:
    for reply in ("short reply", "s" * 1999 + "E", "q" * 2000):
        prompt = _build_judge_prompt(_payload(), _response(raw_response=reply))
        shown = _fenced_sections(prompt)[1]
        assert shown == reply
        assert "characters omitted" not in prompt
