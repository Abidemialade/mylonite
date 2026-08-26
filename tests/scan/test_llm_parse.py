"""Direct unit tests for the model-output parsing layer (issue #98).

The point of extracting these functions out of ``scan._llm`` is that the step
where nondeterministic model text becomes a deterministic value is now testable
without a live-call code path. These tests exercise the functions directly with
plain stub objects -- no LiteLLM, no provider, no network.
"""

from __future__ import annotations

from types import SimpleNamespace

from mylonite.scan.llm_parse import (
    _extract_json_candidate,
    _extract_json_object,
    _extract_text,
    _first_balanced_object,
    _looks_truncated,
    _raw_json_text,
    _tool_call_arguments,
    _try_repair,
)


def _content_response(text: str) -> SimpleNamespace:
    """A LiteLLM/OpenAI-shaped response carrying ``text`` as message content."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _tool_call_response(arguments: object) -> SimpleNamespace:
    fn = SimpleNamespace(arguments=arguments)
    tc = SimpleNamespace(function=fn)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[tc]))]
    )


class TestFirstBalancedObject:
    def test_extracts_from_surrounding_prose(self) -> None:
        assert _first_balanced_object('before {"a": 1} after') == '{"a": 1}'

    def test_ignores_braces_inside_strings(self) -> None:
        assert _first_balanced_object('{"reason": "use } carefully"}') == (
            '{"reason": "use } carefully"}'
        )

    def test_handles_nested_objects(self) -> None:
        assert _first_balanced_object('x {"a": {"b": 2}} y') == '{"a": {"b": 2}}'

    def test_none_when_no_object(self) -> None:
        assert _first_balanced_object("no object here") is None

    def test_none_when_unbalanced(self) -> None:
        assert _first_balanced_object('{"a": 1') is None


class TestExtractJsonObject:
    def test_strips_code_fence(self) -> None:
        assert _extract_json_object('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_empty_returns_none(self) -> None:
        assert _extract_json_object("   ") is None


class TestExtractText:
    def test_reads_content(self) -> None:
        assert _extract_text(_content_response("hello")) == "hello"

    def test_bad_shape_returns_empty(self) -> None:
        assert _extract_text(SimpleNamespace(choices=[])) == ""


class TestToolCallArguments:
    def test_reads_string_arguments(self) -> None:
        assert _tool_call_arguments(_tool_call_response('{"a": 1}')) == '{"a": 1}'

    def test_serialises_dict_arguments(self) -> None:
        assert _tool_call_arguments(_tool_call_response({"a": 1})) == '{"a": 1}'

    def test_no_tool_calls_returns_none(self) -> None:
        assert _tool_call_arguments(_content_response("hi")) is None


class TestRawAndCandidate:
    def test_prefers_content_when_it_has_an_object(self) -> None:
        assert _raw_json_text(_content_response('{"a": 1}')) == '{"a": 1}'

    def test_falls_back_to_tool_call(self) -> None:
        assert _raw_json_text(_tool_call_response('{"b": 2}')) == '{"b": 2}'

    def test_candidate_end_to_end(self) -> None:
        assert _extract_json_candidate(_content_response('prose {"a": 1} more')) == '{"a": 1}'


class TestTruncationAndRepair:
    def test_looks_truncated_true_for_unclosed(self) -> None:
        assert _looks_truncated(_content_response('{"a": 1')) is True

    def test_looks_truncated_false_for_complete(self) -> None:
        assert _looks_truncated(_content_response('{"a": 1}')) is False

    def test_repair_rescues_trailing_comma(self) -> None:
        assert _try_repair('{"a": 1,}') == {"a": 1}

    def test_repair_refuses_truncated(self) -> None:
        # json-repair would fabricate the missing close; the guard must refuse.
        assert _try_repair('{"a": 1') is None
