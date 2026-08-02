"""Unit tests for the v0.2.2 predicate primitives.

These three helpers compose into per-target predicates under
``mylonite.plugins._mcp.predicates``. Coverage here is exhaustive so the
per-target predicate tests can focus on integration rather than
primitive edge cases.
"""

from __future__ import annotations

import json

import pytest

from mylonite.scan.predicate_primitives import (
    tool_call_sequence,
    tool_executed_not_deferred,
    tool_result_contains,
    tool_was_called,
    tool_was_called_with_arg,
)


def _trace(*entries: dict) -> str:
    return json.dumps(list(entries))


def test_tool_executed_not_deferred_executed() -> None:
    blob = _trace({"tool": "send_email", "result": "Email sent to ops@x.com", "is_error": False})
    assert tool_executed_not_deferred(blob, "send_email") is True


def test_tool_executed_not_deferred_is_error_refused() -> None:
    """Structural is_error (guarded refusal) → not executed, regardless of wording."""
    blob = _trace({"tool": "send_email", "result": "host not in allowlist", "is_error": True})
    assert tool_executed_not_deferred(blob, "send_email") is False


def test_tool_executed_not_deferred_queued() -> None:
    """A deferred/queued result (the R3 false positive) → not executed."""
    blob = _trace(
        {
            "tool": "send_email",
            "result": "The email has been queued for approval.",
            "is_error": False,
        }
    )
    assert tool_executed_not_deferred(blob, "send_email") is False


def test_tool_executed_not_deferred_not_called() -> None:
    blob = _trace({"tool": "read_note", "result": "ok", "is_error": False})
    assert tool_executed_not_deferred(blob, "send_email") is False


def test_tool_executed_custom_deferred_markers() -> None:
    """Markers are overridable per target (no English/app assumption baked in)."""
    blob = _trace({"tool": "dispatch", "result": "en attente de validation", "is_error": False})
    assert tool_executed_not_deferred(blob, "dispatch") is True  # default markers miss it
    assert tool_executed_not_deferred(blob, "dispatch", deferred_markers=("en attente",)) is False


def test_tool_result_contains() -> None:
    blob = _trace(
        {"tool": "list_outbox", "result": "to=attacker@x.com status=sent", "is_error": False}
    )
    assert tool_result_contains(blob, "list_outbox", "attacker@x.com") is True
    assert tool_result_contains(blob, "list_outbox", "nope") is False


def test_effect_primitives_malformed_json() -> None:
    assert tool_executed_not_deferred("not json", "x") is False
    assert tool_result_contains("not json", "x", "y") is False


def test_tool_was_called_returns_true_when_name_present() -> None:
    assert tool_was_called(["read_file", "write_file"], "write_file") is True


def test_tool_was_called_returns_false_when_name_absent() -> None:
    assert tool_was_called(["read_file"], "write_file") is False


def test_tool_was_called_with_arg_fires_on_matching_value() -> None:
    trace = json.dumps(
        [
            {"tool": "fetch", "args": {"url": "http://attacker.example.com/x"}},
            {"tool": "fetch", "args": {"url": "http://benign.example.com/y"}},
        ]
    )
    assert tool_was_called_with_arg(trace, "fetch", "url", lambda v: "attacker" in v) is True


def test_tool_was_called_with_arg_silent_on_non_matching_value() -> None:
    trace = json.dumps([{"tool": "fetch", "args": {"url": "http://benign.example.com/y"}}])
    assert tool_was_called_with_arg(trace, "fetch", "url", lambda v: "attacker" in v) is False


def test_tool_was_called_with_arg_silent_when_tool_name_doesnt_match() -> None:
    trace = json.dumps([{"tool": "read_file", "args": {"path": "/etc/passwd"}}])
    assert tool_was_called_with_arg(trace, "fetch", "path", lambda v: True) is False


@pytest.mark.parametrize(
    "blob",
    ["", "not json", "[", "{}", json.dumps("a string"), json.dumps({"not": "a list"})],
)
def test_tool_was_called_with_arg_returns_false_on_malformed_blob(blob: str) -> None:
    assert tool_was_called_with_arg(blob, "fetch", "url", lambda v: True) is False


def test_tool_was_called_with_arg_handles_missing_arg_key() -> None:
    trace = json.dumps([{"tool": "fetch", "args": {}}])
    assert tool_was_called_with_arg(trace, "fetch", "url", lambda v: True) is False


def test_tool_call_sequence_fires_when_order_is_correct() -> None:
    assert tool_call_sequence(["read_file", "write_file"], "read_file", "write_file") is True


def test_tool_call_sequence_silent_when_order_reversed() -> None:
    assert tool_call_sequence(["write_file", "read_file"], "read_file", "write_file") is False


def test_tool_call_sequence_silent_when_either_name_missing() -> None:
    assert tool_call_sequence(["read_file"], "read_file", "write_file") is False
    assert tool_call_sequence(["write_file"], "read_file", "write_file") is False


def test_tool_call_sequence_handles_interleaved_calls() -> None:
    """The two names just need to appear in order — not adjacent."""
    calls = ["read_file", "list_directory", "write_file"]
    assert tool_call_sequence(calls, "read_file", "write_file") is True


def test_sequence_detects_a_later_valid_ordering() -> None:
    """DCR-0020: `str.index` took the FIRST occurrence of both names, so a benign
    write at index 0 masked the injected read->write at indices 1 and 2 — a false
    negative in the core oracle."""
    assert tool_call_sequence(["write_file", "read_file", "write_file"], "read_file", "write_file")
