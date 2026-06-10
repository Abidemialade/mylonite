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
    tool_was_called,
    tool_was_called_with_arg,
)


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
