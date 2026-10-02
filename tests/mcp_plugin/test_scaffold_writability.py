"""`scan --scaffold` must find out it cannot write its output file before it
pays the cost of launching the target MCP server, and the write itself must
be atomic (S14, S15).

Before this: a bad `--scaffold` path (e.g. it is a directory) was only
discovered at `output.write_text(...)`, *after* `adapter.describe()` had
already launched the server -- and the failure surfaced as an unhandled
traceback exiting 1 (a code reserved for `check --enforce` findings), not the
usage-error code 2. A non-atomic write also meant a crash mid-write could
leave a truncated file that still parses as YAML and loads, failing
confusingly later instead of being caught at write time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import EXIT_CONFIG, app
from mylonite.plugins._mcp.scaffold import (
    _atomic_write_text,
    _check_output_writable,
    _OutputNotWritable,
    _with_scaffold_markers,
)
from mylonite.plugins._mcp.target_file import (
    SCAFFOLD_MARKER_FOOTER,
    SCAFFOLD_MARKER_HEADER,
    load_target_file,
)

runner = CliRunner()


def _fake_descriptor() -> Any:
    from mylonite.contracts import TargetDescriptor, ToolSpec

    return TargetDescriptor(
        target_id="mcp:myapp",
        kind="mcp",
        system_prompt="x",
        tools=[ToolSpec(name="read_note", description="read a stored note", json_schema={})],
    )


class _CountingFakeAdapter:
    """Counts constructions/`describe()` calls so a test can assert the server
    launch path was never reached."""

    describe_calls = 0
    init_calls = 0

    def __init__(self, **_: Any) -> None:
        type(self).init_calls += 1

    async def describe(self) -> Any:
        type(self).describe_calls += 1
        return _fake_descriptor()


def _patch_fake_adapter(monkeypatch: pytest.MonkeyPatch) -> type[_CountingFakeAdapter]:
    from mylonite.plugins._mcp import stdio_adapter

    _CountingFakeAdapter.describe_calls = 0
    _CountingFakeAdapter.init_calls = 0
    monkeypatch.setattr(stdio_adapter, "MCPStdioAdapter", _CountingFakeAdapter)
    return _CountingFakeAdapter


def test_check_output_writable_rejects_an_existing_directory(tmp_path: Path) -> None:
    out = tmp_path / "adir"
    out.mkdir()
    with pytest.raises(_OutputNotWritable):
        _check_output_writable(out)


def test_check_output_writable_creates_a_missing_parent(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "deeper" / "target.yaml"
    _check_output_writable(out)  # must not raise
    assert out.parent.is_dir()


def test_check_output_writable_accepts_a_plain_writable_path(tmp_path: Path) -> None:
    out = tmp_path / "target.yaml"
    _check_output_writable(out)  # must not raise


def test_scaffold_rejects_a_directory_output_before_launching_the_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The output path is an existing directory -- a config error (exit 2),
    discovered before the fake adapter's `describe()` is ever called."""
    fake = _patch_fake_adapter(monkeypatch)
    out = tmp_path / "adir"
    out.mkdir()

    result = runner.invoke(
        app,
        [
            "scan",
            "--command",
            "python",
            "--arg",
            "-m",
            "--arg",
            "my_server",
            "--scaffold",
            str(out),
        ],
    )

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "Traceback" not in (result.output + (result.stderr or ""))
    assert fake.init_calls == 0
    assert fake.describe_calls == 0


def test_atomic_write_leaves_the_old_file_intact_on_a_simulated_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "target.yaml"
    out.write_text("ORIGINAL", encoding="utf-8")

    def _boom(_self: Path, _dst: object) -> None:
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(Path, "replace", _boom)

    with pytest.raises(OSError):
        _atomic_write_text(out, "NEW CONTENT")

    assert out.read_text(encoding="utf-8") == "ORIGINAL"
    leftovers = [p for p in tmp_path.iterdir() if p.name != "target.yaml"]
    assert leftovers == []


def test_atomic_write_writes_a_fresh_file(tmp_path: Path) -> None:
    out = tmp_path / "target.yaml"
    _atomic_write_text(out, "hello")
    assert out.read_text(encoding="utf-8") == "hello"


def test_scaffold_marker_round_trip_detects_a_truncated_write(tmp_path: Path) -> None:
    text = _with_scaffold_markers("family: custom\ncommand: python\n")
    assert text.startswith(SCAFFOLD_MARKER_HEADER)
    assert text.endswith(SCAFFOLD_MARKER_FOOTER)

    good = tmp_path / "good.yaml"
    good.write_text(text + "\nweakness_classes: []\n", encoding="utf-8")
    tf = load_target_file(good)
    assert tf.family == "custom"

    # Simulate a crash mid-write: the footer marker never got written.
    truncated = tmp_path / "truncated.yaml"
    truncated.write_text(SCAFFOLD_MARKER_HEADER + "family: custom\ncomma", encoding="utf-8")
    with pytest.raises(ValueError, match="scaffold"):
        load_target_file(truncated)


def test_hand_written_target_file_without_any_marker_still_loads(tmp_path: Path) -> None:
    """A file nobody ran `--scaffold` on never carries the header marker, so
    the missing-footer check must never fire for it."""
    hand = tmp_path / "hand.yaml"
    hand.write_text("family: custom\ncommand: python\n", encoding="utf-8")
    tf = load_target_file(hand)
    assert tf.family == "custom"
