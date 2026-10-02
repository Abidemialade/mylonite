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
    _scaffold_rest_target_file,
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


def test_scaffold_exits_cleanly_when_the_parent_directory_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_check_output_writable`'s `parent.mkdir(...)` call can itself raise
    (e.g. a permission error) -- a config error (exit 2, one line, no
    traceback), discovered before the fake adapter's `describe()` is ever
    called, same as every other `--scaffold` preflight failure."""
    fake = _patch_fake_adapter(monkeypatch)
    out = tmp_path / "newdir" / "target.yaml"

    def _boom(_self: Path, *_args: Any, **_kwargs: Any) -> None:
        raise OSError("simulated mkdir failure")

    monkeypatch.setattr(Path, "mkdir", _boom)

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
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1, result.output
    assert "Traceback" not in result.output
    assert fake.init_calls == 0
    assert fake.describe_calls == 0


def test_scaffold_exits_cleanly_when_the_probe_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_check_output_writable`'s own probe-file write can raise (a
    permission error an existence check alone would miss) -- a config error
    (exit 2, one line, no traceback), discovered before any server launch.
    Only the probe file is made to fail; every other `Path.write_text` call
    (including the eventual real write, if the preflight ever got there)
    still goes to the real method."""
    fake = _patch_fake_adapter(monkeypatch)
    out = tmp_path / "target.yaml"
    original_write_text = Path.write_text

    def _boom(self: Path, *args: Any, **kwargs: Any) -> int:
        if "mylonite-scaffold-writecheck" in self.name:
            raise OSError("simulated permission error")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _boom)

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
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1, result.output
    assert "Traceback" not in result.output
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


def test_atomic_write_removes_the_temp_file_when_the_write_itself_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure can happen earlier than the `replace` -- in the temp
    file's own `write_text` call, before `_atomic_write_text` ever reaches
    the rename. The destination must stay untouched, the (really written)
    temp file must be cleaned up, and the original error must surface
    unwrapped -- never silently swallowed or replaced by a cleanup error."""
    out = tmp_path / "target.yaml"
    out.write_text("ORIGINAL", encoding="utf-8")
    original_write_text = Path.write_text

    def _boom(self: Path, *args: Any, **kwargs: Any) -> int:
        if ".mylonite-tmp-" in self.name:
            # The temp file really gets created on disk before the
            # simulated failure, so the cleanup branch has something to
            # remove -- not just a no-op on a file that never existed.
            original_write_text(self, *args, **kwargs)
            raise OSError("simulated disk full mid-write")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _boom)

    with pytest.raises(OSError, match="simulated disk full mid-write"):
        _atomic_write_text(out, "NEW CONTENT")

    assert out.read_text(encoding="utf-8") == "ORIGINAL"
    leftovers = [p for p in tmp_path.iterdir() if p.name != "target.yaml"]
    assert leftovers == []


def test_atomic_write_writes_a_fresh_file(tmp_path: Path) -> None:
    out = tmp_path / "target.yaml"
    _atomic_write_text(out, "hello")
    assert out.read_text(encoding="utf-8") == "hello"


def test_scaffold_rest_rejects_a_directory_output(tmp_path: Path) -> None:
    """The REST scaffold path (no server to launch) gets the same preflight
    as the MCP path: an existing directory is a config error, not a crash."""
    out = tmp_path / "adir"
    out.mkdir()

    result = runner.invoke(
        app,
        ["scan", "--scaffold", str(out), "--rest-url", "https://agent.example/chat"],
    )

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "Traceback" not in (result.output + (result.stderr or ""))


def test_scaffold_rest_write_is_atomic_on_a_simulated_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The REST scaffold's write goes through the same `_atomic_write_text`
    helper as the MCP path: a crash mid-write leaves a pre-existing output
    file untouched instead of truncated."""
    out = tmp_path / "myagent.yaml"
    out.write_text("ORIGINAL", encoding="utf-8")

    def _boom(_self: Path, _dst: object) -> None:
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(Path, "replace", _boom)

    with pytest.raises(OSError):
        _scaffold_rest_target_file(
            output=out,
            rest_url="https://agent.example/chat",
            rest_body=None,
            rest_response_path=None,
            force=True,
        )

    assert out.read_text(encoding="utf-8") == "ORIGINAL"
    leftovers = [p for p in tmp_path.iterdir() if p.name != "myagent.yaml"]
    assert leftovers == []
