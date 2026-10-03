"""`scan --scaffold` must write `system_prompt_file` so it loads back to the
SAME file once the scaffolded target.yaml is later read (#187) -- the scaffold
and `load_target_file` must agree on what a relative path in the written file
resolves against, even when `--scaffold` ran from a different directory than
the one the file ends up in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mylonite.plugins._mcp.scaffold import _rebase_relative_path


def test_rebase_relative_path_returns_absolute_unchanged(tmp_path: Path) -> None:
    abs_path = tmp_path / "prompt.txt"
    out = tmp_path / "configs" / "target.yaml"
    assert _rebase_relative_path(abs_path, output=out) == abs_path


def test_rebase_relative_path_stays_relative_under_outputs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common case: `--scaffold` and `--system-prompt-file` both typed
    relative to the SAME cwd, and the scaffolded file lands there too."""
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "target.yaml"
    result = _rebase_relative_path(Path("prompt.txt"), output=out)
    assert not result.is_absolute()
    assert result == Path("prompt.txt")


def test_rebase_relative_path_falls_back_to_absolute_when_climbing_would_be_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the scaffolded file lands somewhere that could only reach the
    prompt file by climbing out with `..`, write an absolute path instead --
    a `..`-climbing value would fail the loader's containment check."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "prompt.txt").write_text("x", encoding="utf-8")
    monkeypatch.chdir(workdir)
    out_dir = tmp_path / "configs"
    out_dir.mkdir()
    out = out_dir / "target.yaml"
    result = _rebase_relative_path(Path("prompt.txt"), output=out)
    assert result.is_absolute()
    assert result == (workdir / "prompt.txt").resolve()


def test_rebase_relative_path_under_a_nested_output_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prompt file that stays reachable under the output's directory, just
    one level deeper than the scaffold's own cwd -- the realistic case a
    `--scaffold configs/app.yaml --system-prompt-file configs/sub/prompt.txt`
    invocation from the project root produces. Before the fix, the scaffold
    wrote the flag's value VERBATIM ("configs/sub/prompt.txt"), and the
    loader then resolved that a second time against the file's own directory
    (already `configs/`), looking for the wrong, doubled path."""
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "configs" / "app.yaml"
    result = _rebase_relative_path(Path("configs/sub/prompt.txt"), output=out)
    assert not result.is_absolute()
    assert result == Path("sub/prompt.txt")


def _fake_descriptor() -> Any:
    from mylonite.contracts import TargetDescriptor, ToolSpec

    return TargetDescriptor(
        target_id="mcp:myapp",
        kind="mcp",
        system_prompt="x",
        tools=[ToolSpec(name="read_note", description="read a stored note", json_schema={})],
    )


def _patch_fake_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    from mylonite.plugins._mcp import stdio_adapter

    class _FakeAdapter:
        def __init__(self, **_: Any) -> None:
            pass

        async def describe(self) -> Any:
            return _fake_descriptor()

    monkeypatch.setattr(stdio_adapter, "MCPStdioAdapter", _FakeAdapter)


def test_scaffold_system_prompt_file_round_trips_from_a_different_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: `--scaffold configs/app.yaml --system-prompt-file
    configs/sub/prompt.txt`, run from the project ROOT (a different directory
    than `configs/`, the output's own directory) -- the prompt stays
    reachable under the output's directory, just a level deeper than the
    scaffold's own cwd. Before the fix, `system_prompt_file` was written
    verbatim as typed ("configs/sub/prompt.txt"), and `load_target_file`
    resolved that path a SECOND time against the file's own directory
    (already `configs/`), looking for a doubled, nonexistent path."""
    _patch_fake_adapter(monkeypatch)
    from mylonite.plugins._mcp.scaffold import _scaffold_target_file
    from mylonite.plugins._mcp.target_file import load_target_file, resolved_system_prompt

    root = tmp_path
    (root / "configs" / "sub").mkdir(parents=True)
    (root / "configs" / "sub" / "prompt.txt").write_text("Be careful with tools.", encoding="utf-8")
    out = root / "configs" / "app.yaml"

    monkeypatch.chdir(root)
    _scaffold_target_file(
        output=out,
        command="python",
        arg=None,
        env=None,
        scope=None,
        system_prompt=None,
        system_prompt_file=Path("configs/sub/prompt.txt"),
        model=None,
        force=False,
    )

    tf = load_target_file(out)
    assert resolved_system_prompt(tf) == "Be careful with tools."


def test_scaffold_warns_when_prompt_file_is_outside_the_outputs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A prompt file that is NOT reachable under the output's own directory
    (e.g. a sibling tree) can never load, by the same containment rule that
    protects `system_prompt_file` from arbitrary-file-read -- no path
    representation fixes that. The scaffold now says so immediately, instead
    of leaving the operator to discover a load failure only later."""
    _patch_fake_adapter(monkeypatch)
    from mylonite.plugins._mcp.scaffold import _scaffold_target_file

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "prompt.txt").write_text("x", encoding="utf-8")
    out_dir = tmp_path / "configs"
    out_dir.mkdir()
    out = out_dir / "target.yaml"

    monkeypatch.chdir(workdir)
    _scaffold_target_file(
        output=out,
        command="python",
        arg=None,
        env=None,
        scope=None,
        system_prompt=None,
        system_prompt_file=Path("prompt.txt"),
        model=None,
        force=False,
    )

    assert "outside" in capsys.readouterr().err
