"""`gate` warns when the committed gate workflows pin an older mylonite.

The workflows `gate --workflows` scaffolds install the mylonite that wrote
them. An older pin may not replay what a newer `gate` records, so the new
tests would fail in CI on their first run. `gate` says so, naming the file
and the fix, and carries on: the user may bump the pin in the same commit.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.gate.workflows import stale_workflow_pins, write_workflows


def _workflow(repo: Path, name: str, pin: str) -> Path:
    path = repo / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'      - run: pip install "mylonite=={pin}" pytest\n', encoding="utf-8")
    return path


def test_an_older_pin_is_named_with_the_fix(tmp_path: Path) -> None:
    path = _workflow(tmp_path, "mylonite-gate.yml", "0.10.5")
    lines = stale_workflow_pins(tmp_path / ".mylonite" / "gate", version="0.12.0")
    assert len(lines) == 1
    assert str(path) in lines[0]
    assert "mylonite==0.10.5" in lines[0]
    assert "--workflows" in lines[0]
    assert "mylonite==0.12.0" in lines[0]


def test_a_current_or_newer_pin_is_quiet(tmp_path: Path) -> None:
    _workflow(tmp_path, "mylonite-gate.yml", "0.12.0")
    _workflow(tmp_path, "mylonite-discovery.yml", "0.13.0")
    assert stale_workflow_pins(tmp_path / ".mylonite" / "gate", version="0.12.0") == []


def test_no_workflows_is_quiet(tmp_path: Path) -> None:
    assert stale_workflow_pins(tmp_path / ".mylonite" / "gate", version="0.12.0") == []


def test_freshly_scaffolded_workflows_are_quiet(tmp_path: Path) -> None:
    write_workflows(tmp_path, model="openai/gpt-4o-mini")
    assert stale_workflow_pins(tmp_path / ".mylonite" / "gate") == []


def test_open_pr_fn_prints_the_warning_and_still_writes_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mylonite.gate.wiring import make_open_pr_fn

    monkeypatch.chdir(tmp_path)
    _workflow(tmp_path, "mylonite-gate.yml", "0.0.1")
    calls: dict[str, Any] = {}

    def _print_pr(paths: Any, **kwargs: Any) -> SimpleNamespace:
        calls["paths"] = paths
        return SimpleNamespace(opened=False, branch=None)

    pr_mod = SimpleNamespace(
        resolve_repo_root=lambda: tmp_path,
        resolve_default_base=lambda _root: "main",
        GatePaths=lambda **kw: SimpleNamespace(**kw),
        open_or_print_pr=_print_pr,
    )
    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=None,
        pr_mod=pr_mod,
        model="openai/gpt-4o-mini",
    )
    out_dir = Path(".mylonite") / "gate"
    out_dir.mkdir(parents=True)
    exploit = SimpleNamespace(pattern_id="p")
    report = SimpleNamespace(test_filename="test_w2-abcdef.py")
    open_pr_fn(out_dir=out_dir, findings=[(exploit, report)], body="b", open_pr=False)

    err = capsys.readouterr().err
    assert "mylonite==0.0.1" in err
    assert "--workflows" in err
    assert "paths" in calls  # a warning, never a refusal
