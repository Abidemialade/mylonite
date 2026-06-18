"""Offline test for the `mylonite ablate` command (engine-backed scan patched out)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app

_runner = CliRunner()

_YAML = """\
family: myapp-notes
command: echo
args: []
weakness_classes:
  - W2
  - W4
"""


def _write(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text(_YAML, encoding="utf-8")
    return p


def test_ablate_renders_load_bearing_and_theater(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mylonite.scan.ablation as ablation_mod

    def fake_scan(adapter: Any, pattern_id: str, **kwargs: Any) -> bool:
        applied = {c.weakness for c in adapter._controls}
        if pattern_id.startswith("indirect"):  # W2 seed -> load-bearing
            return len(applied) == 0  # fires raw, resisted when a control is applied
        return True  # W4 seed -> fires regardless -> theater

    monkeypatch.setattr(ablation_mod, "scan_target_fires", fake_scan)
    result = _runner.invoke(
        app,
        [
            "ablate",
            "--target-file",
            str(_write(tmp_path)),
            "--authorize",
            "me",
            "--controls",
            "W2,W4",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "W2" in out and "W4" in out
    assert "load-bearing" in out
    assert "theater" in out


def test_ablate_requires_authorize(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["ablate", "--target-file", str(_write(tmp_path))])
    assert result.exit_code != 0
    assert "authorize" in result.output.lower()
