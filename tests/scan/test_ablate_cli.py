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


# --- Theme B: server-layer ablation (control_env toggles) -------------------

_YAML_SERVER_LAYER = """\
family: myapp-server
command: echo
args: []
weakness_classes:
  - W2
  - W4
control_env:
  W2:
    DISABLE_MARKING: "1"
  W4:
    AUTONOMY: full
"""


def test_ablate_server_layer_toggles_via_control_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A target whose guards live in the SERVER (not the adapter shim) is ablated
    by DISABLING them via control_env. The raw side disables all guards (fires);
    the 'only C' side leaves C on (resists) → load-bearing, not no-attack.

    Before Theme B this target returned no-attack for every control because the
    shim could not strip the server-layer guard.
    """
    import mylonite.scan.ablation as ablation_mod

    def fake_scan(adapter: Any, pattern_id: str, **kwargs: Any) -> bool:
        # Server-layer mode uses no adapter-shim controls; the differential is
        # produced entirely by the launch env that disables server guards.
        assert adapter._controls == []
        env = adapter._launch_env or {}
        w2_disabled = env.get("DISABLE_MARKING") == "1"
        w4_disabled = env.get("AUTONOMY") == "full"
        if pattern_id.startswith("indirect"):  # W2 representative seed
            return w2_disabled  # fires only when the W2 server guard is off
        return w4_disabled  # W4 representative seed

    monkeypatch.setattr(ablation_mod, "scan_target_fires", fake_scan)
    p = tmp_path / "server.yaml"
    p.write_text(_YAML_SERVER_LAYER, encoding="utf-8")
    result = _runner.invoke(
        app,
        ["ablate", "--target-file", str(p), "--authorize", "me", "--controls", "W2,W4"],
    )
    assert result.exit_code == 0, result.output
    assert "load-bearing" in result.output
    assert "server-layer" in result.output  # banner announces the mode
