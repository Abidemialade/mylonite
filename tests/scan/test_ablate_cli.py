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
    from mylonite.scan.ablation import FireOutcome

    def fake_scan(adapter: Any, pattern_id: str, **kwargs: Any) -> FireOutcome:
        applied = {c.weakness for c in adapter._controls}
        if pattern_id.startswith("indirect"):  # W2 seed -> load-bearing
            # fires raw, resisted when a control is applied
            return FireOutcome.FIRED if len(applied) == 0 else FireOutcome.RESISTED
        return FireOutcome.FIRED  # W4 seed -> fires regardless -> theater

    monkeypatch.setattr(ablation_mod, "scan_target_fires", fake_scan)
    result = _runner.invoke(
        app,
        [
            "ablate",
            "--target-file",
            str(_write(tmp_path)),
            "--authorize",
            "myapp-notes",
            "--controls",
            "W2,W4",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "W2" in out and "W4" in out
    assert "load-bearing" in out
    assert "theater" in out


def test_ablate_renders_inconclusive_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T3 regression at the CLI layer: a crashed guarded-side scan (simulated
    here as scan_target_fires returning INCONCLUSIVE) must render as
    'inconclusive' in the table -- never as 'load-bearing', and never crash
    the render."""
    import mylonite.scan.ablation as ablation_mod
    from mylonite.scan.ablation import FireOutcome

    def fake_scan(adapter: Any, pattern_id: str, **kwargs: Any) -> FireOutcome:
        applied = {c.weakness for c in adapter._controls}
        if len(applied) == 0:
            return FireOutcome.FIRED  # raw side fires normally
        return FireOutcome.INCONCLUSIVE  # guarded side "crashes"

    monkeypatch.setattr(ablation_mod, "scan_target_fires", fake_scan)
    result = _runner.invoke(
        app,
        [
            "ablate",
            "--target-file",
            str(_write(tmp_path)),
            "--authorize",
            "myapp-notes",
            "--controls",
            "W2",
        ],
    )
    assert result.exit_code == 0, result.output
    combined = result.output + (result.stderr or "")
    assert "inconclusive" in combined
    assert "load-bearing: W2" not in combined  # the summary list, not the caveat prose
    assert combined.count("inconclusive") >= 2  # the table row + the post-render hint


def test_ablate_requires_authorize(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["ablate", "--target-file", str(_write(tmp_path))])
    assert result.exit_code != 0
    assert "authorize" in result.output.lower()


def test_ablate_refuses_authorize_that_does_not_name_the_target(tmp_path: Path) -> None:
    """One-gate consolidation (DCR-0008/0009): ablate used to accept ANY non-empty
    --authorize value; it must now match the target's family (or scope), same as
    scan/gate/validate."""
    result = _runner.invoke(
        app,
        ["ablate", "--target-file", str(_write(tmp_path)), "--authorize", "not-the-family"],
    )
    assert result.exit_code != 0
    out = result.stderr or result.output
    assert "myapp-notes" in out


def test_ablate_refuses_iterations_below_one(tmp_path: Path) -> None:
    """DCR-0014: ablate now rejects --iterations < 1 with the same guard `gate`
    already had, instead of silently doing zero (or a negative number of) runs
    per control per side."""
    result = _runner.invoke(
        app,
        [
            "ablate",
            "--target-file",
            str(_write(tmp_path)),
            "--authorize",
            "myapp-notes",
            "--iterations",
            "0",
        ],
    )
    assert result.exit_code != 0
    out = result.stderr or result.output
    assert "--iterations" in out


def test_ablate_controls_dedupes_repeated_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DCR-0015: --controls W2,W2,W4 must not double-count W2's scans/rows in
    the ablation matrix — `dict.fromkeys` dedupes while preserving order."""
    import mylonite.scan.ablation as ablation_mod
    from mylonite.scan.ablation import ControlContribution

    captured: dict[str, Any] = {}

    def _fake_run_control_ablation(*, controls: list[str], **kwargs: Any) -> list[Any]:
        captured["controls"] = list(controls)
        return [
            ControlContribution(
                weakness=c,
                raw_fired=1,
                guarded_fired=0,
                total=1,
                contribution=1.0,
                status="load-bearing",
            )
            for c in controls
        ]

    monkeypatch.setattr(ablation_mod, "run_control_ablation", _fake_run_control_ablation)

    result = _runner.invoke(
        app,
        [
            "ablate",
            "--target-file",
            str(_write(tmp_path)),
            "--authorize",
            "myapp-notes",
            "--controls",
            "W2,W2,W4",
        ],
    )
    assert result.exit_code == 0, result.output
    # The deduped, order-preserving list actually driven through the ablation —
    # a pre-fix run would have passed ["W2", "W2", "W4"] here.
    assert captured["controls"] == ["W2", "W4"]


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
    from mylonite.scan.ablation import FireOutcome

    def fake_scan(adapter: Any, pattern_id: str, **kwargs: Any) -> FireOutcome:
        # Server-layer mode uses no adapter-shim controls; the differential is
        # produced entirely by the launch env that disables server guards.
        assert adapter._controls == []
        env = adapter._launch_env or {}
        w2_disabled = env.get("DISABLE_MARKING") == "1"
        w4_disabled = env.get("AUTONOMY") == "full"
        if pattern_id.startswith("indirect"):  # W2 representative seed
            # fires only when the W2 server guard is off
            return FireOutcome.FIRED if w2_disabled else FireOutcome.RESISTED
        return FireOutcome.FIRED if w4_disabled else FireOutcome.RESISTED  # W4 rep seed

    monkeypatch.setattr(ablation_mod, "scan_target_fires", fake_scan)
    p = tmp_path / "server.yaml"
    p.write_text(_YAML_SERVER_LAYER, encoding="utf-8")
    result = _runner.invoke(
        app,
        ["ablate", "--target-file", str(p), "--authorize", "myapp-server", "--controls", "W2,W4"],
    )
    assert result.exit_code == 0, result.output
    assert "load-bearing" in result.output
    assert "server-layer" in result.output  # banner announces the mode
