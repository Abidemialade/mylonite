"""Recorded end-to-end tests for the offline ``mylonite demo`` (v0.3.0, PR A).

These run fully offline against the committed fixtures under
``mylonite/demo/fixtures/{vulnerable,guarded}/`` — no network, no API key.
They prove three things:

* the recorded happy path loads via ``importlib.resources`` with deterministic
  note IDs and yields the 4-vs-0 differential that is the validation oracle;
* replay genuinely never touches the network (litellm.acompletion is patched to
  explode, and ``run_demo`` still succeeds);
* a missing fixture surfaces as the friendly ``DemoFixtureError`` (→ CLI exit 2)
  rather than a silently-clean result or provider-unreachable/exit-4 semantics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import EXIT_CONFIG, app
from mylonite.demo import packaged_fixture_dir
from mylonite.demo.runner import DemoFixtureError, run_demo


def _fixtures_present() -> bool:
    """True when both recorded variants are on disk.

    The fixtures are produced by ``scripts/record_demo_fixtures.py``, which needs
    a live provider key, so a fresh checkout (or a branch mid-re-record) legitimately
    has none. Skipping keeps that state green instead of reporting four failures
    that say nothing about the code under test.

    This is deliberately NOT the only guard. Skipping cannot be allowed to mean
    "the demo is fine" in CI, where a missing or stale fixture set is exactly the
    failure a user would hit on the first command they ever run. CI runs
    ``mylonite demo`` as its own job, which fails loudly on an absent fixture via
    the runner's recorder-state inspection. Do not "fix" a red CI demo job by
    widening this skip.
    """
    root = packaged_fixture_dir()
    return all((root / variant).is_dir() for variant in ("vulnerable", "guarded"))


pytestmark = pytest.mark.skipif(
    not _fixtures_present(),
    reason=(
        "demo fixtures not recorded - run scripts/record_demo_fixtures.py "
        "with a provider key. CI's `mylonite demo` job covers this unskipped."
    ),
)


async def test_demo_recorded_happy_path() -> None:
    """Replay yields ≥1 finding on vulnerable, 0 on guarded, neither aborted."""
    result = await run_demo(live=False)

    assert result.vulnerable.report.findings_count >= 1
    assert result.guarded.report.findings_count == 0
    assert result.vulnerable.report.aborted is None
    assert result.guarded.report.aborted is None
    # startswith, not ==: the label now carries fixture provenance
    # ("recorded <date> against <model>") so a replayed number is never
    # mistaken for a live measurement.
    assert result.mode.startswith("replay (offline)")


async def test_demo_replay_is_zero_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay never calls litellm — patch acompletion to raise and still succeed."""

    async def a_raiser(**_: Any) -> Any:
        raise AssertionError("replay must not touch the network")

    monkeypatch.setattr("litellm.acompletion", a_raiser)

    result = await run_demo(live=False)

    # The differential survives with no network access whatsoever.
    assert result.vulnerable.report.findings_count >= 1
    assert result.guarded.report.findings_count == 0


def _copy_fixtures_to(tmp_path: Path) -> Path:
    """Copy the packaged fixtures into ``tmp_path`` and return the root."""
    src_root = packaged_fixture_dir()
    dst_root = tmp_path / "fixtures"
    for variant in ("vulnerable", "guarded"):
        dst = dst_root / variant
        dst.mkdir(parents=True, exist_ok=True)
        for entry in (src_root / variant).iterdir():
            (dst / entry.name).write_text(entry.read_text(encoding="utf-8"), encoding="utf-8")
    return dst_root


async def test_demo_fixture_miss_surfaces_friendly_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing fixture raises DemoFixtureError, not a silent clean result."""
    dst_root = _copy_fixtures_to(tmp_path)

    # Delete one vulnerable fixture so a (model, messages) key misses.
    vuln_fixtures = sorted((dst_root / "vulnerable").glob("*.json"))
    assert vuln_fixtures, "expected packaged vulnerable fixtures"
    vuln_fixtures[0].unlink()

    monkeypatch.setattr("mylonite.demo.runner.packaged_fixture_dir", lambda: dst_root)

    with pytest.raises(DemoFixtureError):
        await run_demo(live=False)


def test_demo_cli_fixture_miss_maps_to_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the CLI layer, a fixture miss → exit 2 with re-record guidance (plain def)."""
    dst_root = _copy_fixtures_to(tmp_path)
    vuln_fixtures = sorted((dst_root / "vulnerable").glob("*.json"))
    vuln_fixtures[0].unlink()

    monkeypatch.setattr("mylonite.demo.runner.packaged_fixture_dir", lambda: dst_root)

    result = CliRunner().invoke(app, ["demo"])
    assert result.exit_code == EXIT_CONFIG, result.output
    out = result.stderr or result.output
    assert "missing or stale" in out
    assert "Traceback" not in out
