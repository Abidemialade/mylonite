"""A two-finding reference gate writes a directory that passes ``pytest`` on its
first run, offline, with no provider key.

Each kept finding lives in its own ``<gate dir>/<id>/`` and its emitted test
replays ``<id>/fixtures``. The validator must record each finding's replay
fixtures into that finding's own directory: a single shared ``fixtures/`` at the
gate root left every test but the last without matching recordings, and the
validator's own copy of the test at the root broke pytest collection.

Offline: only ``litellm.acompletion`` is replaced, by the same scripted
completion the validator's own record tests use. The gate's real
``make_validate_fn`` (reference route), the real generator, the real
orchestrator and the real ``open_pr_fn`` (print mode, git step recorded) run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.plugins.test_differential_validator import _build_exploit
from tests.plugins.test_record_during_validate import _install_fake_acompletion

from mylonite.gate import pr as real_pr_mod
from mylonite.gate.orchestrator import ScanOutcomeBundle, _finding_id, run_gate
from mylonite.gate.wiring import make_open_pr_fn, make_validate_fn
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.scan.coverage import Coverage, ScanOutcome

_PATTERNS = ("indirect-injection-note-body-direct", "indirect-injection-note-body-roleplay")
_REPO_SRC = str(Path(__file__).resolve().parents[2] / "src")


def _folder(out_dir: Path, pattern: str) -> Path:
    """The short-id folder the gate gives this pattern's finding."""
    return out_dir / _finding_id(_build_exploit(pattern))


def _two_found() -> ScanOutcome:
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=2,
        not_tested=0,
        findings=2,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


def _reference_validate_fn(out_dir: Path) -> Any:
    model = "claude-haiku-4-5-20251001"
    return make_validate_fn(
        is_reference=True,
        iterations=2,
        effective_provider="anthropic",
        effective_model=model,
        effective_planner_model=model,
        planner_model=None,
        effective_customiser_model=model,
        customiser_model=None,
        effective_judge_model=model,
        judge_model=None,
        out=out_dir,
        effective_policy=None,
        routed_to="reference",
        custom_spec=None,
        mcp_scope=None,
        tf=None,
        fast=False,
        randomize_exfil=False,
    )


@pytest.fixture(scope="module")
def two_finding_gate(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Any, Path, list[Any]]:
    """Run the gate once on two kept reference findings and share the result."""
    mp = pytest.MonkeyPatch()
    try:
        _install_fake_acompletion(mp)
        repo = tmp_path_factory.mktemp("two-finding-gate")
        out_dir = repo / ".mylonite" / "gate"
        captured: list[Any] = []

        def _capture(paths: Any, **_kwargs: Any) -> Any:
            captured.append(paths)
            return SimpleNamespace(opened=False, branch=None, commit_sha=None)

        pr_mod = SimpleNamespace(
            GatePaths=real_pr_mod.GatePaths,
            open_or_print_pr=_capture,
            resolve_repo_root=lambda: repo,
            resolve_default_base=lambda _root: "main",
        )
        result = run_gate(
            out_dir=out_dir,
            scan_fn=lambda: ScanOutcomeBundle(
                outcome=_two_found(), exploits=[_build_exploit(p) for p in _PATTERNS]
            ),
            generate_fn=ReferencePytestGenerator().emit,
            validate_fn=_reference_validate_fn(out_dir),
            open_pr_fn=make_open_pr_fn(
                runs_on="ubuntu-latest",
                workflows=False,
                target_file=None,
                pr_mod=pr_mod,
                model="anthropic/claude-haiku-4-5-20251001",
            ),
            open_pr=False,
        )
    finally:
        mp.undo()
    return result, out_dir, captured


def test_both_findings_are_kept(two_finding_gate: tuple[Any, Path, list[Any]]) -> None:
    result, _out, _captured = two_finding_gate
    assert result.kept is True
    assert result.exit_code == 0


def test_each_finding_records_its_own_fixtures(
    two_finding_gate: tuple[Any, Path, list[Any]],
) -> None:
    import json

    _result, out_dir, _captured = two_finding_gate
    for pattern in _PATTERNS:
        meta_path = _folder(out_dir, pattern) / "fixtures" / "_meta.json"
        assert meta_path.is_file(), f"no fixtures recorded for {pattern}"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["pattern_id"] == pattern


def test_nothing_is_written_at_the_gate_root(
    two_finding_gate: tuple[Any, Path, list[Any]],
) -> None:
    """A test or exploit copy at the root collides with the per-finding ones
    under pytest, and a root ``fixtures/`` belongs to no test."""
    _result, out_dir, _captured = two_finding_gate
    assert not list(out_dir.glob("test_*.py"))
    assert not list(out_dir.glob("exploit_*.json"))
    assert not (out_dir / "fixtures").exists()


def test_the_gate_dir_passes_pytest_on_its_first_run_offline(
    two_finding_gate: tuple[Any, Path, list[Any]],
) -> None:
    """What CI runs: ``pytest <gate dir>``, in a fresh process with no key."""
    _result, out_dir, _captured = two_finding_gate
    run = _pytest(out_dir)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "2 passed" in run.stdout, run.stdout


@pytest.mark.skipif(
    os.environ.get("MYLONITE_E2E_DEEP_OUT") != "1",
    reason="set MYLONITE_E2E_DEEP_OUT=1 (CI's Windows deep-path job)",
)
def test_every_path_in_the_project_fits_the_windows_limit(
    two_finding_gate: tuple[Any, Path, list[Any]],
) -> None:
    """In CI's deep-path job the project root is 200 characters long. Every
    file and folder the gate and its pytest run left there must fit."""
    from mylonite.gate.orchestrator import WINDOWS_MAX_PATH

    _result, out_dir, _captured = two_finding_gate
    project = out_dir.parent.parent
    written = list(project.rglob("*"))
    assert written
    assert [p for p in written if len(str(p)) > WINDOWS_MAX_PATH] == []


def test_colliding_pattern_ids_still_collect_as_two_tests(tmp_path: Path) -> None:
    """Two similar pattern_ids get separate folders and, with the real
    generator, distinct test file names, so pytest collects both."""
    from mylonite.contracts import ValidationReport

    out_dir = tmp_path / ".mylonite" / "gate"
    patterns = ("indirect-injection-note-body-direct", "indirect.injection.note.body.direct")
    run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(
            outcome=_two_found(), exploits=[_build_exploit(p) for p in patterns]
        ),
        generate_fn=ReferencePytestGenerator().emit,
        validate_fn=lambda g, _d: ValidationReport(test_filename=g.filename, kept=True),
        open_pr_fn=lambda **_k: None,
        open_pr=False,
    )

    run = _pytest(out_dir, "--collect-only")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "2 tests collected" in run.stdout, run.stdout


def _ci_env() -> dict[str, str]:
    """The environment of the emitted per-PR workflow, minus every credential:
    no provider key, no token, no Mylonite setting from this machine."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not (k.endswith(("_KEY", "_TOKEN")) or k.startswith("MYLONITE_"))
    }
    env.update(
        {
            "MYLONITE_LIVE_TARGET": "1",
            "MYLONITE_REQUIRE_GATE_RUN": "1",
            "PYTHONPATH": _REPO_SRC,
            "PYTHONUTF8": "1",
        }
    )
    return env


def _pytest(gate_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args, str(gate_dir)],
        cwd=str(gate_dir.parent.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_ci_env(),
    )


def test_the_commit_names_each_findings_fixtures(
    two_finding_gate: tuple[Any, Path, list[Any]],
) -> None:
    _result, out_dir, captured = two_finding_gate
    assert len(captured) == 1
    add_paths = set(captured[0].add_paths)
    for pattern in _PATTERNS:
        assert _folder(out_dir, pattern) / "fixtures" in add_paths
    assert out_dir / "fixtures" not in add_paths
