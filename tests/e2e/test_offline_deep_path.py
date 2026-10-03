"""The deepest offline path: reference scan, generate, validate, then run the emitted test.

One run, no provider and no network:

1. the real reference scan of the vulnerable twin, with the planner replaying
   the demo's recordings and the customiser and judge scripted;
2. its finding for the committed example's seed goes through the real gate:
   the pytest generator writes the test, and the differential validator
   replays the committed recordings for both twins;
3. the emitted test runs under pytest, offline, the way a user's CI runs it.

It also checks the gate path's LLM call count against the committed baseline.

This takes a while on Windows, so the main test jobs skip it. CI runs it in
the ``nr-ci-e2e`` jobs (Linux and Windows) on every pull request, with
``MYLONITE_OFFLINE_E2E=1``. Run it locally the same way.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mylonite.exit_codes import EXIT_GATE_KEPT
from mylonite.scan.pytest_runner import run_test_file

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import count_llm_calls as counter  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_OFFLINE_E2E") != "1",
    reason="set MYLONITE_OFFLINE_E2E=1 to run (CI runs it in the nr-ci-e2e jobs)",
)


#: Set in CI's Windows deep-path job: put the gate dir as deep as `gate`'s own
#: path check accepts. This run is a single kept finding, so it writes a few
#: characters short of the modelled bound; what it shows is that no file the
#: check does not model goes past the limit.
DEEP_OUT = os.environ.get("MYLONITE_E2E_DEEP_OUT") == "1"


def _out_dir(base: Path) -> Path:
    if not DEEP_OUT:
        return base / "gate"
    from mylonite.gate.orchestrator import WINDOWS_MAX_PATH, gate_path_problem

    out = base / "g"
    assert gate_path_problem(out, limit=WINDOWS_MAX_PATH) is None, f"{base} is already too deep"
    while gate_path_problem(out.with_name(out.name + "g"), limit=WINDOWS_MAX_PATH) is None:
        out = out.with_name(out.name + "g")
    return out


@pytest.fixture(scope="module")
def gate_run(tmp_path_factory: pytest.TempPathFactory) -> Any:
    out_dir = _out_dir(tmp_path_factory.mktemp("offline-deep-path"))
    return counter.run_reference_gate(out_dir)


def _example_seed() -> str:
    meta_path = ROOT / counter.EXAMPLE_DIRNAME / "differential_fixtures" / "_meta.json"
    return str(json.loads(meta_path.read_text(encoding="utf-8"))["pattern_id"])


def test_the_scan_finds_the_seed_the_gate_validates(gate_run: Any) -> None:
    assert _example_seed() in gate_run.exploits_found


def test_every_call_was_answered_from_a_recording(gate_run: Any) -> None:
    assert gate_run.scan.planner_misses == 0
    assert gate_run.validate.planner_misses == 0


def test_the_gate_keeps_the_generated_test(gate_run: Any) -> None:
    assert gate_run.result.kept is True
    assert gate_run.result.exit_code == EXIT_GATE_KEPT
    assert gate_run.result.opened_pr is False


def test_the_emitted_test_passes_offline(gate_run: Any) -> None:
    emitted = sorted(gate_run.out_dir.glob("test_*.py"))
    assert len(emitted) == 1, f"expected one emitted test, found {emitted}"
    result = run_test_file(emitted[0])
    assert result.passed, f"exit_code={result.exit_code}: {result.detail}"


def test_the_gate_stays_within_its_call_budget(gate_run: Any) -> None:
    total = gate_run.scan.total + gate_run.validate.total
    assert counter.over_budget({"gate": total}, counter.load_baseline()) == []


@pytest.mark.skipif(not DEEP_OUT, reason="set MYLONITE_E2E_DEEP_OUT=1 (CI's Windows deep-path job)")
def test_every_written_path_fits_the_windows_limit(gate_run: Any) -> None:
    from mylonite.gate.orchestrator import WINDOWS_MAX_PATH, gate_paths

    # The gate dir sits right at the edge the path check allows...
    assert max(len(str(p)) for p in gate_paths(gate_run.out_dir)) == WINDOWS_MAX_PATH
    # ...and nothing the run wrote went past the limit.
    written = list(gate_run.out_dir.parent.rglob("*"))
    assert written
    too_long = [p for p in written if len(str(p)) > WINDOWS_MAX_PATH]
    assert too_long == []
