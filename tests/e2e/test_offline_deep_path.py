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

from mylonite.scan.pytest_runner import run_test_file

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import count_llm_calls as counter  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_OFFLINE_E2E") != "1",
    reason="set MYLONITE_OFFLINE_E2E=1 to run (CI runs it in the nr-ci-e2e jobs)",
)


@pytest.fixture(scope="module")
def gate_run(tmp_path_factory: pytest.TempPathFactory) -> Any:
    out_dir = tmp_path_factory.mktemp("offline-deep-path") / "gate"
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
    assert gate_run.result.exit_code == 0
    assert gate_run.result.opened_pr is False


def test_the_emitted_test_passes_offline(gate_run: Any) -> None:
    emitted = sorted(gate_run.out_dir.glob("test_*.py"))
    assert len(emitted) == 1, f"expected one emitted test, found {emitted}"
    result = run_test_file(emitted[0])
    assert result.passed, f"exit_code={result.exit_code}: {result.detail}"


def test_the_gate_stays_within_its_call_budget(gate_run: Any) -> None:
    total = gate_run.scan.total + gate_run.validate.total
    assert counter.over_budget({"gate": total}, counter.load_baseline()) == []
