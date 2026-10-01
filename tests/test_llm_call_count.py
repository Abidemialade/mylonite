"""The reference scan must not get chattier: at most 15% more LLM calls than the baseline.

``scripts/count_llm_calls.py`` drives the real reference scan through a scripted
fake model that counts every call. The baseline in
``tests/fixtures/llm_call_baseline.json`` was measured with that same script on
an older commit. The gate path's count is checked by
``tests/e2e/test_offline_deep_path.py``, which runs the full gate flow.

If a change needs more calls on purpose, re-measure and update the baseline in
the same PR, and say why in its description.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import count_llm_calls as counter  # noqa: E402


def test_budget_allows_fifteen_percent_and_rounds_down() -> None:
    assert counter.budget(100) == 115
    assert counter.budget(34) == 39  # 39.1
    assert counter.budget(0) == 0


def test_over_budget_names_each_path_that_grew_too_much() -> None:
    baseline = {"scan_vulnerable": 34, "scan_guarded": 36}
    assert counter.over_budget({"scan_vulnerable": 39, "scan_guarded": 41}, baseline) == []
    problems = counter.over_budget({"scan_vulnerable": 40, "scan_guarded": 36}, baseline)
    assert len(problems) == 1
    assert problems[0].startswith("scan_vulnerable: 40 calls, budget 39")


def test_the_baseline_covers_scan_and_gate() -> None:
    assert set(counter.load_baseline()) == {"scan_vulnerable", "scan_guarded", "gate"}


@pytest.mark.parametrize("variant", ["vulnerable", "guarded"])
def test_reference_scan_stays_within_its_call_budget(variant: str) -> None:
    result, fake = counter.run_reference_scan(variant)  # type: ignore[arg-type]

    # Every planner call was answered from a recording: a miss means the run
    # took a path the recordings never saw, so its count means nothing.
    assert fake.planner_misses == 0, f"{fake.planner_misses} planner call(s) had no recording"
    # The customiser and judge stages really ran, so their calls are counted too.
    assert fake.calls["customiser"] > 0
    assert fake.calls["judge"] > 0
    assert result.report.attempts, "the scan made no attempts"

    path = f"scan_{variant}"
    assert counter.over_budget({path: fake.total}, counter.load_baseline()) == []
