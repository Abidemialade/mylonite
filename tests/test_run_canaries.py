"""Unit tests for scripts/run_canaries.py: aggregation and bar logic only.

No network, no subprocess, no live model call -- every canary run fed into
``aggregate`` here is a hand-built ``CanaryRun``, never the result of
actually invoking the CLI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import run_canaries as rc  # noqa: E402

# --- required_passes ---------------------------------------------------------


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 2),  # the literal rule this project uses: at least 2 of 3
        (6, 4),
        (9, 6),
    ],
)
def test_required_passes(n: int, expected: int) -> None:
    assert rc.required_passes(n) == expected


# --- aggregate ----------------------------------------------------------


def _run(canary_id: str, i: int, *, bar_met: bool, verdict: str = "X") -> rc.CanaryRun:
    return rc.CanaryRun(canary_id=canary_id, run_index=i, verdict=verdict, bar_met=bar_met)


def test_aggregate_passes_when_all_three_meet_the_bar() -> None:
    runs = [_run("w4", i, bar_met=True) for i in range(3)]
    agg = rc.aggregate("w4", runs)
    assert agg.meets_bar is True
    assert agg.required == 2
    assert agg.passes == 3
    assert agg.skipped is False


def test_aggregate_passes_on_exactly_two_of_three() -> None:
    runs = [_run("w4", 0, bar_met=True), _run("w4", 1, bar_met=True), _run("w4", 2, bar_met=False)]
    agg = rc.aggregate("w4", runs)
    assert agg.meets_bar is True
    assert agg.passes == 2


def test_aggregate_fails_on_only_one_of_three() -> None:
    runs = [_run("w4", 0, bar_met=True), _run("w4", 1, bar_met=False), _run("w4", 2, bar_met=False)]
    agg = rc.aggregate("w4", runs)
    assert agg.meets_bar is False
    assert agg.passes == 1


def test_aggregate_fails_on_zero_of_three() -> None:
    runs = [_run("guarded", i, bar_met=False) for i in range(3)]
    agg = rc.aggregate("guarded", runs)
    assert agg.meets_bar is False
    assert agg.passes == 0


def test_aggregate_with_no_runs_is_skipped_not_failed() -> None:
    agg = rc.aggregate("custom-redrive", [])
    assert agg.skipped is True
    assert agg.meets_bar is False


def test_aggregate_all_skipped_verdicts_is_skipped_not_failed() -> None:
    runs = [
        rc.CanaryRun(
            canary_id="custom-redrive",
            run_index=i,
            verdict="SKIPPED",
            bar_met=False,
            detail="no target file",
        )
        for i in range(3)
    ]
    agg = rc.aggregate("custom-redrive", runs)
    assert agg.skipped is True
    assert agg.skip_reason == "no target file"
    # A skipped canary never meets the bar, but it is excluded from the
    # pass/fail decision at the call site, not treated as a FAIL here.
    assert agg.meets_bar is False


def test_aggregate_a_single_run_requires_that_one_run_to_pass() -> None:
    agg_pass = rc.aggregate("w4", [_run("w4", 0, bar_met=True)])
    agg_fail = rc.aggregate("w4", [_run("w4", 0, bar_met=False)])
    assert agg_pass.meets_bar is True
    assert agg_fail.meets_bar is False


# --- parse_llm_summary --------------------------------------------------


def test_parse_llm_summary_pipe_separator() -> None:
    line = "llm: 362 calls (planner 150, customiser 150, judge 62) of 500 cap | 433,000 in / 38,000 out tokens | 253.4s"
    summary = rc.parse_llm_summary(f"some other output\n{line}\nmore output")
    assert summary.calls == 362
    assert summary.prompt_tokens == 433000
    assert summary.completion_tokens == 38000
    assert summary.seconds == pytest.approx(253.4)


def test_parse_llm_summary_middle_dot_separator() -> None:
    line = "llm: 32 calls (planner 32) · 12,000 in / 1,000 out tokens · 45.0s"
    summary = rc.parse_llm_summary(line)
    assert summary.calls == 32
    assert summary.prompt_tokens == 12000
    assert summary.completion_tokens == 1000
    assert summary.seconds == pytest.approx(45.0)


def test_parse_llm_summary_with_no_matching_line_is_empty() -> None:
    summary = rc.parse_llm_summary("no llm line in this output at all\nexit 0")
    assert summary.calls is None
    assert summary.prompt_tokens is None
    assert summary.seconds is None


def test_parse_llm_summary_with_no_tokens_reported() -> None:
    # Some calls report no usage at all; format_spend then omits the tokens
    # clause entirely rather than printing a misleading zero.
    summary = rc.parse_llm_summary("llm: 5 calls of 50 cap")
    assert summary.calls == 5
    assert summary.prompt_tokens is None
    assert summary.completion_tokens is None


# --- cost cap sizing -----------------------------------------------------


def test_max_calls_for_budget() -> None:
    assert rc.max_calls_for_budget(5.0, 0.0025) == 2000


def test_max_calls_for_budget_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        rc.max_calls_for_budget(5.0, 0.0)


def test_scan_call_cap_uses_headroom_when_under_the_dollar_budget() -> None:
    # 362 * 1.15 = 416.3 -> 417, well under the $5/$0.0025 = 2000-call budget.
    assert rc.scan_call_cap(362, max_cost_per_run=5.0, dollars_per_call=0.0025) == 417


def test_scan_call_cap_clamps_to_the_dollar_budget_when_tighter() -> None:
    # A tiny dollar cap must win even though the headroom cap is larger.
    assert rc.scan_call_cap(362, max_cost_per_run=0.01, dollars_per_call=0.0025) == 4


# --- main(): orchestration with faked canary runners, no subprocess --------


def _fake_always_passes(ctx: rc.RunContext, run_index: int) -> rc.CanaryRun:
    return rc.CanaryRun(canary_id="fake-pass", run_index=run_index, verdict="OK", bar_met=True)


def _fake_always_fails(ctx: rc.RunContext, run_index: int) -> rc.CanaryRun:
    return rc.CanaryRun(canary_id="fake-fail", run_index=run_index, verdict="BAD", bar_met=False)


def _fake_skipped(ctx: rc.RunContext, run_index: int) -> rc.CanaryRun:
    return rc.CanaryRun(
        canary_id="fake-skip",
        run_index=run_index,
        verdict="SKIPPED",
        bar_met=False,
        detail="not configured",
    )


def test_main_exits_zero_when_every_canary_meets_its_bar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        rc, "CANARIES", {"fake-pass": _fake_always_passes, "fake-skip": _fake_skipped}
    )
    code = rc.main(["--model", "fake/model", "--runs", "3", "--out-dir", str(tmp_path)])
    assert code == 0
    report = json.loads((tmp_path / "canaries_report.json").read_text(encoding="utf-8"))
    ids = {c["canary_id"] for c in report["canaries"]}
    assert ids == {"fake-pass", "fake-skip"}
    skip_entry = next(c for c in report["canaries"] if c["canary_id"] == "fake-skip")
    assert skip_entry["skipped"] is True


def test_main_exits_nonzero_when_a_canary_misses_its_bar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rc, "CANARIES", {"fake-fail": _fake_always_fails})
    code = rc.main(["--model", "fake/model", "--runs", "3", "--out-dir", str(tmp_path)])
    assert code == 1


def test_main_requires_a_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MYLONITE_CANARY_MODEL", raising=False)
    code = rc.main(["--runs", "1", "--out-dir", str(tmp_path)])
    assert code == 2


def test_main_never_writes_a_key_looking_string_to_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rc, "CANARIES", {"fake-pass": _fake_always_passes})
    rc.main(["--model", "fake/model", "--runs", "1", "--out-dir", str(tmp_path)])
    text = (tmp_path / "canaries_report.json").read_text(encoding="utf-8")
    assert "sk-ant-" not in text
    assert "ANTHROPIC_API_KEY" not in text
