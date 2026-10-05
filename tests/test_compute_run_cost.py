"""`compute_run_cost.py` turns Mylonite's already-printed `llm:` spend line
into a `cost.json` for the third-party campaign, without any change to
`src/mylonite` (see the script's module docstring and
`verification/PREREG_THIRD_PARTY_2026_10.md`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import compute_run_cost as cost


def test_parses_a_single_llm_line_with_the_ascii_separator() -> None:
    log = "llm: 12 calls (planner 8, judge 4) of 50 cap | 3,200 in / 410 out tokens | 12.6s\n"
    spend = cost.parse_spend(log)
    assert spend.calls == 12
    assert (spend.prompt_tokens, spend.completion_tokens) == (3200, 410)
    assert spend.partial is None


def test_parses_a_single_llm_line_with_the_rich_separator() -> None:
    log = "llm: 3 calls · 1,000 in / 200 out tokens · 2.0s\n"
    spend = cost.parse_spend(log)
    assert spend.calls == 3
    assert (spend.prompt_tokens, spend.completion_tokens) == (1000, 200)


def test_sums_calls_and_tokens_across_multiple_llm_lines_in_one_log() -> None:
    log = "\n".join(
        [
            "llm: 2 calls | 500 in / 100 out tokens | 1.0s",
            "some unrelated output",
            "gate llm: 3 calls | 1,500 in / 300 out tokens | 2.0s",
        ]
    )
    spend = cost.parse_spend(log)
    assert spend.calls == 5
    assert (spend.prompt_tokens, spend.completion_tokens) == (2000, 400)


def test_a_run_that_reported_no_usage_has_zero_tokens_but_a_real_call_count() -> None:
    log = "llm: 1 calls (planner 1) of 10 cap | 0.3s\n"
    spend = cost.parse_spend(log)
    assert spend.calls == 1
    assert (spend.prompt_tokens, spend.completion_tokens) == (0, 0)


def test_a_partial_usage_marker_is_captured_not_dropped() -> None:
    log = "llm: 5 calls | 2,000 in / 400 out tokens (reported by 3 of 5 calls) | 4.0s\n"
    spend = cost.parse_spend(log)
    assert spend.partial == (3, 5)


def test_no_llm_line_at_all_raises_instead_of_reporting_zero_cost() -> None:
    with pytest.raises(cost.NoSpendLineFoundError):
        cost.parse_spend("Traceback (most recent call last):\n  ...\nSomeError: boom\n")


def test_compute_cost_usd_matches_the_rate_table() -> None:
    # gpt-4o-mini: $0.15 / M in, $0.60 / M out (verification/PREREG_THIRD_PARTY_2026_10.md).
    cost_usd = cost.compute_cost_usd(
        1_000_000, 1_000_000, in_rate_per_million=0.15, out_rate_per_million=0.60
    )
    assert cost_usd == 0.75


def test_build_result_shape() -> None:
    log = "llm: 1 calls | 1,000,000 in / 0 out tokens | 1.0s\n"
    result = cost.build_result(
        log,
        model="openai/gpt-4o-mini",
        in_rate_per_million=0.15,
        out_rate_per_million=0.60,
        ref="deadbeef",
    )
    assert result == {
        "model": "openai/gpt-4o-mini",
        "ref": "deadbeef",
        "calls": 1,
        "prompt_tokens": 1_000_000,
        "completion_tokens": 0,
        "in_rate_per_million_usd": 0.15,
        "out_rate_per_million_usd": 0.60,
        "cost_usd": 0.15,
    }


def test_build_result_includes_partial_when_present() -> None:
    log = "llm: 2 calls | 1,000 in / 100 out tokens (reported by 1 of 2 calls) | 1.0s\n"
    result = cost.build_result(
        log, model="x", in_rate_per_million=1.0, out_rate_per_million=1.0, ref="abc123"
    )
    assert result["partial"] == {"reported_by": 1, "of_calls": 2}


def test_cli_writes_cost_json(tmp_path: Path) -> None:
    log_file = tmp_path / "run.log"
    log_file.write_text("llm: 1 calls | 2,000 in / 1,000 out tokens | 1.0s\n", encoding="utf-8")
    out_file = tmp_path / "cost.json"

    rc = cost.main(
        [
            str(log_file),
            "--model",
            "anthropic/claude-haiku-4-5-20251001",
            "--in-rate",
            "1.0",
            "--out-rate",
            "5.0",
            "--ref",
            "cafef00d",
            "--out",
            str(out_file),
        ]
    )

    assert rc == 0
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["calls"] == 1
    assert written["prompt_tokens"] == 2000
    assert written["completion_tokens"] == 1000
    assert written["ref"] == "cafef00d"
    assert written["cost_usd"] == round(2000 / 1_000_000 * 1.0 + 1000 / 1_000_000 * 5.0, 6)


def test_cli_fails_loudly_when_no_spend_line_is_present(tmp_path: Path) -> None:
    log_file = tmp_path / "run.log"
    log_file.write_text("Traceback (most recent call last):\nboom\n", encoding="utf-8")
    out_file = tmp_path / "cost.json"

    rc = cost.main(
        [
            str(log_file),
            "--model",
            "x",
            "--in-rate",
            "1.0",
            "--out-rate",
            "1.0",
            "--ref",
            "abc",
            "--out",
            str(out_file),
        ]
    )

    assert rc != 0
    assert not out_file.exists()


def test_preflight_refusal_signature_matches_a_myl_pre_code() -> None:
    log = (
        "error: [MYL-PRE-003] could not describe the server (AdapterDescribeFailed) "
        "to check which declared weakness classes can run.\n"
    )
    assert cost.preflight_refusal_signature(log) == "MYL-PRE-003"


def test_preflight_refusal_signature_matches_the_reference_app_refusal() -> None:
    log = (
        "the reference app target isn't installed (it's opt-in) — run "
        "`pip install mcp-kitchen-sink`.\n"
    )
    assert cost.preflight_refusal_signature(log) == "isn't installed"


def test_preflight_refusal_signature_is_none_for_an_unrecognised_crash() -> None:
    assert cost.preflight_refusal_signature("Traceback (most recent call last):\nboom\n") is None


def test_build_result_for_preflight_refusal_is_zero_cost_not_an_error() -> None:
    result = cost.build_result_for_preflight_refusal(
        model="anthropic/claude-sonnet-5", ref="abc123", signature="MYL-PRE-003"
    )
    assert result["calls"] == 0
    assert result["cost_usd"] == 0.0
    assert "MYL-PRE-003" in result["reason"]


def test_cli_writes_a_zero_cost_json_for_a_preflight_refusal_with_no_spend_line(
    tmp_path: Path,
) -> None:
    """Mirrors the real e2e-reference-w1 run: `scan` refuses before any LLM
    call (no reference app installed), so run.log EXISTS but has no `llm:`
    line at all -- this must read as a $0 run with a named reason, not fail
    the job."""
    log_file = tmp_path / "run.log"
    log_file.write_text(
        "Run plan (nothing has been sent yet):\n"
        "  Model: anthropic/claude-sonnet-5 (planner, customiser and judge)\n"
        "the reference app target isn't installed (it's opt-in) — run "
        "`pip install mcp-kitchen-sink`, or from a checkout "
        "`pip install -e ./reference_targets/mcp_kitchen_sink`.\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "cost.json"

    rc = cost.main(
        [
            str(log_file),
            "--model",
            "anthropic/claude-sonnet-5",
            "--in-rate",
            "2.0",
            "--out-rate",
            "10.0",
            "--ref",
            "e5339d49",
            "--out",
            str(out_file),
        ]
    )

    assert rc == 0
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["calls"] == 0
    assert written["cost_usd"] == 0.0
    assert "isn't installed" in written["reason"]


def test_cli_still_fails_loudly_on_a_mid_run_crash_with_no_preflight_signature(
    tmp_path: Path,
) -> None:
    """A log that exists, has no `llm:` line, and shows no recognised
    pre-flight refusal signature is a genuine crash (or a signature this
    script doesn't know about yet) -- it must still raise, never report
    $0. Distinct from the pre-flight-refusal test above only by which
    signature (if any) the log text carries."""
    log_file = tmp_path / "run.log"
    log_file.write_text(
        "Run plan (nothing has been sent yet):\n"
        "Traceback (most recent call last):\n"
        '  File "mylonite/scan/engine.py", line 1, in <module>\n'
        "RuntimeError: boom\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "cost.json"

    rc = cost.main(
        [
            str(log_file),
            "--model",
            "x",
            "--in-rate",
            "1.0",
            "--out-rate",
            "1.0",
            "--ref",
            "abc",
            "--out",
            str(out_file),
        ]
    )

    assert rc != 0
    assert not out_file.exists()


def test_build_result_for_missing_log_is_zero_cost_not_an_error() -> None:
    result = cost.build_result_for_missing_log(
        model="anthropic/claude-haiku-4-5-20251001", ref="abc123"
    )
    assert result["calls"] == 0
    assert result["cost_usd"] == 0.0
    assert "reason" in result


def test_cli_writes_a_zero_cost_json_when_run_log_does_not_exist(tmp_path: Path) -> None:
    """An earlier workflow step failing before any mylonite command ran
    means run.log never existed -- genuinely $0, not an error to raise
    about (unlike a run.log that EXISTS with no spend line, which still
    raises -- see the previous test)."""
    missing_log = tmp_path / "run.log"
    out_file = tmp_path / "cost.json"
    assert not missing_log.exists()

    rc = cost.main(
        [
            str(missing_log),
            "--model",
            "openai/gpt-4o-mini",
            "--in-rate",
            "0.15",
            "--out-rate",
            "0.60",
            "--ref",
            "deadbeef",
            "--out",
            str(out_file),
        ]
    )

    assert rc == 0
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["calls"] == 0
    assert written["cost_usd"] == 0.0
    assert "reason" in written
