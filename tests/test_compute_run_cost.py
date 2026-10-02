"""`compute_run_cost.py` turns Mylonite's already-printed `llm:` spend line
into a `cost.json` for the third-party campaign, without any change to
`src/mylonite` (see the script's module docstring and
`verification/PREREG_L2_THIRD_PARTY.md`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import compute_run_cost as cost


def test_parses_a_single_llm_line_with_the_ascii_separator() -> None:
    log = "llm: 12 calls (planner 8, judge 4) of 50 cap | 3,200 in / 410 out tokens | 12.6s\n"
    assert cost.parse_tokens(log) == (3200, 410)


def test_parses_a_single_llm_line_with_the_rich_separator() -> None:
    log = "llm: 3 calls · 1,000 in / 200 out tokens · 2.0s\n"
    assert cost.parse_tokens(log) == (1000, 200)


def test_sums_tokens_across_multiple_llm_lines_in_one_log() -> None:
    log = "\n".join(
        [
            "llm: 2 calls | 500 in / 100 out tokens | 1.0s",
            "some unrelated output",
            "gate llm: 3 calls | 1,500 in / 300 out tokens | 2.0s",
        ]
    )
    assert cost.parse_tokens(log) == (2000, 400)


def test_a_run_that_reported_no_usage_costs_nothing() -> None:
    log = "llm: 1 calls (planner 1) of 10 cap | 0.3s\n"
    assert cost.parse_tokens(log) == (0, 0)


def test_compute_cost_usd_matches_the_rate_table() -> None:
    # gpt-4o-mini: $0.15 / M in, $0.60 / M out (verification/PREREG_L2_THIRD_PARTY.md).
    cost_usd = cost.compute_cost_usd(
        1_000_000, 1_000_000, in_rate_per_million=0.15, out_rate_per_million=0.60
    )
    assert cost_usd == 0.75


def test_build_result_shape() -> None:
    log = "llm: 1 calls | 1,000,000 in / 0 out tokens | 1.0s\n"
    result = cost.build_result(
        log, model="openai/gpt-4o-mini", in_rate_per_million=0.15, out_rate_per_million=0.60
    )
    assert result == {
        "model": "openai/gpt-4o-mini",
        "prompt_tokens": 1_000_000,
        "completion_tokens": 0,
        "in_rate_per_million_usd": 0.15,
        "out_rate_per_million_usd": 0.60,
        "cost_usd": 0.15,
    }


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
            "--out",
            str(out_file),
        ]
    )

    assert rc == 0
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["prompt_tokens"] == 2000
    assert written["completion_tokens"] == 1000
    assert written["cost_usd"] == round(2000 / 1_000_000 * 1.0 + 1000 / 1_000_000 * 5.0, 6)
