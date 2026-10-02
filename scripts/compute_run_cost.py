#!/usr/bin/env python3
"""Compute one CI run's $ cost from the token counts Mylonite already prints.

Why this exists
----------------
``mylonite scan``/``validate``/``gate`` already print an ``llm:`` summary line
with the provider-reported prompt/completion token totals for the run (see
``mylonite.scan.artefacts.format_spend``/``spend_summary``) -- but nothing
turns that into a dollar figure, and the third-party campaign
(``.github/workflows/third-party-campaign.yml``) needs a ``cost.json`` per
run (see ``docs/superpowers/plans/2026-10-02-l2-master-plan.md``'s TPV-0 row).

Mylonite does not record a $ cost anywhere today -- only token counts, and
only in that printed line, not in ``scan_report.json``. Adding cost tracking
to ``src/mylonite`` would be a runtime behaviour change for a one-off CI
need, so this script instead parses the token counts out of the command's
*already-captured* stdout log and multiplies by the model's per-token rate
(the caller supplies both; see ``verification/PREREG_L2_THIRD_PARTY.md``'s
"Provider and model" section for the two rates this campaign uses). The
whole computation stays workflow-side; nothing in ``src/mylonite`` changes.

If a log contains more than one ``llm:`` line (e.g. a ``gate`` run that scans
and then validates), every line's tokens are summed.

Usage
-----

::

    python scripts/compute_run_cost.py run.log \\
        --model openai/gpt-4o-mini --in-rate 0.15 --out-rate 0.60 \\
        --out cost.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

#: Matches the "P in / C out tokens" fragment ``format_spend`` always emits
#: when at least one call reported usage. Deliberately not anchored to the
#: rest of the line: the separator around it is " | " on an ASCII-only
#: stdout and " · " otherwise (``_stdout_is_ascii_only``), and this must
#: match either.
_TOKENS_RE = re.compile(r"([\d,]+)\s+in\s*/\s*([\d,]+)\s+out tokens")


def parse_tokens(log_text: str) -> tuple[int, int]:
    """Sum every "P in / C out tokens" fragment found in a captured log."""
    prompt_total = 0
    completion_total = 0
    for prompt_str, completion_str in _TOKENS_RE.findall(log_text):
        prompt_total += int(prompt_str.replace(",", ""))
        completion_total += int(completion_str.replace(",", ""))
    return prompt_total, completion_total


def compute_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    *,
    in_rate_per_million: float,
    out_rate_per_million: float,
) -> float:
    return (prompt_tokens / 1_000_000) * in_rate_per_million + (
        completion_tokens / 1_000_000
    ) * out_rate_per_million


def build_result(
    log_text: str,
    *,
    model: str,
    in_rate_per_million: float,
    out_rate_per_million: float,
) -> dict[str, object]:
    prompt_tokens, completion_tokens = parse_tokens(log_text)
    cost_usd = compute_cost_usd(
        prompt_tokens,
        completion_tokens,
        in_rate_per_million=in_rate_per_million,
        out_rate_per_million=out_rate_per_million,
    )
    return {
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "in_rate_per_million_usd": in_rate_per_million,
        "out_rate_per_million_usd": out_rate_per_million,
        "cost_usd": round(cost_usd, 6),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "log_file",
        type=Path,
        help="Captured stdout of one or more mylonite invocations (e.g. via `tee`).",
    )
    parser.add_argument("--model", required=True, help="litellm model id this run used.")
    parser.add_argument(
        "--in-rate", type=float, required=True, dest="in_rate", help="$ per 1M input tokens."
    )
    parser.add_argument(
        "--out-rate", type=float, required=True, dest="out_rate", help="$ per 1M output tokens."
    )
    parser.add_argument("--out", type=Path, required=True, help="Where to write cost.json.")
    args = parser.parse_args(argv)

    text = args.log_file.read_text(encoding="utf-8", errors="replace")
    result = build_result(
        text, model=args.model, in_rate_per_million=args.in_rate, out_rate_per_million=args.out_rate
    )
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
