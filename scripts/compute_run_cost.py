#!/usr/bin/env python3
"""Compute one CI run's $ cost from the token counts Mylonite already prints.

Why this exists
----------------
``mylonite scan``/``validate``/``gate`` already print an ``llm:`` summary line
with the call count and the provider-reported prompt/completion token totals
for the run (see ``mylonite.scan.artefacts.format_spend``/``spend_summary``)
-- but nothing turns that into a dollar figure, and the third-party campaign
(``.github/workflows/third-party-campaign.yml``) needs a ``cost.json`` per
run.

Mylonite does not record a $ cost anywhere today -- only token counts, and
only in that printed line, not in ``scan_report.json``. Adding cost tracking
to ``src/mylonite`` would be a runtime behaviour change for a one-off CI
need, so this script instead parses the token counts out of the command's
*already-captured* stdout log and multiplies by the model's per-token rate
(the caller supplies both; see
``verification/PREREG_THIRD_PARTY_2026_10.md``'s "Provider and model"
section for the two rates this campaign uses). The whole computation stays
workflow-side; nothing in ``src/mylonite`` changes.

If a log contains more than one ``llm:`` line (e.g. a run that scans and
then validates), every line's calls and tokens are summed. **A log with no
``llm:`` line at all is an error, not a $0 run** -- a crashed or
incomplete scan must never silently cost nothing; the caller (the scorer)
decides separately whether that crash is a product defect or an
infrastructure failure.

Usage
-----

::

    python scripts/compute_run_cost.py run.log \\
        --model openai/gpt-4o-mini --in-rate 0.15 --out-rate 0.60 \\
        --ref <commit-sha> --out cost.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

#: The call count `format_spend` always emits as the first clause of the
#: `llm:` line, e.g. "llm: 12 calls (planner 8, judge 4) of 50 cap | ...".
_CALLS_RE = re.compile(r"\bllm:\s*(\d+)\s*calls\b")

#: The "P in / C out tokens" fragment, present only when at least one call
#: reported usage. Deliberately not anchored to the rest of the line: the
#: separator around it is " | " on an ASCII-only stdout and " · "
#: otherwise (`_stdout_is_ascii_only`), and this must match either.
_TOKENS_RE = re.compile(r"([\d,]+)\s+in\s*/\s*([\d,]+)\s+out tokens")

#: "(reported by X of Y calls)" -- present only when SOME but not all calls
#: on that line reported usage. Dropping this silently (as an earlier
#: version of this script did) hid a partial-usage run behind a complete-
#: looking token total.
_PARTIAL_RE = re.compile(r"reported by (\d+) of (\d+) calls")


class NoSpendLineFoundError(RuntimeError):
    """Raised when a captured log carries no `llm:` line at all.

    A scan/validate run that crashed before printing its spend summary, or
    whose stdout was never captured, must never silently report $0 -- that
    reads as "this run was free" when the truth is "this run's cost is
    unknown". The caller decides what a missing spend line means (a crash
    worth investigating, or legitimately no run at all); this script only
    refuses to guess.
    """


@dataclass(frozen=True)
class SpendInfo:
    calls: int
    prompt_tokens: int
    completion_tokens: int
    #: None when every `llm:` line's calls all reported usage; otherwise the
    #: summed (reported, of) pair across every partial line found.
    partial: tuple[int, int] | None


def parse_spend(log_text: str) -> SpendInfo:
    """Parse every `llm:` line in a captured log, raising when none exist."""
    call_matches = _CALLS_RE.findall(log_text)
    if not call_matches:
        raise NoSpendLineFoundError(
            "no 'llm: N calls' line found in the captured log -- this run's cost "
            "cannot be computed, and must not be reported as $0. Check whether the "
            "run crashed before printing its spend summary."
        )
    total_calls = sum(int(c) for c in call_matches)

    prompt_total = 0
    completion_total = 0
    for prompt_str, completion_str in _TOKENS_RE.findall(log_text):
        prompt_total += int(prompt_str.replace(",", ""))
        completion_total += int(completion_str.replace(",", ""))

    partial_matches = _PARTIAL_RE.findall(log_text)
    partial: tuple[int, int] | None = None
    if partial_matches:
        reported = sum(int(a) for a, _ in partial_matches)
        of_calls = sum(int(b) for _, b in partial_matches)
        partial = (reported, of_calls)

    return SpendInfo(
        calls=total_calls,
        prompt_tokens=prompt_total,
        completion_tokens=completion_total,
        partial=partial,
    )


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
    ref: str,
) -> dict[str, object]:
    spend = parse_spend(log_text)
    cost_usd = compute_cost_usd(
        spend.prompt_tokens,
        spend.completion_tokens,
        in_rate_per_million=in_rate_per_million,
        out_rate_per_million=out_rate_per_million,
    )
    result: dict[str, object] = {
        "model": model,
        "ref": ref,
        "calls": spend.calls,
        "prompt_tokens": spend.prompt_tokens,
        "completion_tokens": spend.completion_tokens,
        "in_rate_per_million_usd": in_rate_per_million,
        "out_rate_per_million_usd": out_rate_per_million,
        "cost_usd": round(cost_usd, 6),
    }
    if spend.partial is not None:
        reported, of_calls = spend.partial
        result["partial"] = {"reported_by": reported, "of_calls": of_calls}
    return result


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
    parser.add_argument(
        "--ref",
        required=True,
        help="The commit SHA actually checked out and measured (not a branch/tag name).",
    )
    parser.add_argument("--out", type=Path, required=True, help="Where to write cost.json.")
    args = parser.parse_args(argv)

    text = args.log_file.read_text(encoding="utf-8", errors="replace")
    try:
        result = build_result(
            text,
            model=args.model,
            in_rate_per_million=args.in_rate,
            out_rate_per_million=args.out_rate,
            ref=args.ref,
        )
    except NoSpendLineFoundError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
