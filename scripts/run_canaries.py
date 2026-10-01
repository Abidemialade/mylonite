#!/usr/bin/env python3
"""Run the live canaries against a real LLM and check their bars.

A canary drives the real CLI (``python -m mylonite ...``, never a mocked
path) against a live model, 3 times by default, and must meet its bar on at
least 2 of those 3 runs. The four canaries:

- **W4**: ``validate`` of the reference ``excessive-agency-send-email-
  direct-unconfirmed`` finding on ``reference:vulnerable`` -- bar: KEPT.
- **guarded-w2-reject**: ``validate`` of the guarded W2 "note body
  roleplay" seed on ``reference:guarded`` -- bar: REJECTED (or no finding
  at all, which also means the bar holds -- see
  ``run_guarded_w2_reject`` below).
- **reference-scan**: a full scan of ``reference:vulnerable`` -- bar: at
  least 4 findings.
- **custom-redrive**: a live re-drive of a custom kitchen-sink target's
  generated tests. This repository does not carry the target file an
  earlier measurement used -- without ``--custom-target-file`` (or
  ``MYLONITE_CANARY_CUSTOM_TARGET``) pointing at one, this canary is
  reported SKIPPED, not failed.

Cost control: ``scan`` and ``gate`` both take ``--max-llm-calls``, so the
two discovery scans (W4, guarded-w2-reject) and the reference scan get a
real, enforced budget computed from a recorded baseline call count plus
15% headroom, the same margin this project uses elsewhere for a
no-regression call-count bar. ``validate`` has no budget flag at all
(checked against ``mylonite validate --help``) -- its cost is bounded by
pinning ``--iterations`` at the baseline value (5) rather than letting it
grow, and by flagging (never aborting mid-run) a printed call count above
baseline x 1.15.

Never prints a provider key: the key is read from the environment by the
``mylonite`` subprocess itself (whatever credential env var the chosen
provider needs), never passed on a command line or logged here.

Usage::

    python scripts/run_canaries.py --model <provider>/<model>
    python scripts/run_canaries.py --runs 3 --out-dir .mylonite/canaries
    MYLONITE_CANARY_MODEL=<provider>/<model> python scripts/run_canaries.py
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Call counts recorded from an earlier live measurement of each canary,
# frozen at v0.10.4. Used only to size each run's cost cap -- not asserted
# as an exact match, since a live model's call count is not deterministic
# run to run. Re-measure and update these if a canary's shape changes.
BASELINE_CALLS = {
    "w4": 362,
    "guarded-w2-reject": 367,
    "reference-scan": 32,
}
CALL_HEADROOM = 1.15  # a 15% margin, as used elsewhere for a call-count bar

#: A deliberately conservative dollars-per-call estimate. The baseline W4
#: and guarded-w2-reject runs (~360 calls) were estimated at $0.60-0.70 on
#: a small hosted model, i.e. roughly $0.0017-0.0019/call; this rounds up
#: for safety margin so the dollar cap is a sanity ceiling, not the normal
#: binding constraint.
DEFAULT_DOLLARS_PER_CALL = 0.0025
DEFAULT_MAX_COST_PER_RUN = 5.0

DEFAULT_RUNS = 3
DEFAULT_VALIDATE_ITERATIONS = 5

# mylonite.exit_codes, inlined so this script has no import-time dependency
# on the package layout (it must keep working even if exit_codes.py moves).
EXIT_SUCCESS = 0
EXIT_NOT_KEPT = 5

_LLM_LINE_RE = re.compile(r"llm:\s*(\d+)\s*calls")
_TOKENS_RE = re.compile(r"([\d,]+)\s*in\s*/\s*([\d,]+)\s*out\s*tokens")
_SECONDS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*s\s*$")


def required_passes(n: int) -> int:
    """At least 2 of 3; generalised as ceil(2n/3) for any run count."""
    if n <= 0:
        return 0
    return math.ceil(n * 2 / 3)


@dataclass
class LLMSummary:
    calls: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    seconds: float | None = None


def parse_llm_summary(stdout: str) -> LLMSummary:
    """Parse the ``llm: N calls (...) | P in / Q out tokens | R.Rs`` line
    every command prints (``mylonite.scan.artefacts.format_spend``). The
    separator is either `` | `` or `` · `` depending on console
    encoding, so this matches each field independently rather than the
    whole line shape.
    """
    for line in stdout.splitlines():
        calls_m = _LLM_LINE_RE.search(line)
        if not calls_m:
            continue
        tokens_m = _TOKENS_RE.search(line)
        seconds_m = _SECONDS_RE.search(line.strip())
        return LLMSummary(
            calls=int(calls_m.group(1)),
            prompt_tokens=int(tokens_m.group(1).replace(",", "")) if tokens_m else None,
            completion_tokens=int(tokens_m.group(2).replace(",", "")) if tokens_m else None,
            seconds=float(seconds_m.group(1)) if seconds_m else None,
        )
    return LLMSummary()


def max_calls_for_budget(max_cost_per_run: float, dollars_per_call: float) -> int:
    if dollars_per_call <= 0:
        raise ValueError("dollars_per_call must be positive")
    return max(1, math.floor(max_cost_per_run / dollars_per_call))


def scan_call_cap(baseline_calls: int, *, max_cost_per_run: float, dollars_per_call: float) -> int:
    """The ``--max-llm-calls`` value to pass: baseline + 15% headroom,
    clamped to whatever the dollar cap allows.
    """
    headroom_cap = math.ceil(baseline_calls * CALL_HEADROOM)
    budget_cap = max_calls_for_budget(max_cost_per_run, dollars_per_call)
    return min(headroom_cap, budget_cap)


@dataclass
class CanaryRun:
    """One run of one canary."""

    canary_id: str
    run_index: int
    verdict: str
    bar_met: bool
    calls: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    seconds: float | None = None
    cost_estimate: float | None = None
    detail: str = ""


@dataclass
class CanaryAggregate:
    canary_id: str
    runs: list[CanaryRun] = field(default_factory=list)
    required: int = 0
    passes: int = 0
    meets_bar: bool = False
    skipped: bool = False
    skip_reason: str = ""


def aggregate(canary_id: str, runs: list[CanaryRun]) -> CanaryAggregate:
    """Pure aggregation: at least 2 of 3 (``required_passes``) runs must
    meet the bar. A canary whose every run is a SKIPPED verdict is reported
    as skipped rather than failed -- it was never exercised, so it has
    nothing to say about regression.
    """
    if not runs:
        return CanaryAggregate(canary_id=canary_id, skipped=True, skip_reason="no runs recorded")
    if all(r.verdict == "SKIPPED" for r in runs):
        return CanaryAggregate(
            canary_id=canary_id,
            runs=runs,
            skipped=True,
            skip_reason=runs[0].detail or "skipped",
        )
    req = required_passes(len(runs))
    passes = sum(1 for r in runs if r.bar_met)
    return CanaryAggregate(
        canary_id=canary_id,
        runs=runs,
        required=req,
        passes=passes,
        meets_bar=passes >= req,
    )


# --- subprocess plumbing -----------------------------------------------------


@dataclass
class RunContext:
    model: str
    out_dir: Path
    dollars_per_call: float
    max_cost_per_run: float
    validate_iterations: int
    timeout_s: float
    custom_target_file: Path | None


def run_cli(args: list[str], *, cwd: Path, timeout_s: float) -> subprocess.CompletedProcess[str]:
    """Invoke the real CLI as a subprocess. Never passes a key on the
    command line; whatever provider credential the environment already
    carries is inherited as-is (and never logged by this script).
    """
    cmd = [sys.executable, "-m", "mylonite", *args]
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=os.environ.copy(),
    )


def _cost_estimate(calls: int | None, dollars_per_call: float) -> float | None:
    return None if calls is None else round(calls * dollars_per_call, 4)


def _find_exploit(scan_dir: Path, pattern_id: str) -> Path | None:
    candidate = scan_dir / f"exploit_{pattern_id}.json"
    if candidate.is_file():
        return candidate
    matches = list(scan_dir.glob(f"**/exploit_{pattern_id}.json"))
    return matches[0] if matches else None


def _read_findings_count(scan_dir: Path) -> int | None:
    report_path = scan_dir / "scan_report.json"
    if not report_path.is_file():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    count = data.get("findings_count")
    return int(count) if isinstance(count, int) else None


def _discover(
    ctx: RunContext,
    *,
    target: str,
    weakness_class: str,
    out_dir: Path,
    baseline_calls: int,
) -> tuple[subprocess.CompletedProcess[str] | None, LLMSummary, Path, str | None]:
    """Run the discovery scan for the W4 or guarded-w2-reject canary. Returns the completed
    process (or ``None`` on a timeout), its LLM summary, the scan dir it
    wrote to, and an error string when the scan itself could not be run.
    """
    cap = scan_call_cap(
        baseline_calls,
        max_cost_per_run=ctx.max_cost_per_run,
        dollars_per_call=ctx.dollars_per_call,
    )
    try:
        proc = run_cli(
            [
                "scan",
                target,
                "--weakness-class",
                weakness_class,
                "--output-dir",
                str(out_dir),
                "--model",
                ctx.model,
                "--max-llm-calls",
                str(cap),
            ],
            cwd=ROOT,
            timeout_s=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return None, LLMSummary(), out_dir, "scan timed out"
    summary = parse_llm_summary(proc.stdout)
    return proc, summary, out_dir, None


def run_w4(ctx: RunContext, run_index: int) -> CanaryRun:
    pattern_id = "excessive-agency-send-email-direct-unconfirmed"
    scan_dir = ctx.out_dir / f"w4-{run_index}" / "scan"
    _proc, scan_summary, scan_dir, err = _discover(
        ctx,
        target="reference:vulnerable",
        weakness_class="W4",
        out_dir=scan_dir,
        baseline_calls=BASELINE_CALLS["w4"],
    )
    if err is not None:
        return CanaryRun("w4", run_index, "ERROR", False, detail=err)

    exploit = _find_exploit(scan_dir, pattern_id)
    if exploit is None:
        return CanaryRun(
            "w4",
            run_index,
            "NOT_FOUND",
            False,
            calls=scan_summary.calls,
            seconds=scan_summary.seconds,
            detail="scan did not reproduce the W4 finding",
        )

    gen_dir = ctx.out_dir / f"w4-{run_index}" / "generated"
    gen_proc = run_cli(
        ["generate", str(exploit), "--out", str(gen_dir)],
        cwd=ROOT,
        timeout_s=ctx.timeout_s,
    )
    if gen_proc.returncode != 0:
        return CanaryRun("w4", run_index, "ERROR", False, detail="generate failed")

    try:
        val_proc = run_cli(
            [
                "validate",
                str(gen_dir),
                "--model",
                ctx.model,
                "--iterations",
                str(ctx.validate_iterations),
            ],
            cwd=ROOT,
            timeout_s=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return CanaryRun("w4", run_index, "ERROR", False, detail="validate timed out")

    val_summary = parse_llm_summary(val_proc.stdout)
    kept = val_proc.returncode == EXIT_SUCCESS
    detail = f"validate exit {val_proc.returncode}"
    if val_summary.calls and val_summary.calls > math.ceil(BASELINE_CALLS["w4"] * CALL_HEADROOM):
        detail += f"; cost-cap note: {val_summary.calls} calls exceeds the baseline ceiling"
    return CanaryRun(
        "w4",
        run_index,
        "KEPT" if kept else f"NOT_KEPT({val_proc.returncode})",
        kept,
        calls=val_summary.calls,
        prompt_tokens=val_summary.prompt_tokens,
        completion_tokens=val_summary.completion_tokens,
        seconds=val_summary.seconds,
        cost_estimate=_cost_estimate(val_summary.calls, ctx.dollars_per_call),
        detail=detail,
    )


def run_guarded_w2_reject(ctx: RunContext, run_index: int) -> CanaryRun:
    """The judge-hallucination bug this seed used to expose is already
    fixed on main (the judge success cross-check), so the honest live
    re-proof has two outcomes that both meet the bar: the scan finds
    nothing (the cheap fix still holds), or -- if that regresses -- the
    live differential still rejects it. Only a KEPT verdict is a miss.
    """
    pattern_id = "indirect-injection-note-body-roleplay"
    scan_dir = ctx.out_dir / f"guarded-w2-reject-{run_index}" / "scan"
    _proc, scan_summary, scan_dir, err = _discover(
        ctx,
        target="reference:guarded",
        weakness_class="W2",
        out_dir=scan_dir,
        baseline_calls=BASELINE_CALLS["guarded-w2-reject"],
    )
    if err is not None:
        return CanaryRun("guarded-w2-reject", run_index, "ERROR", False, detail=err)

    exploit = _find_exploit(scan_dir, pattern_id)
    if exploit is None:
        return CanaryRun(
            "guarded-w2-reject",
            run_index,
            "REJECTED(no finding)",
            True,
            calls=scan_summary.calls,
            seconds=scan_summary.seconds,
            detail="the guarded scan found nothing to validate -- the fix holds",
        )

    gen_dir = ctx.out_dir / f"guarded-w2-reject-{run_index}" / "generated"
    gen_proc = run_cli(
        ["generate", str(exploit), "--out", str(gen_dir)],
        cwd=ROOT,
        timeout_s=ctx.timeout_s,
    )
    if gen_proc.returncode != 0:
        return CanaryRun("guarded-w2-reject", run_index, "ERROR", False, detail="generate failed")

    try:
        val_proc = run_cli(
            [
                "validate",
                str(gen_dir),
                "--model",
                ctx.model,
                "--iterations",
                str(ctx.validate_iterations),
            ],
            cwd=ROOT,
            timeout_s=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return CanaryRun(
            "guarded-w2-reject", run_index, "ERROR", False, detail="validate timed out"
        )

    val_summary = parse_llm_summary(val_proc.stdout)
    rejected = val_proc.returncode == EXIT_NOT_KEPT
    detail = f"validate exit {val_proc.returncode} (a finding resurfaced -- cross-check regression)"
    if val_summary.calls and val_summary.calls > math.ceil(
        BASELINE_CALLS["guarded-w2-reject"] * CALL_HEADROOM
    ):
        detail += f"; cost-cap note: {val_summary.calls} calls exceeds the baseline ceiling"
    return CanaryRun(
        "guarded-w2-reject",
        run_index,
        "REJECTED" if rejected else f"KEPT({val_proc.returncode})",
        rejected,
        calls=val_summary.calls,
        prompt_tokens=val_summary.prompt_tokens,
        completion_tokens=val_summary.completion_tokens,
        seconds=val_summary.seconds,
        cost_estimate=_cost_estimate(val_summary.calls, ctx.dollars_per_call),
        detail=detail,
    )


def run_reference_scan(ctx: RunContext, run_index: int) -> CanaryRun:
    scan_dir = ctx.out_dir / f"reference-scan-{run_index}" / "scan"
    cap = scan_call_cap(
        BASELINE_CALLS["reference-scan"],
        max_cost_per_run=ctx.max_cost_per_run,
        dollars_per_call=ctx.dollars_per_call,
    )
    try:
        proc = run_cli(
            [
                "scan",
                "reference:vulnerable",
                "--output-dir",
                str(scan_dir),
                "--model",
                ctx.model,
                "--max-llm-calls",
                str(cap),
            ],
            cwd=ROOT,
            timeout_s=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return CanaryRun("reference-scan", run_index, "ERROR", False, detail="scan timed out")

    summary = parse_llm_summary(proc.stdout)
    findings = _read_findings_count(scan_dir)
    bar_met = findings is not None and findings >= 4
    return CanaryRun(
        "reference-scan",
        run_index,
        f"{findings} FOUND" if findings is not None else "UNKNOWN",
        bar_met,
        calls=summary.calls,
        prompt_tokens=summary.prompt_tokens,
        completion_tokens=summary.completion_tokens,
        seconds=summary.seconds,
        cost_estimate=_cost_estimate(summary.calls, ctx.dollars_per_call),
        detail=f"scan exit {proc.returncode}",
    )


_PYTEST_SUMMARY_RE = re.compile(r"(\d+)\s+(failed|passed|error)")


def _parse_pytest_summary(stdout: str) -> dict[str, int]:
    """``N failed, M passed in Rs`` -> {"failed": N, "passed": M}. Missing
    categories default to 0 (pytest omits a category with zero in it).
    """
    counts = {"failed": 0, "passed": 0, "error": 0}
    for line in stdout.splitlines()[::-1]:
        matches = _PYTEST_SUMMARY_RE.findall(line)
        if matches:
            for n, kind in matches:
                counts[kind] = int(n)
            break
    return counts


def run_custom_redrive(ctx: RunContext, run_index: int) -> CanaryRun:
    """Re-drive a custom target's generated tests live: baseline is 4
    generated tests, each re-driven 5 times, 20/20 expected to fail
    correctly (the attack lands on the target under test with no
    safeguard). Needs a target file this repository does not carry (see
    the module docstring) -- SKIPPED, not failed, until one is supplied via
    ``--custom-target-file``/``MYLONITE_CANARY_CUSTOM_TARGET``.
    """
    if ctx.custom_target_file is None or not ctx.custom_target_file.is_file():
        return CanaryRun(
            "custom-redrive",
            run_index,
            "SKIPPED",
            False,
            detail=(
                "no custom kitchen-sink target file configured (pass "
                "--custom-target-file or set MYLONITE_CANARY_CUSTOM_TARGET); "
                "the baseline run used a local, uncommitted file"
            ),
        )

    gen_dir = ctx.out_dir / f"custom-redrive-{run_index}" / "generated"
    scan_dir = ctx.out_dir / f"custom-redrive-{run_index}" / "scan"
    try:
        scan_proc = run_cli(
            [
                "scan",
                "--target-file",
                str(ctx.custom_target_file),
                "--authorize",
                "mylonite-canary",
                "--output-dir",
                str(scan_dir),
                "--model",
                ctx.model,
            ],
            cwd=ROOT,
            timeout_s=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return CanaryRun("custom-redrive", run_index, "ERROR", False, detail="scan timed out")
    if scan_proc.returncode not in (0, 1):
        return CanaryRun(
            "custom-redrive", run_index, "ERROR", False, detail=f"scan exit {scan_proc.returncode}"
        )

    gen_proc = run_cli(
        [
            "generate",
            str(scan_dir),
            "--out",
            str(gen_dir),
            "--target-file",
            str(ctx.custom_target_file),
        ],
        cwd=ROOT,
        timeout_s=ctx.timeout_s,
    )
    if gen_proc.returncode != 0:
        return CanaryRun("custom-redrive", run_index, "ERROR", False, detail="generate failed")

    try:
        collect_proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(gen_dir), "--collect-only", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=ctx.timeout_s,
        )
    except subprocess.TimeoutExpired:
        return CanaryRun("custom-redrive", run_index, "ERROR", False, detail="collection timed out")
    collect_m = re.search(r"(\d+)\s+tests?\s+collected", collect_proc.stdout)
    if not collect_m:
        return CanaryRun(
            "custom-redrive", run_index, "ERROR", False, detail="could not parse test collection"
        )
    tests_collected = int(collect_m.group(1))

    total_failed = 0
    total_expected = 0
    redrive_runs = 5
    for _ in range(redrive_runs):
        try:
            test_proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(gen_dir), "-q"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=ctx.timeout_s,
                env={**os.environ, "MYLONITE_LIVE_TARGET": "1"},
            )
        except subprocess.TimeoutExpired:
            return CanaryRun(
                "custom-redrive", run_index, "ERROR", False, detail="pytest re-drive timed out"
            )
        counts = _parse_pytest_summary(test_proc.stdout)
        total_failed += counts["failed"]
        total_expected += tests_collected

    # Baseline expects every re-driven test to FAIL correctly (the attack
    # landed on the build under test with no safeguard) -- a pass or an
    # error here is a miss, not just a non-zero exit code.
    bar_met = total_expected > 0 and total_failed == total_expected
    return CanaryRun(
        "custom-redrive",
        run_index,
        f"{total_failed}/{total_expected} failed correctly",
        bar_met,
        detail=(
            "re-drive failed correctly"
            if bar_met
            else f"expected {total_expected} failures across {redrive_runs} runs of "
            f"{tests_collected} tests, got {total_failed}"
        ),
    )


CANARIES: dict[str, object] = {
    "w4": run_w4,
    "guarded-w2-reject": run_guarded_w2_reject,
    "reference-scan": run_reference_scan,
    "custom-redrive": run_custom_redrive,
}


# --- reporting ----------------------------------------------------------


def render_table(aggregates: list[CanaryAggregate]) -> str:
    lines = [
        f"{'canary':<16} {'run':>3} {'verdict':<24} {'calls':>6} {'tokens':>18} {'seconds':>8}"
    ]
    for agg in aggregates:
        for run in agg.runs:
            tokens = (
                f"{run.prompt_tokens or 0:,}/{run.completion_tokens or 0:,}"
                if run.prompt_tokens is not None
                else "n/a"
            )
            lines.append(
                f"{agg.canary_id:<16} {run.run_index:>3} {run.verdict:<24} "
                f"{run.calls if run.calls is not None else 'n/a':>6} {tokens:>18} "
                f"{run.seconds if run.seconds is not None else 'n/a':>8}"
            )
        if agg.skipped:
            lines.append(f"{agg.canary_id:<16} SKIPPED -- {agg.skip_reason}")
        else:
            verdict = "PASS" if agg.meets_bar else "FAIL"
            lines.append(
                f"{agg.canary_id:<16} {verdict} ({agg.passes}/{len(agg.runs)}, needs {agg.required})"
            )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("MYLONITE_CANARY_MODEL"),
        help=(
            "LiteLLM provider/model, e.g. <provider>/<model> (never a hardcoded default). "
            "Required (no default provider); may also come from "
            "MYLONITE_CANARY_MODEL."
        ),
    )
    parser.add_argument(
        "--runs", type=int, default=DEFAULT_RUNS, help="Runs per canary (default 3)."
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Where to write scan/generate/validate artefacts and the JSON report (default: a timestamped dir under .mylonite/canaries/).",
    )
    parser.add_argument(
        "--max-cost-per-run",
        type=float,
        default=DEFAULT_MAX_COST_PER_RUN,
        help="Dollar sanity cap per run (default $5).",
    )
    parser.add_argument(
        "--dollars-per-call",
        type=float,
        default=DEFAULT_DOLLARS_PER_CALL,
        help="Conservative $/call estimate used to size --max-llm-calls (default $0.0025).",
    )
    parser.add_argument(
        "--validate-iterations",
        type=int,
        default=DEFAULT_VALIDATE_ITERATIONS,
        help="--iterations passed to `validate` for the W4 and guarded-w2-reject canaries (default 5, the baseline value).",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=900.0,
        help="Per-subprocess wall-clock timeout in seconds (default 900).",
    )
    parser.add_argument(
        "--custom-target-file",
        type=Path,
        default=(
            Path(os.environ["MYLONITE_CANARY_CUSTOM_TARGET"])
            if os.environ.get("MYLONITE_CANARY_CUSTOM_TARGET")
            else None
        ),
        help="A custom kitchen-sink target.yaml for the re-drive canary; skipped if unset.",
    )
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(CANARIES),
        help="Run only this canary (repeatable). Default: all four.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.model:
        print(
            "error: --model is required (or set MYLONITE_CANARY_MODEL). "
            "Mylonite has no default provider.",
            file=sys.stderr,
        )
        return 2

    out_dir = args.out_dir or (
        ROOT / ".mylonite" / "canaries" / time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    ctx = RunContext(
        model=args.model,
        out_dir=out_dir,
        dollars_per_call=args.dollars_per_call,
        max_cost_per_run=args.max_cost_per_run,
        validate_iterations=args.validate_iterations,
        timeout_s=args.timeout_s,
        custom_target_file=args.custom_target_file,
    )

    selected = args.only or sorted(CANARIES)
    aggregates: list[CanaryAggregate] = []
    for canary_id in selected:
        run_fn = CANARIES[canary_id]
        runs = [run_fn(ctx, i) for i in range(args.runs)]  # type: ignore[operator]
        aggregates.append(aggregate(canary_id, runs))

    print(render_table(aggregates))

    report = {
        "model": args.model,
        "runs": args.runs,
        "max_cost_per_run": args.max_cost_per_run,
        "dollars_per_call": args.dollars_per_call,
        "canaries": [
            {
                "canary_id": agg.canary_id,
                "skipped": agg.skipped,
                "skip_reason": agg.skip_reason,
                "meets_bar": agg.meets_bar,
                "required": agg.required,
                "passes": agg.passes,
                "runs": [asdict(r) for r in agg.runs],
            }
            for agg in aggregates
        ],
    }
    report_path = out_dir / "canaries_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nJSON report: {report_path}")

    skipped = [a for a in aggregates if a.skipped]
    for agg in skipped:
        print(f"NOTICE: {agg.canary_id} SKIPPED -- {agg.skip_reason}", file=sys.stderr)

    failing = [a for a in aggregates if not a.skipped and not a.meets_bar]
    if failing:
        for agg in failing:
            print(
                f"FAIL: {agg.canary_id} met its bar on {agg.passes}/{len(agg.runs)} runs, needs {agg.required}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
