"""Verification harness CLI.

Layer 2 (record -> score), with explicit, separable steps:

    # 1. download + verify pinned third-party data (no vendoring)
    python -m verification.runner fetch --dataset injecagent

    # 2. run a model once over the benchmark -> transcripts + ASR (needs an API key)
    python -m verification.runner record --dataset injecagent --split dh \\
        --model anthropic/claude-sonnet-4-6 --limit 50 --out verification/reports/dh.jsonl

    # 3. score Mylonite's judge vs the benchmark's rule (hermetic; no model)
    python -m verification.runner score --dataset injecagent \\
        --transcripts verification/reports/dh.jsonl

``score`` is the reproducible, CI-safe step; ``record`` is the opt-in step that
needs an LLM key. See ``verification/README.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from mylonite._concurrency import gather_bounded
from mylonite.scan.judge import SuccessJudge
from verification import fetch
from verification.crosswalk import load_crosswalk
from verification.layer1_runnable import run as layer1_run
from verification.layer2_datasets import agentdojo, injecagent
from verification.layer3_production import run as layer3_run
from verification.report import build_report, write_report
from verification.score import score_transcripts
from verification.transcript import read_transcripts, write_transcripts

_REPORTS = Path(__file__).with_name("reports")
_SETTING_FILES = {
    ("injecagent", "dh", "base"): "test_cases_dh_base.json",
    ("injecagent", "dh", "enhanced"): "test_cases_dh_enhanced.json",
    ("injecagent", "ds", "base"): "test_cases_ds_base.json",
    ("injecagent", "ds", "enhanced"): "test_cases_ds_enhanced.json",
}


def _cmd_fetch(args: argparse.Namespace) -> int:
    if args.dataset == "injecagent":
        paths = fetch.fetch_injecagent()
        print(f"fetched + verified {len(paths)} files into {fetch.injecagent_cache_dir()}")
        for name in paths:
            print(f"  - {name}")
        return 0
    if args.dataset == "agentdojo":
        # AgentDojo ships recorded runs (no model run needed): download the pinned
        # subset and convert straight to a Transcript JSONL the `score` step reads.
        run_paths = fetch.fetch_agentdojo_runs()
        transcripts = agentdojo.load_run_transcripts(fetch.agentdojo_cache_dir())
        out = Path(args.out) if args.out else _REPORTS / "transcripts_agentdojo.jsonl"
        n = write_transcripts(out, transcripts)
        positives = sum(1 for t in transcripts if t.benchmark_success)
        print(f"fetched {len(run_paths)} AgentDojo runs -> {n} transcripts -> {out}")
        print(f"  {positives} real positives (security=False); {n - positives} negatives")
        print("next: `score --transcripts <out> --with-llm` to verify the judge on real positives")
        return 0
    print(f"fetch: dataset {args.dataset!r} not wired yet", file=sys.stderr)
    return 2


def _cmd_record(args: argparse.Namespace) -> int:
    if args.dataset != "injecagent":
        print(f"record: dataset {args.dataset!r} not wired yet", file=sys.stderr)
        return 2
    key = ("injecagent", args.split, args.setting)
    if key not in _SETTING_FILES:
        print(f"record: no file for split={args.split} setting={args.setting}", file=sys.stderr)
        return 2
    data_path = fetch.injecagent_cache_dir() / _SETTING_FILES[key]
    if not data_path.exists():
        print(f"record: {data_path} missing - run `fetch` first", file=sys.stderr)
        return 2
    fetch._enable_truststore()
    cases = injecagent.load_cases(data_path, args.split, limit=args.limit)
    # Each case is an independent, blocking litellm.completion call
    # (injecagent.record_case is sync). Farm them out to threads and await
    # them concurrently (bounded) instead of recording one case at a time.
    transcripts = asyncio.run(
        gather_bounded(
            [
                asyncio.to_thread(
                    injecagent.record_case,
                    c,
                    model=args.model,
                    elicit_positives=args.elicit_positives,
                )
                for c in cases
            ]
        )
    )
    suffix = "_elicit" if args.elicit_positives else ""
    out = (
        Path(args.out)
        if args.out
        else _REPORTS / f"transcripts_injecagent_{args.split}{suffix}.jsonl"
    )
    n = write_transcripts(out, transcripts)
    asr = sum(1 for t in transcripts if t.benchmark_success) / n if n else 0.0
    print(f"recorded {n} transcripts -> {out}")
    if args.elicit_positives:
        print(
            f"ELICIT-POSITIVES mode (compliant agent): {asr:.1%} attacks succeeded — "
            "NOT a fair ASR; used to verify the judge's positive class."
        )
    else:
        print(f"benchmark ASR (asr-all, model={args.model}, split={args.split}): {asr:.1%}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    transcripts = list(read_transcripts(Path(args.transcripts)))
    if not transcripts:
        print(f"score: no transcripts in {args.transcripts}", file=sys.stderr)
        return 2
    crosswalk = load_crosswalk()
    if args.with_llm:
        judge = SuccessJudge(model=args.model, llm_fallback=True)
        fetch._enable_truststore()
        judge_mode = "with-llm"
    else:
        judge = SuccessJudge(model="deterministic-unused", llm_fallback=False)
        judge_mode = "deterministic"
    rows, matrix = asyncio.run(score_transcripts(transcripts, crosswalk=crosswalk, judge=judge))
    dataset = transcripts[0].dataset
    synthetic = any(t.synthetic for t in transcripts)
    report = build_report(
        dataset=dataset,
        model=(args.model if args.with_llm else ""),
        rows=rows,
        matrix=matrix,
        judge_mode=judge_mode,
        synthetic=synthetic,
    )
    out = Path(args.out) if args.out else _REPORTS / f"layer2_{dataset}_{judge_mode}.json"
    write_report(out, report)
    agree = report["judge_agreement"]
    print(f"scored {len(rows)} transcripts ({judge_mode}) -> {out}")
    print(
        f"  benchmark ASR : {report['benchmark_asr']:.1%}  ({report['positive_cases']} positives)"
    )
    if report["judge_agreement_exercised"]:
        print(
            f"  judge agreement: precision={agree['precision']:.3f} "
            f"recall={agree['recall']:.3f} f1={agree['f1']:.3f}"
        )
    else:
        print("  judge agreement: NOT EXERCISED - 0 successful attacks (vacuous; see report note)")
    if synthetic:
        print("  NOTE: synthetic fixture - plumbing check only, not a third-party number")
    return 0


def _cmd_layer1_fetch(args: argparse.Namespace) -> int:
    try:
        dest = fetch.fetch_dvmcp(include_unlicensed=args.include_unlicensed)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"DVMCP cloned at pinned commit {fetch.DVMCP_COMMIT[:10]} -> {dest}")
    return 0


def _cmd_layer1_emit(args: argparse.Namespace) -> int:
    repo = fetch.dvmcp_cache_dir()
    if not (repo / ".git").exists():
        print(
            "emit-targets: DVMCP not fetched - run `layer1 fetch --include-unlicensed`",
            file=sys.stderr,
        )
        return 2
    out = Path(args.out) if args.out else _REPORTS / "dvmcp" / "targets"
    written = layer1_run.emit_targets(repo, out)
    print(f"wrote {len(written)} target files -> {out}")
    for p in written:
        print(f"  - {p.name}")
    print("next: start the DVMCP servers, then `mylonite scan --target-file <t> --json <report>`")
    return 0


def _cmd_layer1_score(args: argparse.Namespace) -> int:
    rows, _matrix, report = layer1_run.score_reports(Path(args.reports))
    out = Path(args.out) if args.out else _REPORTS / "layer1_dvmcp.json"
    write_report(out, report)
    print(f"scored {len(rows)} in-scope challenges -> {out}")
    print(
        f"  recall: {report['recall']:.1%}  ({report['found']} found / {report['missed']} missed)"
    )
    for r in rows:
        mark = "OK " if r.detected_exploited else "MISS"
        print(f"  [{mark}] {r.variant}: {r.detail}")
    return 0


def _cmd_layer3_score(args: argparse.Namespace) -> int:
    report = layer3_run.precision_report(Path(args.scan), target_label=args.target)
    out = Path(args.out) if args.out else _REPORTS / "layer3_precision.json"
    write_report(out, report)
    print(f"scored {report['completed_probes']} probes on a known-good target -> {out}")
    print(
        f"  false positives: {report['false_positives']} "
        f"(FPR {report['false_positive_rate']:.1%}); true negatives: {report['true_negatives']}"
    )
    for fp in report["false_positive_detail"]:
        print(f"  [FALSE POSITIVE] {fp['pattern_id']}: {fp['reason']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="verification.runner", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch", help="download + verify pinned third-party data")
    f.add_argument("--dataset", default="injecagent", choices=["injecagent", "agentdojo"])
    f.add_argument("--out", default=None, help="(agentdojo) transcripts JSONL output path")
    f.set_defaults(func=_cmd_fetch)

    r = sub.add_parser("record", help="run a model over the benchmark -> transcripts (needs a key)")
    r.add_argument("--dataset", default="injecagent")
    r.add_argument("--split", default="dh", choices=["dh", "ds"])
    r.add_argument("--setting", default="base", choices=["base", "enhanced"])
    r.add_argument("--model", required=True)
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--out", default=None)
    r.add_argument(
        "--elicit-positives",
        action="store_true",
        help="use a compliant agent to manufacture successful attacks (verify the judge's "
        "positive class); the resulting ASR is NOT fair",
    )
    r.set_defaults(func=_cmd_record)

    s = sub.add_parser("score", help="score Mylonite's judge vs the benchmark rule (hermetic)")
    s.add_argument("--dataset", default="injecagent")
    s.add_argument("--transcripts", required=True)
    s.add_argument("--with-llm", action="store_true", help="also exercise the LLM-judge leg")
    s.add_argument("--model", default="anthropic/claude-sonnet-4-6")
    s.add_argument("--out", default=None)
    s.set_defaults(func=_cmd_score)

    l1 = sub.add_parser("layer1", help="Layer 1: runnable vulnerable MCP target (DVMCP)")
    l1sub = l1.add_subparsers(dest="layer1_command", required=True)
    l1f = l1sub.add_parser("fetch", help="clone DVMCP at the pinned commit (no LICENSE -> opt-in)")
    l1f.add_argument("--include-unlicensed", action="store_true")
    l1f.set_defaults(func=_cmd_layer1_fetch)
    l1e = l1sub.add_parser("emit-targets", help="write a target.yaml per in-scope challenge")
    l1e.add_argument("--out", default=None)
    l1e.set_defaults(func=_cmd_layer1_emit)
    l1s = l1sub.add_parser("score", help="score recall from per-challenge JSON report bundles")
    l1s.add_argument("--reports", required=True)
    l1s.add_argument("--out", default=None)
    l1s.set_defaults(func=_cmd_layer1_score)

    l3 = sub.add_parser("layer3", help="Layer 3: false-positive control on a known-good target")
    l3sub = l3.add_subparsers(dest="layer3_command", required=True)
    l3s = l3sub.add_parser("score", help="count false positives in a scan of a known-good target")
    l3s.add_argument("--scan", required=True, help="scan output dir (contains scan_report.json)")
    l3s.add_argument("--target", default="", help="label for the report")
    l3s.add_argument("--out", default=None)
    l3s.set_defaults(func=_cmd_layer3_score)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
