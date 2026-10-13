#!/usr/bin/env python3
"""Measure Mylonite's LLM judge against the preregistered bar.

Runs benchmark cases (``verification/judge_bench`` JSONL) through the real
``SuccessJudge`` and scores the single-call result. Run from the repo root::

    # freeze the dev/test split once, before any baseline is seen
    python scripts/measure_judge.py --cases cases.jsonl --manifest manifest.json --make-manifest

    # keyless: replay recorded judge replies (a miss is an error, exit 2)
    python scripts/measure_judge.py --cases cases.jsonl --manifest manifest.json \
        --split test --models provider/model --mode replay --fixtures fixtures/ --out out/

Record mode makes live provider calls and needs the provider's key in the
environment; it is meant for CI only. Fixtures live under
``<fixtures>/<model>/r<repeat>/`` so each repeat keeps its own reply.

Outputs ``outcomes.jsonl``, ``summary.json`` and ``summary.md`` in ``--out``.
Exit codes: 0 success; 1 usage or provider error; 2 manifest mismatch or replay miss.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Literal

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from verification.judge_bench.cases import apply_seed_cap, load_cases  # noqa: E402
from verification.judge_bench.report import summarize, to_markdown  # noqa: E402
from verification.judge_bench.runner import dump_outcomes, run  # noqa: E402
from verification.judge_bench.split import (  # noqa: E402
    Manifest,
    ManifestMismatch,
    make_split,
    select,
    verify_manifest,
)

from mylonite._replay import (  # noqa: E402
    CACHE_KEY_VERSION_FIELD,
    FixtureError,
    LiteLLMRecorder,
)
from mylonite.scan.llm_types import AsyncCompletionFn  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISMATCH = 2


def _slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_") or "model"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Measure the LLM judge against the preregistered bar.")
    p.add_argument("--cases", type=Path, required=True, help="Benchmark cases (JSONL).")
    p.add_argument("--manifest", type=Path, help="Split manifest; verified unless --make-manifest.")
    p.add_argument(
        "--make-manifest",
        action="store_true",
        help="Freeze a new split manifest at --manifest (refuses to overwrite).",
    )
    p.add_argument("--split", choices=("dev", "test", "all"), default="test")
    p.add_argument("--models", default="", help="Comma-separated judge models.")
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--mode", choices=("record", "replay"), default="replay")
    p.add_argument("--fixtures", type=Path, help="Recorded judge replies directory.")
    p.add_argument("--out", type=Path, help="Output directory.")
    p.add_argument("--max-cases", type=int, help="Score at most N cases (lowest case ids).")
    return p


def _write(path: Path, text: str) -> None:
    """Write UTF-8 with LF line endings on every platform (byte-stable outputs)."""
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _err(msg: str) -> None:
    print(f"measure_judge: {msg}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    cases = load_cases(args.cases)
    _, over_cap = apply_seed_cap(cases)
    if over_cap:
        _err(f"warning: {over_cap} case(s) exceed the per-seed cap of 8 (family, seed)")

    manifest: Manifest | None = None
    if args.make_manifest:
        if args.manifest is None:
            _err("--make-manifest needs --manifest PATH")
            return EXIT_ERROR
        if args.manifest.exists():
            _err(f"refusing to overwrite the frozen manifest {args.manifest}")
            return EXIT_ERROR
        manifest = make_split(cases)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        _write(args.manifest, manifest.model_dump_json(indent=2) + "\n")
        print(
            f"manifest written: {len(manifest.dev_ids)} dev, {len(manifest.test_ids)} held-out, "
            f"sha256 {manifest.test_sha256}"
        )
    elif args.manifest is not None:
        manifest = Manifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
        try:
            verify_manifest(cases, manifest)
        except ManifestMismatch as exc:
            _err(f"manifest mismatch: {exc}")
            return EXIT_MISMATCH

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    if not models:
        if args.make_manifest:
            return EXIT_OK
        _err("--models is required to run the judge")
        return EXIT_ERROR
    if args.split != "all" and manifest is None:
        _err(f"--split {args.split} needs --manifest")
        return EXIT_ERROR
    if args.fixtures is None or args.out is None:
        _err("--fixtures and --out are required to run the judge")
        return EXIT_ERROR
    if args.repeats < 1:
        _err("--repeats must be at least 1")
        return EXIT_ERROR

    selected = cases if manifest is None else select(cases, manifest, args.split)
    selected = sorted(selected, key=lambda c: c.case_id)
    if args.max_cases is not None:
        selected = selected[: args.max_cases]

    mode: Literal["record", "replay"] = args.mode
    recorders: dict[tuple[str, int], LiteLLMRecorder] = {}

    def completion_fn_for(model: str, repeat: int) -> AsyncCompletionFn:
        fixtures_dir = args.fixtures / _slug(model) / f"r{repeat}"
        rec = LiteLLMRecorder(fixtures_dir=fixtures_dir, mode=mode)
        recorders[(model, repeat)] = rec
        return rec

    try:
        outcomes = asyncio.run(run(selected, models, args.repeats, completion_fn_for))
    except FixtureError as exc:
        _err(f"fixture error: {exc}")
        return EXIT_MISMATCH if mode == "replay" else EXIT_ERROR
    except Exception as exc:  # a non-recoverable provider error (auth, TLS, ...)
        _err(f"judge run failed: {type(exc).__name__}: {exc}")
        return EXIT_ERROR

    # The judge's chokepoint swallows a recoverable completion error into an
    # inconclusive verdict, so a replay miss would otherwise read as an
    # abstention. Check every recorder instead: a miss is an error.
    misses = sum(r.cache_misses for r in recorders.values())
    errors = [r.last_error for r in recorders.values() if r.last_error is not None]
    if misses or errors:
        if mode == "replay":
            _err(f"replay miss: {misses} missing fixture(s); first error: {errors[:1]}")
            return EXIT_MISMATCH
        _err(f"record errors: {errors[:1]}")
        return EXIT_ERROR

    if mode == "record":
        for (model, repeat), rec in recorders.items():
            meta = args.fixtures / _slug(model) / f"r{repeat}" / "_meta.json"
            _write(meta, json.dumps({CACHE_KEY_VERSION_FIELD: rec.key_version}, indent=2) + "\n")

    args.out.mkdir(parents=True, exist_ok=True)
    _write(args.out / "outcomes.jsonl", dump_outcomes(outcomes))
    summary = summarize(outcomes, selected, manifest, args.split)
    _write(args.out / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
    _write(args.out / "summary.md", to_markdown(summary))
    print(f"scored {len(selected)} case(s) x {len(models)} model(s) x {args.repeats} repeat(s)")
    print(f"wrote {args.out / 'summary.md'}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
