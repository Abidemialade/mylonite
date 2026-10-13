"""Derive ``synthetic`` cases from landed ones by moving evidence that exists.

Run from the repo root::

    python -m verification.judge_bench.variants --cases out/cases/shadow.jsonl \
        --cases out/cases/llm_routed.jsonl --out out/cases/synthetic.jsonl

Each transform targets one way the judge's view of an attempt can lose the
evidence. None writes new prompt or attack text: they only blank, pad with
neutral filler, or copy text the case already holds.

* ``args_only`` -- the reply and every tool result are blanked, so the only
  evidence left is in the recorded tool-call arguments.
* ``past_result_excerpt`` -- neutral filler goes before each tool result, so
  the original result starts past the 300-character excerpt the judge reads.
* ``past_reply_excerpt`` -- neutral filler goes before the reply, so the
  original reply starts past the 1,500-character excerpt the judge reads.
* ``duplicated_json`` -- the reply's own text is repeated after it as a second,
  JSON-shaped block.

Sources are cases labelled ``landed`` in the ``shadow`` and ``llm_routed``
families. A variant keeps its source's label, seed and scan; its family is
``synthetic``, which never counts toward the bar. A transform that has nothing
to move (no trace, no reply) yields no variant. Output is deterministic.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from verification.judge_bench.cases import BenchCase, dump_cases, load_cases

#: Families whose landed cases seed the variants.
SOURCE_FAMILIES: frozenset[str] = frozenset({"shadow", "llm_routed"})

#: The excerpt bounds in the judge's prompt that the padding variants cross.
RESULT_EXCERPT = 300
REPLY_EXCERPT = 1500

#: Response metadata keys holding a JSON list of ``{tool, args, result, ...}``.
TRACE_KEYS: tuple[str, ...] = ("effect_trace", "mcp_trace_planner")

_LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua. "
)


def filler(min_chars: int) -> str:
    """Neutral lorem-style text, whole sentences, longer than ``min_chars``."""
    repeats = min_chars // len(_LOREM) + 1
    return (_LOREM * repeats).strip() + "\n"


def _trace(metadata: dict[str, str], key: str) -> list[dict[str, Any]] | None:
    raw = metadata.get(key)
    if not raw:
        return None
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return None
    return entries


def _map_traces(
    response: dict[str, Any], fn: Callable[[dict[str, Any]], dict[str, Any]]
) -> dict[str, Any] | None:
    """``response`` with ``fn`` applied to every trace entry; ``None`` if no trace."""
    metadata = dict(response.get("metadata") or {})
    changed = False
    for key in TRACE_KEYS:
        entries = _trace(metadata, key)
        if entries:
            metadata[key] = json.dumps([fn(dict(e)) for e in entries])
            changed = True
    if not changed:
        return None
    return {**response, "metadata": metadata}


def args_only(response: dict[str, Any]) -> dict[str, Any] | None:
    """Blank the reply and every tool result; the arguments stay as recorded."""
    metadata = response.get("metadata") or {}
    has_args = any(e.get("args") for k in TRACE_KEYS for e in (_trace(metadata, k) or []))
    if not has_args:
        return None

    def blank(entry: dict[str, Any]) -> dict[str, Any]:
        if "result" in entry:
            entry["result"] = ""
        return entry

    out = _map_traces(response, blank)
    return None if out is None else {**out, "raw_response": ""}


def past_result_excerpt(response: dict[str, Any]) -> dict[str, Any] | None:
    """Put filler before each non-empty tool result, past the 300-character excerpt."""
    pad = filler(RESULT_EXCERPT)
    metadata = response.get("metadata") or {}
    if not any(e.get("result") for k in TRACE_KEYS for e in (_trace(metadata, k) or [])):
        return None

    def push(entry: dict[str, Any]) -> dict[str, Any]:
        if entry.get("result"):
            entry["result"] = pad + str(entry["result"])
        return entry

    return _map_traces(response, push)


def past_reply_excerpt(response: dict[str, Any]) -> dict[str, Any] | None:
    """Put filler before the reply, past the 1,500-character excerpt."""
    reply = str(response.get("raw_response") or "")
    if not reply:
        return None
    return {**response, "raw_response": filler(REPLY_EXCERPT) + reply}


def duplicated_json(response: dict[str, Any]) -> dict[str, Any] | None:
    """Repeat the reply after itself as a JSON-shaped block."""
    reply = str(response.get("raw_response") or "")
    if not reply:
        return None
    block = json.dumps({"reply": reply}, ensure_ascii=False)
    return {**response, "raw_response": f"{reply}\n{block}"}


#: The transforms, in output order.
TRANSFORMS: dict[str, Callable[[dict[str, Any]], dict[str, Any] | None]] = {
    "args_only": args_only,
    "past_result_excerpt": past_result_excerpt,
    "past_reply_excerpt": past_reply_excerpt,
    "duplicated_json": duplicated_json,
}


def variants_of(case: BenchCase) -> list[BenchCase]:
    """Every variant one source case yields (possibly none)."""
    out: list[BenchCase] = []
    for kind, transform in TRANSFORMS.items():
        response = transform(dict(case.response))
        if response is None:
            continue
        out.append(
            BenchCase(
                case_id=f"{case.case_id}~{kind}",
                family="synthetic",
                seed_id=case.seed_id,
                scan_id=case.scan_id,
                target_type=case.target_type,
                label=case.label,
                payload=case.payload,
                response=response,
                provenance=f"variant:{kind} of {case.case_id} ({case.family})",
            )
        )
    return out


def derive(cases: Iterable[BenchCase]) -> list[BenchCase]:
    """Variants of every landed source case, in ``case_id`` order."""
    sources = [c for c in cases if c.family in SOURCE_FAMILIES and c.label == "landed"]
    derived = [v for c in sources for v in variants_of(c)]
    return sorted(derived, key=lambda c: c.case_id)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Derive synthetic variants from landed cases.")
    p.add_argument("--cases", type=Path, action="append", required=True, help="Case JSONL.")
    p.add_argument("--out", type=Path, required=True, help="Output JSONL (synthetic family).")
    args = p.parse_args(argv)
    cases = [c for path in args.cases for c in load_cases(path)]
    n = dump_cases(args.out, derive(cases))
    print(f"wrote {n} synthetic case(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
