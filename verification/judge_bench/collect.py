"""Capture every attempt the judge sees in real Mylonite scans.

Run from the repo root::

    python -m verification.judge_bench.collect --model provider/model \
        --scans 3 --max-llm-requests 2000 --out out/collect

Each scan is the real ``mylonite scan`` command, run in-process, so the target,
its authorization, the attack modules and the request ceiling behave exactly as
they do on the command line. The only difference is the judge: while a scan is
assembled, :class:`mylonite.scan.judge.SuccessJudge` is swapped for a recording
subclass. It calls the real ``judge()`` unchanged and appends what it was given
and what it returned to ``captures.jsonl``. Nothing under ``src/`` changes.

Outputs in ``--out``:

* ``captures.jsonl`` -- one record per judged attempt (see :class:`Capture`);
* ``spend.json`` -- LLM calls by role, token totals where the provider reported
  them, requests sent against the ceiling, and each scan's exit code;
* ``scans/<scan_id>/`` -- each scan's own artefacts and its CLI output.

``--max-llm-requests`` is required and is the CLI's own hard ceiling. It is
process-wide, so it caps the whole collection, not each scan; once it trips,
no further scan starts. Reference targets need no authorization and no
network beyond the model provider. A target file is refused unless
``--authorize`` is given, the same as ``mylonite scan``.

A scan that ran but left attempts NOT TESTED still counts as run (its
judged attempts are captured); one that wrote no report stops the collection.

Exit codes: 0 every scan ran; 1 usage error or a scan that could not run;
3 the request ceiling stopped the collection (what was captured is kept).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest import mock

from pydantic import BaseModel, ConfigDict

from mylonite.contracts._types import AdapterResponse, Payload

#: The targets scanned when no ``--target`` is given: both reference twins.
DEFAULT_TARGETS: tuple[str, ...] = ("reference:vulnerable", "reference:guarded")

#: Verdict evidence keys copied into a capture when present.
EVIDENCE_KEYS: tuple[str, ...] = (
    "proof_level",
    "trace_outcome",
    "link",
    "effect_confirmed",
    "negative_basis",
    "reason_code",
    "no_adjudicator",
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CEILING = 3

#: ``mylonite scan`` exit codes that always mean the scan ran to an answer.
#: A scan with untested attempts exits 2 too (NOT TESTED is never clean), so
#: any other code counts as a run only when the scan wrote its report.
_SCAN_RAN = frozenset({0, 1})


class Capture(BaseModel):
    """One judged attempt: exactly what the judge was handed, and its verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_id: str
    scan_id: str
    target: str
    target_type: str
    seed_id: str
    pattern_id: str
    payload: dict[str, Any]
    response: dict[str, Any]
    verdict: dict[str, Any]
    model: str
    mylonite_version: str


@dataclass
class ScanContext:
    """What every capture from one scan shares."""

    scan_id: str
    target: str
    target_type: str


@dataclass
class CaptureSink:
    """Collects captures; the recording judge writes here."""

    mylonite_version: str
    captures: list[Capture] = field(default_factory=list)
    context: ScanContext | None = None
    _seq: dict[str, int] = field(default_factory=dict)

    def record(self, model: str, payload: Payload, response: AdapterResponse, verdict: Any) -> None:
        ctx = self.context
        if ctx is None:
            raise RuntimeError("a judge ran outside a collection scan")
        n = self._seq.get(ctx.scan_id, 0) + 1
        self._seq[ctx.scan_id] = n
        raw_seed = payload.metadata.get("seed_id")
        self.captures.append(
            Capture(
                capture_id=f"{ctx.scan_id}-{n:04d}",
                scan_id=ctx.scan_id,
                target=ctx.target,
                target_type=ctx.target_type,
                # The engine's own rule: a present seed_id wins, even when empty.
                seed_id=raw_seed if raw_seed is not None else payload.pattern_id,
                pattern_id=payload.pattern_id,
                payload=payload.model_dump(mode="json"),
                response=response.model_dump(mode="json"),
                verdict=verdict_record(verdict),
                model=model,
                mylonite_version=self.mylonite_version,
            )
        )


def _jsonable(value: object) -> Any:
    """``value`` if it survives JSON, else its ``str()``."""
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def verdict_record(verdict: Any) -> dict[str, Any]:
    """The verdict fields a capture keeps (see the module docstring)."""
    evidence = dict(verdict.evidence)
    out: dict[str, Any] = {
        "success": bool(verdict.success),
        "mechanism": verdict.mechanism,
        "fallback_cause": verdict.fallback_cause,
        "applicable": bool(verdict.applicable),
        "reason": verdict.reason,
    }
    for key in EVIDENCE_KEYS:
        if key in evidence:
            out[key] = _jsonable(evidence[key])
    confidence = evidence.get("confidence")
    if isinstance(confidence, int | float) and not isinstance(confidence, bool):
        out["confidence"] = float(confidence)
    else:
        out["confidence"] = None
    return out


def recording_judge_class(sink: CaptureSink) -> type[Any]:
    """A ``SuccessJudge`` subclass that records every call into ``sink``."""
    from mylonite.scan.judge import SuccessJudge

    class RecordingJudge(SuccessJudge):
        async def judge(self, payload: Payload, response: AdapterResponse) -> Any:
            verdict = await super().judge(payload, response)
            sink.record(self._model, payload, response, verdict)
            return verdict

    return RecordingJudge


class _SeedFilter:
    """Wraps an attack module so only payloads for the chosen seeds are emitted."""

    def __init__(self, inner: Any, seeds: frozenset[str]) -> None:
        self._inner = inner
        self._seeds = seeds

    def attack_metadata(self) -> Any:
        return self._inner.attack_metadata()

    def generate_payloads(self, target: Any) -> Iterator[Any]:
        for payload in self._inner.generate_payloads(target):
            seed = (payload.metadata or {}).get("seed_id")
            if payload.pattern_id in self._seeds or seed in self._seeds:
                yield payload

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@contextmanager
def instrumented(sink: CaptureSink, seeds: frozenset[str] | None) -> Iterator[None]:
    """Swap in the recording judge (and the seed filter) for the block.

    ``build_scan_engine`` imports ``SuccessJudge`` from ``mylonite.scan.judge``
    when it runs, so patching that module attribute reaches every scan the CLI
    assembles. The filter wraps the CLI's own ``select_attack_modules``.
    """
    import mylonite.cli as cli_mod
    import mylonite.scan.judge as judge_mod

    with mock.patch.object(judge_mod, "SuccessJudge", recording_judge_class(sink)):
        if not seeds:
            yield
            return
        original = getattr(cli_mod, "select_attack_modules")  # noqa: B009 - not re-exported

        def select(*args: Any, **kwargs: Any) -> list[Any]:
            return [_SeedFilter(m, seeds) for m in original(*args, **kwargs)]

        with mock.patch.object(cli_mod, "select_attack_modules", select):
            yield


def target_type_for(target: str) -> str:
    """``reference`` for a reference twin, else ``rest`` or ``mcp`` from the file."""
    if target.startswith("reference:"):
        return "reference"
    import yaml

    try:
        data = yaml.safe_load(Path(target).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return "mcp"
    transport = data.get("transport") if isinstance(data, dict) else None
    return "rest" if transport == "rest" else "mcp"


def _slug(text: str) -> str:
    keep = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return keep.strip("_") or "target"


def scan_argv(
    target: str, *, model: str, ceiling: int, out_dir: Path, authorize: str | None
) -> list[str]:
    """The ``mylonite`` argv for one scan of ``target``."""
    argv = ["--max-llm-requests", str(ceiling), "scan"]
    if target.startswith("reference:"):
        argv.append(target)
    else:
        argv += ["--target-file", target]
        if authorize:
            argv += ["--authorize", authorize]
    argv += ["--model", model, "--output-dir", str(out_dir)]
    return argv


@dataclass
class ScanRun:
    scan_id: str
    target: str
    exit_code: int
    captures: int


def run_scan(argv: Sequence[str], log_path: Path) -> int:
    """Run ``mylonite <argv>`` in-process; write its output to ``log_path``."""
    from typer.testing import CliRunner

    from mylonite.cli import app

    result = CliRunner().invoke(app, list(argv))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    text = result.output
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        text += f"\n[collect] scan raised {type(result.exception).__name__}: {result.exception}\n"
    log_path.write_text(text, encoding="utf-8")
    return int(result.exit_code)


def scan_ran(code: int, scan_dir: Path) -> bool:
    """True when the scan reached a verdict: a clean or finding exit, or a report."""
    return code in _SCAN_RAN or any(scan_dir.rglob("scan_report.json"))


def write_captures(path: Path, captures: Iterable[Capture]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for cap in captures:
            fh.write(json.dumps(cap.model_dump(mode="json"), sort_keys=True) + "\n")
            n += 1
    return n


def load_captures(path: Path) -> list[Capture]:
    out: list[Capture] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(Capture.model_validate_json(line))
    return out


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Capture every judged attempt from real scans.")
    p.add_argument(
        "--target",
        action="append",
        default=None,
        help="reference:vulnerable, reference:guarded, or a target file (repeatable). "
        "Default: both reference twins.",
    )
    p.add_argument("--model", required=True, help="One model for planner, customiser and judge.")
    p.add_argument("--scans", type=int, default=1, help="Scans per target.")
    p.add_argument("--seeds", default="", help="Comma-separated seed or pattern ids to run.")
    p.add_argument(
        "--max-llm-requests",
        type=int,
        required=True,
        help="Hard request ceiling for the whole collection, retries included.",
    )
    p.add_argument("--authorize", default=None, help="Passed to scan for target files.")
    p.add_argument("--out", type=Path, required=True, help="Output directory.")
    return p


def _err(msg: str) -> None:
    print(f"collect: {msg}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    targets: list[str] = args.target or list(DEFAULT_TARGETS)
    if args.scans < 1:
        _err("--scans must be at least 1")
        return EXIT_ERROR
    if args.max_llm_requests < 1:
        _err("--max-llm-requests must be at least 1")
        return EXIT_ERROR
    unauthorized = [t for t in targets if not t.startswith("reference:") and not args.authorize]
    if unauthorized:
        _err(f"--authorize is required for target files (as for mylonite scan): {unauthorized}")
        return EXIT_ERROR
    seeds = frozenset(s.strip() for s in args.seeds.split(",") if s.strip()) or None

    from mylonite import __version__
    from mylonite.scan._llm import request_ceiling_hit, requests_sent, usage_tally

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    sink = CaptureSink(mylonite_version=__version__)
    runs: list[ScanRun] = []
    status = EXIT_OK
    sent_before = requests_sent()
    with usage_tally() as tally, instrumented(sink, seeds):
        for target in targets:
            for i in range(1, args.scans + 1):
                scan_id = f"{_slug(target)}-s{i:02d}"
                sink.context = ScanContext(scan_id, target, target_type_for(target))
                before = len(sink.captures)
                scan_dir = out / "scans" / scan_id
                code = run_scan(
                    scan_argv(
                        target,
                        model=args.model,
                        ceiling=args.max_llm_requests,
                        out_dir=scan_dir,
                        authorize=args.authorize,
                    ),
                    scan_dir / "cli.log",
                )
                sink.context = None
                runs.append(ScanRun(scan_id, target, code, len(sink.captures) - before))
                if request_ceiling_hit() is not None:
                    _err(f"request ceiling of {args.max_llm_requests} reached; stopping")
                    status = EXIT_CEILING
                    break
                if not scan_ran(code, scan_dir):
                    _err(f"scan {scan_id} exited {code}; see {scan_dir / 'cli.log'}")
                    status = EXIT_ERROR
                    break
            if status != EXIT_OK:
                break
        spend = tally.spend()

    n = write_captures(out / "captures.jsonl", sink.captures)
    summary = {
        "model": args.model,
        "mylonite_version": __version__,
        "targets": targets,
        "scans_per_target": args.scans,
        "seeds": sorted(seeds) if seeds else None,
        "captures": n,
        "calls": spend.calls,
        "calls_by_role": dict(sorted(spend.by_caller.items())),
        "prompt_tokens": spend.prompt_tokens,
        "completion_tokens": spend.completion_tokens,
        "calls_with_usage": spend.calls_with_usage,
        "requests_sent": requests_sent() - sent_before,
        "max_llm_requests": args.max_llm_requests,
        "ceiling_hit": request_ceiling_hit() is not None,
        "scans": [r.__dict__ for r in runs],
    }
    (out / "spend.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"captured {n} judged attempt(s) from {len(runs)} scan(s); wrote {out}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
