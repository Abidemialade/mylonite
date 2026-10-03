#!/usr/bin/env python3
"""Count the LLM calls the reference ``scan`` and ``gate`` paths make, offline.

Every call goes through one scripted fake model that counts it by role:

* **planner** calls (the agent under test) replay the recorded demo fixtures
  (``mylonite demo``'s own), or, for the gate's validation leg, the committed
  differential fixtures under ``src/mylonite/demo/kept/``. A call with
  no recording gets a plain "Done." reply and is counted as a miss.
* **customiser** calls get the seed body back unchanged, as strict JSON.
* **judge** calls get a low-confidence "not landed" reply.

The planner keeps its recorded behaviour, so the attack really lands on the
vulnerable twin and the judge and customiser stages really run. Nothing here
needs a network or a provider key.

The counts are compared against ``tests/fixtures/llm_call_baseline.json`` by
``tests/test_llm_call_count.py`` (scan) and ``tests/e2e/test_offline_deep_path.py``
(gate): a change that makes either path more than
15% chattier fails the build.

Usage::

    python scripts/count_llm_calls.py            # scan counts only (fast)
    python scripts/count_llm_calls.py --gate     # also the gate path (slower)
    python scripts/count_llm_calls.py --root DIR # read examples/ from DIR

The script uses only APIs that existed at the baseline commit, so the same file
can measure an older tree: point ``PYTHONPATH`` at that tree's ``src`` and
``--root`` at the tree itself.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
import shutil
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent

#: Model names that route a call to the scripted customiser and judge. They
#: never reach a provider: the fake answers every call itself.
CUSTOMISER_MODEL = "scripted/customiser"
JUDGE_MODEL = "scripted/judge"

#: The committed counts, measured at the baseline commit.
BASELINE_FILE = ROOT / "tests" / "fixtures" / "llm_call_baseline.json"

#: How far above the baseline a count may go before the build fails, in percent.
ALLOWED_GROWTH_PERCENT = 15

#: The committed reference finding the gate path validates: the kept finding
#: `mylonite demo` ships, recorded on the same run as the demo scan fixtures,
#: so the scan above finds the seed it validates.
EXAMPLE_DIRNAME = Path("src") / "mylonite" / "demo" / "kept"

_SEED_RE = re.compile(
    r"SEED PATTERN \([^)]*\):\n(?P<body>.*)\n\nProduce the refined payload body\.",
    re.DOTALL,
)


def _text(content: str) -> SimpleNamespace:
    message = SimpleNamespace(content=content, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")])


def _seed_body(messages: Sequence[Any]) -> str | None:
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            match = _SEED_RE.search(content)
            if match:
                return match.group("body")
    return None


@dataclass
class ScriptedLLM:
    """A counting fake model: replays the planner, scripts the customiser and judge."""

    planner_fixtures: Any
    calls: Counter[str] = field(default_factory=Counter)
    planner_misses: int = 0

    def __post_init__(self) -> None:
        import litellm

        from mylonite._replay import LiteLLMRecorder

        # The scripted model names are unknown to LiteLLM's capability lookup,
        # which prints a provider-list banner each time it is asked about one.
        litellm.suppress_debug_info = True
        self._recorder = LiteLLMRecorder(self.planner_fixtures, mode="replay")

    @property
    def total(self) -> int:
        return sum(self.calls.values())

    async def __call__(self, *, model: str, messages: Sequence[Any], **kwargs: Any) -> Any:
        if model == CUSTOMISER_MODEL:
            self.calls["customiser"] += 1
            body = _seed_body(messages)
            return _text(json.dumps({"body": body}) if body is not None else "{}")
        if model == JUDGE_MODEL:
            self.calls["judge"] += 1
            verdict = {
                "success": False,
                "harmful_intent_present": False,
                "confidence": 0.0,
                "reason": "scripted judge: not landed",
            }
            return _text(json.dumps(verdict))
        self.calls["planner"] += 1
        from mylonite._replay import FixtureError

        try:
            return await self._recorder(model=model, messages=messages, **kwargs)
        except FixtureError:
            self.planner_misses += 1
            return _text("Done.")


def _demo_model() -> tuple[str, str]:
    from mylonite.demo.runner import DEMO_MODEL, DEMO_PROVIDER

    return DEMO_PROVIDER, DEMO_MODEL


def run_reference_scan(variant: Literal["vulnerable", "guarded"]) -> tuple[Any, ScriptedLLM]:
    """One reference ``scan`` with the customiser and judge stages on."""
    from mylonite.demo import packaged_fixture_dir
    from mylonite.scan.wiring import build_scan, note_id_counter

    provider, model = _demo_model()
    fake = ScriptedLLM(packaged_fixture_dir() / variant)
    engine = build_scan(
        variant,
        completion_fn=fake,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
        planner_model=model,
        customiser_model=CUSTOMISER_MODEL,
        judge_model=JUDGE_MODEL,
        llm_assist=True,
    )
    result = asyncio.run(engine.run())
    return result, fake


@dataclass
class GateRun:
    """What one offline gate run produced, plus its call counts."""

    result: Any
    out_dir: Path
    scan: ScriptedLLM
    validate: ScriptedLLM
    exploits_found: list[str]


def run_reference_gate(out_dir: Path, *, root: Path = ROOT) -> GateRun:
    """The gate's finding path, offline: scan, generate, validate, write.

    The scan is the reference vulnerable scan above. Its finding for the
    committed example's seed goes through the real pytest generator and the
    real differential validator, which replays the committed differential
    fixtures. Only that one finding is validated, because it is the only one
    with recorded validation traffic.
    """
    from types import SimpleNamespace as _NS

    from mylonite.gate.orchestrator import ScanOutcomeBundle, run_gate
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
    )
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )
    from mylonite.scan.coverage import ScanOutcome

    example = root / EXAMPLE_DIRNAME
    differential = example / "differential_fixtures"
    meta = json.loads((differential / "_meta.json").read_text(encoding="utf-8"))

    scan_result, scan_fake = run_reference_scan("vulnerable")
    found = [e.pattern_id for e in scan_result.exploits]
    # Validate the committed exploit, not the scan's copy of it: the recorded
    # differential is keyed on the payload the recording run validated, and the
    # scripted customiser here hands back the raw seed body instead. The scan
    # still has to find the seed for the gate to reach validation at all.
    from mylonite.testkit import load_exploit

    committed = load_exploit(next(example.glob("exploit_*.json")))
    picked = [committed] if meta["pattern_id"] in found else []

    validate_fake = ScriptedLLM(differential)
    validator = DifferentialValidator(
        iterations=int(meta["iterations"]),
        provider=str(meta["provider"]),
        model=str(meta["model"]),
        completion_fn=validate_fake,
        record_fixtures_dir=None,
        metamorphic_strategies=list(meta["metamorphic_strategies"]),
    )
    outcome = ScanOutcome.from_report(scan_result.report)
    result = run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome, exploits=picked),
        generate_fn=ReferencePytestGenerator().emit,
        validate_fn=lambda generated, _finding_dir: validator.validate(
            generated,
            ReferenceVulnerableOracle().adapter(),
            ReferenceVulnerableOracle(),
        ),
        open_pr_fn=lambda **_: _NS(opened=False, branch=None),
        open_pr=False,
    )
    # The emitted test replays the single-seed guarded set. Recording it is a
    # live operation, so it comes from the committed example. Each recording
    # takes the short name a fresh recording gets today, so the gate dir has
    # the layout a new gate writes (and fits a deep Windows checkout).
    from mylonite._replay import FIXTURE_NAME_LENGTH

    fixtures = out_dir / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    for src in (example / "fixtures").iterdir():
        name = src.name
        if len(src.stem) == 64:
            name = src.stem[:FIXTURE_NAME_LENGTH] + src.suffix
        shutil.copyfile(src, fixtures / name)
    return GateRun(
        result=result,
        out_dir=out_dir,
        scan=scan_fake,
        validate=validate_fake,
        exploits_found=found,
    )


def _summary(fake: ScriptedLLM) -> dict[str, Any]:
    return {
        "total": fake.total,
        "by_role": dict(sorted(fake.calls.items())),
        "planner_misses": fake.planner_misses,
    }


def load_baseline(path: Path = BASELINE_FILE) -> dict[str, int]:
    """The committed per-path call counts (``{"scan_vulnerable": 34, ...}``)."""
    document = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): int(v) for k, v in document["counts"].items()}


def budget(baseline: int, growth_percent: int = ALLOWED_GROWTH_PERCENT) -> int:
    """The most calls a path may make: the baseline plus 15%, rounded down.

    Integer arithmetic on purpose: ``100 * 1.15`` is ``114.99...`` in floating point.
    """
    return baseline * (100 + growth_percent) // 100


def over_budget(counts: dict[str, int], baseline: dict[str, int]) -> list[str]:
    """One line per path whose count is above its budget; empty when all fit."""
    return [
        f"{path}: {counts[path]} calls, budget {budget(baseline[path])} "
        f"(baseline {baseline[path]} + 15%)"
        for path in sorted(counts)
        if counts[path] > budget(baseline[path])
    ]


def measure(*, gate: bool, root: Path = ROOT) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for variant in ("vulnerable", "guarded"):
        _, fake = run_reference_scan(variant)  # type: ignore[arg-type]
        counts[f"scan_{variant}"] = _summary(fake)
    if gate:
        with tempfile.TemporaryDirectory() as tmp:
            run = run_reference_gate(Path(tmp) / "gate", root=root)
            counts["gate"] = {
                "total": run.scan.total + run.validate.total,
                "scan": _summary(run.scan),
                "validate": _summary(run.validate),
                "kept": bool(run.result.kept),
            }
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gate", action="store_true", help="also count the gate path")
    parser.add_argument("--root", type=Path, default=ROOT, help="tree to read examples/ from")
    args = parser.parse_args(argv)
    # The gate prints its own progress to stdout; keep stdout for the JSON.
    with contextlib.redirect_stdout(sys.stderr):
        counts = measure(gate=args.gate, root=args.root)
    print(json.dumps(counts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
