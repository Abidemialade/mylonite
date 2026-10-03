"""The kept finding ``mylonite demo`` shows: verdict, then its test red and green.

The scan table shows that a finding exists. This module shows what happens
next, offline, from one recorded run of the full pipeline (``demo/kept/``):

1. **Keep.** :class:`DifferentialValidator` re-derives the verdict from the
   recorded differential, the same way
   ``tests/plugins/test_reference_validation_example.py`` does: the attack fired
   on the vulnerable twin, the guarded twin resisted it, it held under a
   deterministic rewording, and the emitted test collects under pytest.
2. **Red.** The generated test's own check, run against the vulnerable twin's
   recorded single-seed run (``red_fixtures/``), must fail. That is the failure
   CI reports when the safeguard is missing.
3. **Green.** The generated test file itself, called as pytest would call it,
   must pass against the guarded twin's recorded run (``fixtures/``).

Every step replays recorded model replies. A lookup that misses, a verdict that
does not come back KEPT, a red run that passes or a green run that fails raises
:class:`~mylonite.demo.runner.DemoFixtureError`: the demo never shows a proof it
could not reproduce.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite.contracts import ExploitRecord, ValidationReport
from mylonite.demo import DEMO_RERECORD_HINT, LiteLLMRecorder, packaged_kept_dir


@dataclass(frozen=True)
class KeptProof:
    """Everything the renderer needs to show the kept finding and its test."""

    exploit: ExploitRecord
    report: ValidationReport
    test_filename: str
    model: str
    metamorphic_strategies: tuple[str, ...]
    red_message: str


def _fail(what: str) -> Exception:
    from mylonite.demo.runner import DemoFixtureError

    return DemoFixtureError(
        f"the demo's kept finding could not be replayed: {what}. {DEMO_RERECORD_HINT}"
    )


def _check(recorder: LiteLLMRecorder, step: str) -> None:
    if recorder.cache_misses or recorder.last_error is not None:
        detail = f" ({recorder.last_error})" if recorder.last_error is not None else ""
        raise _fail(f"{step} missed {recorder.cache_misses} recorded lookup(s){detail}")


def _read_meta(directory: Path) -> dict[str, Any]:
    meta = json.loads((directory / "_meta.json").read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or not meta.get("model"):
        raise _fail(f"{directory.name}/_meta.json names no recorded model")
    return meta


def _load_test_function(test_path: Path) -> Callable[[], None]:
    """The generated test function, imported from its own file."""
    spec = importlib.util.spec_from_file_location(f"_mylonite_demo_{test_path.stem}", test_path)
    if spec is None or spec.loader is None:
        raise _fail(f"cannot import {test_path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    func = getattr(module, test_path.stem, None)
    if not callable(func):
        raise _fail(f"{test_path.name} defines no {test_path.stem}()")
    return func  # type: ignore[no-any-return]


def _rederive(exploit: ExploitRecord, kept_dir: Path) -> tuple[ValidationReport, dict[str, Any]]:
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )

    differential = kept_dir / "differential_fixtures"
    meta = _read_meta(differential)
    recorder = LiteLLMRecorder(differential, mode="replay")
    validator = DifferentialValidator(
        iterations=int(meta.get("iterations", 1)),
        provider=str(meta.get("provider", "")) or "unknown",
        model=str(meta["model"]),
        completion_fn=recorder,
        record_fixtures_dir=None,
        metamorphic_strategies=list(meta.get("metamorphic_strategies", [])),
    )
    test = ReferencePytestGenerator().emit(exploit)
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )
    _check(recorder, "re-deriving the verdict")
    if not report.kept:
        raise _fail(f"the recorded run no longer re-derives KEPT ({report.notes})")
    return report, meta


def _red(exploit: ExploitRecord, kept_dir: Path) -> str:
    """Run the test's check against the vulnerable twin; return its failure message."""
    from mylonite import testkit
    from mylonite.scan.wiring import build_scan, note_id_counter

    red_dir = kept_dir / "red_fixtures"
    meta = _read_meta(red_dir)
    recorder = LiteLLMRecorder(red_dir, mode="replay")
    engine = build_scan(
        "vulnerable",
        completion_fn=recorder,
        note_id_factory=note_id_counter(),
        provider=str(meta.get("provider", "")) or "unknown",
        model=str(meta["model"]),
        pattern_id_filter=exploit.pattern_id,
    )
    result = asyncio.run(engine.run())
    _check(recorder, "the run on the vulnerable build")
    try:
        testkit._assert_from_result(
            result,
            exploit,
            subject="the vulnerable build",
            regression_detail="This is the failure CI reports when the safeguard is missing.",
        )
    except AssertionError as exc:
        return str(exc)
    except testkit.TestkitFixtureError as exc:
        raise _fail(f"the run on the vulnerable build reached no verdict ({exc})") from exc
    raise _fail("the generated test passed on the vulnerable build, so it proves nothing")


def _green(test_path: Path) -> None:
    """Call the generated test function itself; it replays the guarded twin."""
    from mylonite import testkit

    test_function = _load_test_function(test_path)
    try:
        test_function()
    except testkit.TestkitFixtureError as exc:
        raise _fail(f"the generated test could not replay the guarded build ({exc})") from exc
    except AssertionError as exc:
        raise _fail(f"the generated test failed on the guarded build ({exc})") from exc


def prove_kept(kept_dir: Path | None = None) -> KeptProof:
    """Replay the kept finding's verdict, then its test red and green. Offline."""
    from mylonite import testkit

    root = kept_dir if kept_dir is not None else packaged_kept_dir()
    exploits = sorted(root.glob("exploit_*.json"))
    tests = sorted(root.glob("test_security_*.py"))
    if len(exploits) != 1 or len(tests) != 1:
        raise _fail(f"expected one exploit and one test in {root}")
    exploit = testkit.load_exploit(exploits[0])
    report, meta = _rederive(exploit, root)
    red_message = _red(exploit, root)
    _green(tests[0])
    return KeptProof(
        exploit=exploit,
        report=report,
        test_filename=tests[0].name,
        model=str(meta["model"]),
        metamorphic_strategies=tuple(str(s) for s in meta.get("metamorphic_strategies", [])),
        red_message=red_message,
    )


__all__ = ["KeptProof", "prove_kept"]
