"""`mylonite gate` drives a real finding all the way to a passing test — offline.

The gap this closes
-------------------
Until now nothing in CI exercised the gate's *finding* path.

- ``tests/gate/test_gate_e2e_offline.py`` Part A covers only the **no-finding**
  path: it stubs the planner into a benign response so ``scan_fn`` yields zero
  exploits, and ``run_gate`` short-circuits at the empty-exploits check *before*
  generate/validate. Part B is the real flow and is ``skipif``-ed without
  ``MYLONITE_LIVE_E2E=1``.
- ``tests/gate/test_orchestrator.py`` does drive the finding path, but with
  ``generate_fn``/``validate_fn`` stubbed — it verifies the orchestration's
  branching, not that a real generator and a real differential oracle agree
  with it.
- ``.github/workflows/gate-dogfood.yml``'s ``live`` job runs the genuine flow,
  but only on ``workflow_dispatch`` and only with a provider key.

So the product's headline claim — a finding becomes a regression test the oracle
has proven — was asserted end-to-end nowhere a push could check.

What this test does
-------------------
Injects only the two collaborators that would otherwise need the outside world:
``scan_fn`` (hands over the committed exploit instead of calling a provider) and
``open_pr_fn`` (records its call instead of touching git). ``generate_fn`` and
``validate_fn`` are the **real** ones — the reference pytest generator and the
full ``DifferentialValidator``, replayed against the fixtures committed under
``examples/reference_validation/``.

The one piece not produced by the run is the single-seed guarded fixture set
the emitted test replays against: recording it is a live operation, so it is
copied from the committed artefact. The generator, the differential, the
written directory and the emitted test's execution are all real.

No ``skipif``, deliberately, for the same reason
``tests/plugins/test_reference_validation_example.py`` carries none: a skip is
how a claim quietly stops being checked.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite._replay import LiteLLMRecorder
from mylonite.gate.orchestrator import ScanOutcomeBundle, run_gate
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)
from mylonite.scan.coverage import Coverage, ScanOutcome
from mylonite.scan.pytest_runner import run_test_file
from mylonite.testkit import load_exploit

EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "reference_validation"
DIFFERENTIAL_FIXTURES = EXAMPLE_DIR / "differential_fixtures"


def _committed_exploit() -> Any:
    found = sorted(EXAMPLE_DIR.glob("exploit_*.json"))
    assert len(found) == 1, f"expected exactly one committed exploit, found {found}"
    return load_exploit(found[0])


def _differential_meta() -> dict[str, Any]:
    """Iterations/provider/model/strategies come from the sidecar, not constants
    here: a replay that used different ones would make different calls and miss."""
    return json.loads((DIFFERENTIAL_FIXTURES / "_meta.json").read_text(encoding="utf-8"))


def _found_outcome() -> ScanOutcome:
    """A scan that ran and found one thing. Not "clean", but a trusted result."""
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=1,
        not_tested=0,
        findings=1,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


class _RecordingPrFn:
    """Stands in for the git/gh step and records how it was invoked.

    ``run_gate`` always calls ``open_pr_fn`` and passes ``open_pr`` down for the
    closure to honour, so refusing the call outright would be asserting a
    contract the orchestrator does not have. Recording it instead lets the test
    assert the flag was forwarded truthfully and that nothing was opened.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return SimpleNamespace(opened=False, branch=None)


@pytest.fixture
def gate_run(tmp_path: Path) -> tuple[Any, Path, _RecordingPrFn]:
    """Run the real gate finding path once, offline, into ``tmp_path``."""
    out_dir = tmp_path / "gate"
    open_pr_fn = _RecordingPrFn()
    meta = _differential_meta()
    exploit = _committed_exploit()
    recorder = LiteLLMRecorder(DIFFERENTIAL_FIXTURES, mode="replay")

    validator = DifferentialValidator(
        iterations=int(meta["iterations"]),
        provider=str(meta["provider"]),
        model=str(meta["model"]),
        completion_fn=recorder,
        # NOT set. `record_fixtures_dir` makes the validator *record* the
        # single-seed guarded set, which is a live operation -- setting it here
        # sent every lookup through the recorder's record path and out to a real
        # provider, which is exactly what this test must never do. The guarded
        # set is instead taken from the committed artefact below.
        record_fixtures_dir=None,
        metamorphic_strategies=list(meta["metamorphic_strategies"]),
    )

    result = run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[exploit]),
        generate_fn=ReferencePytestGenerator().emit,
        validate_fn=lambda generated: validator.validate(
            generated,
            ReferenceVulnerableOracle().adapter(),
            ReferenceVulnerableOracle(),
        ),
        open_pr_fn=open_pr_fn,
        open_pr=False,
    )
    assert recorder.last_error is None, f"replay error: {recorder.last_error}"
    # The guard that would have caught this test's first draft: a miss means a
    # lookup escaped to a live provider, so the run is no longer offline and the
    # verdict is no longer the committed one.
    assert recorder.cache_misses == 0, (
        f"{recorder.cache_misses} lookup(s) missed the committed fixtures and "
        "went live -- this test must run with no provider"
    )

    # The single-seed guarded fixtures the emitted test replays against. The gate
    # cannot produce them offline (recording them is a live operation), so they
    # come from the committed artefact. Everything else here -- the generator,
    # the differential, the written directory -- is the real thing.
    shutil.copytree(EXAMPLE_DIR / "fixtures", out_dir / "fixtures", dirs_exist_ok=True)
    return result, out_dir, open_pr_fn


def test_the_gate_keeps_the_test_and_exits_zero(gate_run: tuple[Any, Path, _RecordingPrFn]) -> None:
    """THE test. A real finding, the real generator, the real differential — and
    the gate reports a kept test with a success exit code, no provider involved."""
    result, _, open_pr_fn = gate_run

    assert result.kept is True, "the differential did not keep the generated test"
    assert result.exit_code == 0, f"gate exited {result.exit_code}"
    assert result.opened_pr is False
    assert [c["open_pr"] for c in open_pr_fn.calls] == [False], (
        "the gate must forward open_pr=False to the git step, exactly once"
    )


def test_the_gate_wrote_a_runnable_directory(gate_run: tuple[Any, Path, _RecordingPrFn]) -> None:
    """Named individually so a partial write says which artefact is missing
    rather than failing somewhere downstream."""
    _, out_dir, _pr = gate_run

    emitted = sorted(out_dir.glob("test_security_*.py"))
    assert len(emitted) == 1, f"expected one emitted test, found {emitted}"
    assert sorted(out_dir.glob("exploit_*.json")), "the exploit JSON was not written"
    assert (out_dir / "validation_report.json").is_file(), (
        "the validation report was not written — it is the most expensive "
        "artefact of the run and used to be discarded on a later failure"
    )


def test_the_emitted_test_passes_offline(gate_run: tuple[Any, Path, _RecordingPrFn]) -> None:
    """What a user's CI actually runs: `pytest <gate-dir>`. This is the end of
    the claim — the gate's own output, executed, with no provider configured."""
    _, out_dir, _pr = gate_run
    emitted = sorted(out_dir.glob("test_security_*.py"))[0]

    result = run_test_file(emitted)

    assert result.passed, (
        f"the test the gate just wrote does not pass "
        f"(exit_code={result.exit_code}): {result.detail}"
    )


def test_the_committed_verdict_is_reproduced_not_asserted(
    gate_run: tuple[Any, Path, _RecordingPrFn],
) -> None:
    """The gate's written report must agree with the artefact committed under
    `examples/reference_validation/`, leg for leg. Otherwise the two could drift
    and each would still look self-consistent."""
    _, out_dir, _pr = gate_run
    written = json.loads((out_dir / "validation_report.json").read_text(encoding="utf-8"))
    committed = json.loads((EXAMPLE_DIR / "validation_report.json").read_text(encoding="utf-8"))

    assert written["kept"] == committed["kept"] is True
    assert written["gating_formula"] == committed["gating_formula"]
    assert written["gating_legs"] == committed["gating_legs"]
    assert {o["stage"]: o["passed"] for o in written["outcomes"]} == {
        o["stage"]: o["passed"] for o in committed["outcomes"]
    }
