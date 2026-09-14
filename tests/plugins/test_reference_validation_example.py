"""The committed proof of the core claim, re-derived offline with no provider.

Mylonite's central claim is one sentence: *the differential oracle keeps a test,
and you can replay the proof offline with no API key.* Until 0.10.0 the repo had
no committed artefact behind it — the live proof was a skipped test, and
`examples/reference_validation/` was a directory the record script created and
never filled.

This module is the gate on that artefact. It re-runs the whole differential
against the recorded fixtures and asserts the KEPT verdict comes back, then
asserts the committed verdict on disk matches the one just re-derived, leg for
leg. A reader can therefore check the claim by running `pytest` — not by
trusting a number in a README.

**No `skipif` anywhere in this file, deliberately.** A skip is exactly how a
committed artefact silently vanishes: delete the directory and a guarded test
goes green while the proof it existed to make is gone. These must fail loudly
instead.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mylonite._replay import LiteLLMRecorder
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)
from mylonite.scan.pytest_runner import run_test_file
from mylonite.testkit import FIXTURE_FORMAT_VERSION, load_exploit

EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "reference_validation"
GUARDED_FIXTURES = EXAMPLE_DIR / "fixtures"
DIFFERENTIAL_FIXTURES = EXAMPLE_DIR / "differential_fixtures"
REPORT_PATH = EXAMPLE_DIR / "validation_report.json"

#: Strategies whose perturbation is a pure function of the payload. A recorded
#: differential can only be replayed if every probe it made is reproducible, so
#: the artefact must not have been recorded with a sampling strategy.
DETERMINISTIC_STRATEGIES = {"paraphrase", "encode", "reorder", "pad"}


def _meta(fixtures_dir: Path) -> dict[str, Any]:
    return json.loads((fixtures_dir / "_meta.json").read_text(encoding="utf-8"))


def _committed_report() -> dict[str, Any]:
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def _exploit_path() -> Path:
    found = sorted(EXAMPLE_DIR.glob("exploit_*.json"))
    assert len(found) == 1, f"expected exactly one committed exploit, found {found}"
    return found[0]


def _committed_test_path() -> Path:
    found = sorted(EXAMPLE_DIR.glob("test_security_*.py"))
    assert len(found) == 1, f"expected exactly one committed test, found {found}"
    return found[0]


def _rederive() -> Any:
    """Re-run the differential offline against the recorded fixtures.

    `record_fixtures_dir=None` so nothing is written: this is a pure replay of
    the pass the artefact came from. The iteration count and strategies come
    from the sidecar rather than from constants here, because a replay that used
    different ones would make different calls and miss.
    """
    meta = _meta(DIFFERENTIAL_FIXTURES)
    exploit = load_exploit(_exploit_path())
    test = ReferencePytestGenerator().emit(exploit)
    recorder = LiteLLMRecorder(DIFFERENTIAL_FIXTURES, mode="replay")
    validator = DifferentialValidator(
        iterations=int(meta["iterations"]),
        provider=str(meta["provider"]),
        model=str(meta["model"]),
        completion_fn=recorder,
        record_fixtures_dir=None,
        metamorphic_strategies=list(meta["metamorphic_strategies"]),
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )
    return report, recorder


# --- 1. the artefact is there -------------------------------------------------


def test_the_committed_artefact_exists() -> None:
    """Every file the claim rests on. Named individually so a partial artefact
    says which piece is missing rather than failing somewhere downstream."""
    assert EXAMPLE_DIR.is_dir(), f"{EXAMPLE_DIR} is missing entirely"
    assert _exploit_path().is_file()
    assert _committed_test_path().is_file()
    assert REPORT_PATH.is_file()
    assert (GUARDED_FIXTURES / "_meta.json").is_file()
    assert (DIFFERENTIAL_FIXTURES / "_meta.json").is_file()
    assert list(GUARDED_FIXTURES.glob("*.json")) != [GUARDED_FIXTURES / "_meta.json"], (
        "the guarded fixture directory holds only its sidecar — the emitted test "
        "would cache-miss on every call"
    )
    assert len(list(DIFFERENTIAL_FIXTURES.glob("*.json"))) > 1


# --- 2. the verdict re-derives, offline --------------------------------------


def test_the_kept_verdict_reproduces_offline() -> None:
    """THE test. No provider, no key: the differential replays from committed
    fixtures and still keeps the test, with every gating leg passing."""
    report, recorder = _rederive()

    assert report.kept is True, f"re-derived verdict is not KEPT: {report.notes}"
    failed = [o.stage for o in report.outcomes if not o.passed and not o.report_only]
    assert not failed, f"gating legs that did not pass on replay: {failed}"
    assert recorder.cache_misses == 0, (
        f"{recorder.cache_misses} lookup(s) missed the committed fixtures, so the "
        "replay diverged from the pass that produced them"
    )
    assert recorder.last_error is None


def test_the_guard_positively_resisted_on_every_recorded_iteration() -> None:
    """The oracle fix, asserted on the committed artefact. A guarded twin that
    merely failed to leak is not proof it resisted, and `guard_resisted` is the
    number that says which happened."""
    report, _ = _rederive()
    evidence = report.reproducibility

    assert evidence is not None
    assert evidence.guard_resisted == evidence.iterations, (
        f"guard positively resisted {evidence.guard_resisted} of "
        f"{evidence.iterations} iterations; the rest reached no verdict"
    )
    assert evidence.guard_fired == 0
    assert evidence.vuln_fired == evidence.iterations


# --- 3. the emitted test is a working offline gate ---------------------------


def test_the_committed_test_passes_offline() -> None:
    """What a user actually runs after `mylonite gate`: the emitted file, against
    the fixtures shipped beside it, with no provider configured."""
    result = run_test_file(_committed_test_path())

    assert result.passed, (
        f"the committed regression test did not pass offline "
        f"(exit_code={result.exit_code}): {result.detail}"
    )


# --- 4. the two fixture sets cannot drift apart ------------------------------


def test_the_fixture_sets_describe_the_same_run() -> None:
    """Two directories recorded by one pass. If they disagree, one of them was
    re-recorded separately and the artefact no longer describes a single run."""
    guarded, differential = _meta(GUARDED_FIXTURES), _meta(DIFFERENTIAL_FIXTURES)

    assert guarded["model"] == differential["model"]
    assert guarded["provider"] == differential["provider"]
    assert guarded["pattern_id"] == differential["pattern_id"]
    assert guarded["cache_key_version"] == differential["cache_key_version"]


def test_only_the_guarded_sidecar_claims_single_seed_scope() -> None:
    """`format_version` means *single-seed fixture isolation*. The guarded set
    has that property and the emitted test relies on it; the differential set is
    a whole-bank recording and must not claim it."""
    assert _meta(GUARDED_FIXTURES)["format_version"] == FIXTURE_FORMAT_VERSION
    assert "format_version" not in _meta(DIFFERENTIAL_FIXTURES)


def test_the_recorded_strategies_are_reproducible() -> None:
    """A differential recorded with a sampling strategy could never replay."""
    strategies = set(_meta(DIFFERENTIAL_FIXTURES)["metamorphic_strategies"])

    assert strategies, "at least one metamorphic strategy must have been recorded"
    assert strategies <= DETERMINISTIC_STRATEGIES, (
        f"non-deterministic strategies in the committed artefact: "
        f"{sorted(strategies - DETERMINISTIC_STRATEGIES)}"
    )


def test_the_exploit_and_the_sidecars_name_the_same_seed() -> None:
    exploit = load_exploit(_exploit_path())

    assert exploit.pattern_id == _meta(GUARDED_FIXTURES)["pattern_id"]
    assert exploit.pattern_id == _meta(DIFFERENTIAL_FIXTURES)["pattern_id"]


# --- 5. the committed verdict is the one that re-derives ---------------------


def test_the_committed_verdict_matches_the_rederived_one() -> None:
    """Not just "both say KEPT". The committed report is only evidence if it
    records the same verdict, by the same formula, over the same legs as a fresh
    replay — otherwise it is a stale claim sitting next to live fixtures."""
    committed = _committed_report()
    report, _ = _rederive()

    assert committed["kept"] == report.kept
    assert committed["gating_formula"] == report.gating_formula
    assert committed["gating_legs"] == report.gating_legs
    assert committed["test_filename"] == report.test_filename
    assert {o["stage"]: o["passed"] for o in committed["outcomes"]} == {
        o.stage: o.passed for o in report.outcomes
    }


def test_the_committed_report_names_its_provenance() -> None:
    """The artefact has to say what produced it, and agree with the fixtures it
    sits beside — otherwise the reader cannot tell what the proof is a proof
    about."""
    provenance = _committed_report()["provenance"]
    differential = _meta(DIFFERENTIAL_FIXTURES)

    assert provenance["provider"] == differential["provider"]
    assert provenance["model"] == differential["model"]
    assert provenance["iterations"] == differential["iterations"]


def test_the_committed_report_carries_no_credential_shaped_keys() -> None:
    """A committed artefact derived from a live provider run must not carry one."""
    raw = REPORT_PATH.read_text(encoding="utf-8").lower()

    for needle in ("api_key", "apikey", "authorization", "bearer ", "password", "secret"):
        assert needle not in raw, f"{needle!r} appears in the committed report"


@pytest.mark.parametrize("sidecar", [GUARDED_FIXTURES, DIFFERENTIAL_FIXTURES])
def test_the_sidecars_pin_the_cache_key_version(sidecar: Path) -> None:
    """A fixture set whose sidecar does not declare its key algorithm is
    replayed under whatever the current default happens to be, which silently
    misses every key the moment that default moves."""
    assert isinstance(_meta(sidecar)["cache_key_version"], int)
