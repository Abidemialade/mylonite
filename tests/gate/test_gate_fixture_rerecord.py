"""`gate` re-records a finding's own replay fixtures from scratch.

A re-run of the same finding id removes that finding's earlier `fixtures/`
folder before validating (it may be in an older replay-key format, which the
recorder refuses to extend). A run that keeps replaces it; a run that does not
keep, or stops on an error, puts the earlier folder back byte for byte. A
fixture error fails only its own finding: the other findings still run.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.gate.test_gate_candidates import (
    PROVEN,
    UNPROVEN,
    _exploit,
    _outcome,
    _Recorder,
    _rejected_report,
    _report,
    _snapshot,
)

from mylonite._replay import FixtureVersionError
from mylonite.contracts._types import ExploitRecord, GeneratedTest, ValidationReport
from mylonite.exit_codes import EXIT_GATE_KEPT
from mylonite.gate.orchestrator import ScanOutcomeBundle, _finding_ids, run_gate

_OLD_META = '{"cache_key_version": 2}'


def _run(out_dir: Path, exploits: list[ExploitRecord], validate) -> object:  # type: ignore[no-untyped-def]
    return run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_outcome(), exploits=exploits),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="# new\n", exploit=e
        ),
        validate_fn=validate,
        open_pr_fn=_Recorder(),
        open_pr=False,
    )


def _old_folder(out_dir: Path) -> Path:
    """A single-finding gate dir whose fixtures were recorded in the v2 format."""
    fixtures = out_dir / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "_meta.json").write_text(_OLD_META, encoding="utf-8")
    (fixtures / "old.json").write_text('{"run": "old"}', encoding="utf-8")
    return fixtures


def _recording(report: ValidationReport):  # type: ignore[no-untyped-def]
    def validate(test: GeneratedTest, finding_dir: Path) -> ValidationReport:
        fixtures = finding_dir / "fixtures"
        # The recorder would refuse an older-format folder; gate removed it.
        assert not fixtures.exists()
        fixtures.mkdir(parents=True)
        (fixtures / "_meta.json").write_text('{"cache_key_version": 3}', encoding="utf-8")
        (fixtures / "new.json").write_text('{"run": "new"}', encoding="utf-8")
        return report

    return validate


def test_a_kept_rerun_replaces_an_older_fixtures_folder(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    _old_folder(out_dir)
    result = _run(out_dir, [_exploit(PROVEN)], _recording(_report(proven=True)))
    assert result.exit_code == EXIT_GATE_KEPT  # type: ignore[attr-defined]
    fixtures = out_dir / "fixtures"
    assert sorted(p.name for p in fixtures.iterdir()) == ["_meta.json", "new.json"]


def test_a_rejected_rerun_restores_the_older_fixtures_folder(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    _old_folder(out_dir)
    before = _snapshot(out_dir)
    _run(out_dir, [_exploit(PROVEN)], _recording(_rejected_report()))
    assert _snapshot(out_dir) == before


def test_a_fixture_error_fails_only_its_own_finding(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    out_dir = tmp_path / "gate"
    exploits = [_exploit(PROVEN), _exploit(UNPROVEN)]
    ordered = sorted(exploits, key=lambda e: e.pattern_id)
    ids = {e.pattern_id: fid for e, fid in zip(ordered, _finding_ids(ordered), strict=True)}
    _old_folder(out_dir / ids[UNPROVEN])
    before = _snapshot(out_dir / ids[UNPROVEN])

    def validate(test: GeneratedTest, finding_dir: Path) -> ValidationReport:
        if test.exploit.pattern_id == UNPROVEN:
            raise FixtureVersionError("refusing to record into somewhere")
        return _recording(_report(proven=True))(test, finding_dir)

    result = _run(out_dir, exploits, validate)

    assert result.exit_code == EXIT_GATE_KEPT  # type: ignore[attr-defined]
    assert result.kept_count == 1  # type: ignore[attr-defined]
    assert _snapshot(out_dir / ids[UNPROVEN]) == before
    out = capsys.readouterr().out
    assert "replay fixtures could not be recorded" in out
    assert "Traceback" not in out


def test_any_other_stop_restores_the_older_fixtures_and_propagates(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    _old_folder(out_dir)

    def validate(test: GeneratedTest, finding_dir: Path) -> ValidationReport:
        _recording(_report(proven=True))(test, finding_dir)
        raise RuntimeError("the target went down")

    with pytest.raises(RuntimeError, match="went down"):
        _run(out_dir, [_exploit(PROVEN)], validate)
    fixtures = out_dir / "fixtures"
    assert sorted(p.name for p in fixtures.iterdir()) == ["_meta.json", "old.json"]
    assert (fixtures / "_meta.json").read_text(encoding="utf-8") == _OLD_META
