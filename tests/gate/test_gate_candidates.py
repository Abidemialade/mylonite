"""`gate` never keeps an unproven finding.

A finding whose validation kept a test but proved nothing (no passing
differential or effect leg, or a black-box keep that rests on the LLM judge)
is STABLE, NOT PROVEN. `gate` reports it as a candidate: its files never land
in the gate directory, it is never committed, and it never counts as kept.

The exit code separates the outcomes: 0 when the scan ran and found nothing,
9 when at least one proven finding was kept, 10 when only candidates remain.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite._verdict import BLACK_BOX_MARKER
from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.exit_codes import (
    EXIT_BUDGET,
    EXIT_GATE_CANDIDATES,
    EXIT_GATE_KEPT,
    EXIT_NOT_KEPT,
    EXIT_SUCCESS,
)
from mylonite.gate.orchestrator import (
    ScanOutcomeBundle,
    _finding_ids,
    candidate_line,
    run_gate,
)
from mylonite.gate.wiring import make_open_pr_fn
from mylonite.scan.coverage import AbortReason, Coverage, ScanOutcome

PROVEN = "proven-pattern"
UNPROVEN = "unproven-pattern"


def _outcome(*, abort: AbortReason | None = None, exit_code: int = 0) -> ScanOutcome:
    return ScanOutcome(
        coverage=Coverage.EXERCISED if abort is None else Coverage.PARTIAL,
        abort=abort,
        exercised=3,
        not_tested=0,
        findings=1,
        fallbacks=0,
        exit_code=exit_code,
        operator_message=None,
    )


def _exploit(pattern_id: str) -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:custom",
        pattern_id=pattern_id,
        payload=Payload(pattern_id=pattern_id, channel="user-message", body="b", metadata={}),
        response=AdapterResponse(
            payload_pattern_id=pattern_id, raw_response="r", tool_calls=[], metadata={}
        ),
        success_reason="r",
        compliance=ComplianceTags(owasp_asi=["ASI01"]),
    )


def _report(*, proven: bool, notes: str | None = None) -> ValidationReport:
    outcomes = [
        ValidationOutcome(stage="build", passed=True, detail="collects", metric=None),
        ValidationOutcome(stage="stability", passed=True, detail="3/3", metric=1.0),
    ]
    if proven:
        outcomes.append(
            ValidationOutcome(stage="differential", passed=True, detail="3/3 vs 0/3", metric=1.0)
        )
    return ValidationReport(
        test_filename="test_x.py", kept=True, outcomes=outcomes, mutation_score=None, notes=notes
    )


def _rejected_report() -> ValidationReport:
    return ValidationReport(
        test_filename="test_x.py",
        kept=False,
        outcomes=[ValidationOutcome(stage="stability", passed=False, detail="0/3", metric=0.0)],
        mutation_score=None,
    )


def _generate(exploit: ExploitRecord) -> GeneratedTest:
    return GeneratedTest(
        framework="pytest", filename="test_x.py", source="# test\n", exploit=exploit
    )


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return SimpleNamespace(opened=False, branch="b")


def _run(
    out_dir: Path,
    exploits: list[ExploitRecord],
    reports: dict[str, ValidationReport],
    *,
    open_pr_fn: Any = None,
    outcome: ScanOutcome | None = None,
    workflows: bool = False,
) -> Any:
    def validate(test: GeneratedTest, _finding_dir: Path) -> ValidationReport:
        return reports[test.exploit.pattern_id]

    return run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome or _outcome(), exploits=exploits),
        generate_fn=_generate,
        validate_fn=validate,
        open_pr_fn=open_pr_fn if open_pr_fn is not None else _Recorder(),
        open_pr=False,
        workflows=workflows,
    )


def _files_under(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


def test_a_single_unproven_finding_is_a_candidate_and_exits_10(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "gate"
    pr = _Recorder()
    result = _run(out_dir, [_exploit(UNPROVEN)], {UNPROVEN: _report(proven=False)}, open_pr_fn=pr)

    assert result.exit_code == EXIT_GATE_CANDIDATES
    assert result.kept is False
    assert result.kept_count == 0
    assert result.candidate_count == 1
    assert pr.calls == []
    # Nothing a commit could pick up: no test, exploit or report in the gate dir.
    assert _files_under(out_dir) == []
    # The evidence stays on disk, outside the gate dir, report included.
    (finding_id,) = _finding_ids([_exploit(UNPROVEN)])
    evidence = tmp_path / "gate-rej" / finding_id
    assert (evidence / f"test_{finding_id}.py").is_file()
    assert (evidence / "validation_report.json").is_file()
    out = capsys.readouterr().out
    assert "STABLE, NOT PROVEN" in out
    assert "candidate" in out
    assert "control_env" in out


def test_workflows_with_only_a_candidate_says_plainly_that_none_were_written(
    tmp_path: Path, capsys
) -> None:
    result = _run(
        tmp_path / "gate", [_exploit(UNPROVEN)], {UNPROVEN: _report(proven=False)}, workflows=True
    )

    assert result.exit_code == EXIT_GATE_CANDIDATES
    out = capsys.readouterr().out
    assert "no CI workflow file was written" in out


def test_a_proven_finding_is_kept_and_exits_9(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    pr = _Recorder()
    result = _run(out_dir, [_exploit(PROVEN)], {PROVEN: _report(proven=True)}, open_pr_fn=pr)

    assert result.exit_code == EXIT_GATE_KEPT
    assert result.kept is True
    assert result.kept_count == 1
    assert result.candidate_count == 0
    assert len(pr.calls) == 1


def test_a_clean_scan_still_exits_0(tmp_path: Path) -> None:
    clean = ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=3,
        not_tested=0,
        findings=0,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )
    result = _run(tmp_path / "gate", [], {}, outcome=clean)
    assert result.exit_code == EXIT_SUCCESS


def test_workflows_on_a_clean_scan_says_plainly_that_none_were_written(
    tmp_path: Path, capsys
) -> None:
    """`--workflows` only ever wires in a KEPT finding's test. A clean scan
    keeps nothing, so no workflow file is written -- this must say so, not
    exit as quietly as a plain `gate` with no findings at all."""
    clean = ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=3,
        not_tested=0,
        findings=0,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )
    result = _run(tmp_path / "gate", [], {}, outcome=clean, workflows=True)

    assert result.exit_code == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "no CI workflow file was written" in out


def test_workflows_with_only_a_rejected_finding_says_plainly_that_none_were_written(
    tmp_path: Path, capsys
) -> None:
    result = _run(
        tmp_path / "gate",
        [_exploit(UNPROVEN)],
        {UNPROVEN: _rejected_report()},
        workflows=True,
    )

    assert result.exit_code == EXIT_NOT_KEPT
    out = capsys.readouterr().out
    assert "no CI workflow file was written" in out


def test_workflows_without_the_flag_says_nothing_extra_about_workflows(
    tmp_path: Path, capsys
) -> None:
    """Without `--workflows`, the operator never asked for one, so the extra
    note would just be noise."""
    result = _run(
        tmp_path / "gate",
        [_exploit(UNPROVEN)],
        {UNPROVEN: _rejected_report()},
        workflows=False,
    )

    assert result.exit_code == EXIT_NOT_KEPT
    out = capsys.readouterr().out
    assert "no CI workflow file was written" not in out


def test_kept_and_candidate_commit_only_the_kept_finding(tmp_path: Path, monkeypatch) -> None:
    """The real open_pr_fn's commit list holds the kept finding's files only."""
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "gate"
    pr_mod = SimpleNamespace(
        calls=[],
        GatePaths=lambda **kw: SimpleNamespace(**kw),
        resolve_repo_root=lambda: tmp_path,
        resolve_default_base=lambda _root: "main",
    )

    def open_or_print_pr(paths: Any, **kwargs: Any) -> Any:
        pr_mod.calls.append({"paths": paths, **kwargs})
        return SimpleNamespace(opened=False, branch=kwargs.get("branch"))

    pr_mod.open_or_print_pr = open_or_print_pr
    open_pr_fn = make_open_pr_fn(
        model="test/model",
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=None,
        pr_mod=pr_mod,
    )
    exploits = [_exploit(PROVEN), _exploit(UNPROVEN)]
    result = _run(
        out_dir,
        exploits,
        {PROVEN: _report(proven=True), UNPROVEN: _report(proven=False)},
        open_pr_fn=open_pr_fn,
    )

    assert result.exit_code == EXIT_GATE_KEPT
    assert (result.kept_count, result.candidate_count, result.rejected_count) == (1, 1, 0)
    ordered = sorted(exploits, key=lambda e: e.pattern_id)
    ids = {e.pattern_id: fid for e, fid in zip(ordered, _finding_ids(ordered), strict=True)}
    (call,) = pr_mod.calls
    committed = [Path(p) for p in call["paths"].add_paths]
    assert not any(ids[UNPROVEN] in str(p) for p in committed)
    assert any(ids[PROVEN] in str(p) for p in committed)
    # No candidate file anywhere in the gate dir.
    assert not (out_dir / ids[UNPROVEN]).exists()
    assert not any(ids[UNPROVEN] in str(p) for p in _files_under(out_dir))
    # The PR body lists the candidate, with why and how to prove it.
    body = call["pr_body"]
    assert "Candidates (not proven, not committed)" in body
    assert f"`{UNPROVEN}`" in body
    assert "control_env" in body


def test_candidates_and_rejected_with_nothing_kept_exit_10(tmp_path: Path) -> None:
    pr = _Recorder()
    result = _run(
        tmp_path / "gate",
        [_exploit(PROVEN), _exploit(UNPROVEN)],
        {PROVEN: _rejected_report(), UNPROVEN: _report(proven=False)},
        open_pr_fn=pr,
    )
    assert result.exit_code == EXIT_GATE_CANDIDATES
    assert (result.kept_count, result.candidate_count, result.rejected_count) == (0, 1, 1)
    assert pr.calls == []
    assert _files_under(tmp_path / "gate") == []


def test_an_aborted_scan_still_wins_over_a_candidate(tmp_path: Path) -> None:
    result = _run(
        tmp_path / "gate",
        [_exploit(UNPROVEN)],
        {UNPROVEN: _report(proven=False)},
        outcome=_outcome(abort=AbortReason.BUDGET_EXCEEDED, exit_code=EXIT_BUDGET),
    )
    assert result.exit_code == EXIT_BUDGET
    assert result.candidate_count == 1


def test_an_aborted_scan_still_wins_over_a_kept_finding(tmp_path: Path) -> None:
    result = _run(
        tmp_path / "gate",
        [_exploit(PROVEN)],
        {PROVEN: _report(proven=True)},
        outcome=_outcome(abort=AbortReason.BUDGET_EXCEEDED, exit_code=EXIT_BUDGET),
    )
    assert result.exit_code == EXIT_BUDGET
    assert result.kept_count == 1


def test_a_black_box_keep_is_a_candidate_that_gate_cannot_prove(tmp_path: Path, capsys) -> None:
    result = _run(
        tmp_path / "gate",
        [_exploit(UNPROVEN)],
        {UNPROVEN: _report(proven=True, notes=f"legs {BLACK_BOX_MARKER}")},
    )
    assert result.exit_code == EXIT_GATE_CANDIDATES
    out = capsys.readouterr().out
    assert "black-box" in out
    assert "control_env" not in out


@pytest.mark.parametrize("notes", [None, f"legs {BLACK_BOX_MARKER}"])
def test_the_candidate_line_prints_on_a_cp1252_console(notes: str | None) -> None:
    line = candidate_line(_exploit(UNPROVEN), _report(proven=notes is not None, notes=notes))
    line.encode("cp1252")
    assert "\n" not in line


def test_a_candidate_leaves_an_earlier_kept_report_in_the_gate_dir_alone(tmp_path: Path) -> None:
    """A single-finding run writes straight into the gate dir, which can hold
    an earlier run's kept report. The candidate's report goes with its
    evidence, never over the kept one. The earlier kept test, exploit and
    fixtures are covered by the re-run tests below."""
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    earlier = out_dir / "validation_report.json"
    earlier.write_text('{"kept": true}\n', encoding="utf-8")

    result = _run(out_dir, [_exploit(UNPROVEN)], {UNPROVEN: _report(proven=False)})

    assert result.exit_code == EXIT_GATE_CANDIDATES
    assert earlier.read_text(encoding="utf-8") == '{"kept": true}\n'
    assert [p.name for p in _files_under(out_dir)] == ["validation_report.json"]


def _recording_run(
    out_dir: Path, exploits: list[ExploitRecord], reports: dict[str, ValidationReport], tag: str
) -> Any:
    """Run the gate with a validator that records replay fixtures the way the
    reference route does: into the finding's own folder, content tagged by run."""

    def validate(test: GeneratedTest, finding_dir: Path) -> ValidationReport:
        fixtures = finding_dir / "fixtures"
        fixtures.mkdir(parents=True, exist_ok=True)
        (fixtures / f"{tag}.json").write_text(f'{{"run": "{tag}"}}', encoding="utf-8")
        (fixtures / "_meta.json").write_text(f'{{"run": "{tag}"}}', encoding="utf-8")
        return reports[test.exploit.pattern_id]

    return run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_outcome(), exploits=exploits),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source=f"# {tag}\n", exploit=e
        ),
        validate_fn=validate,
        open_pr_fn=_Recorder(),
        open_pr=False,
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in _files_under(root)}


@pytest.mark.parametrize(
    ("second", "expected_exit"),
    [("candidate", EXIT_GATE_CANDIDATES), ("rejected", EXIT_NOT_KEPT)],
)
def test_a_rerun_that_does_not_keep_leaves_the_earlier_kept_test_in_place(
    tmp_path: Path, second: str, expected_exit: int
) -> None:
    """A KEPT run, then a run of the same finding id that is not kept: the
    earlier test, exploit, report and fixtures stay byte for byte."""
    out_dir = tmp_path / "gate"
    first = _recording_run(out_dir, [_exploit(UNPROVEN)], {UNPROVEN: _report(proven=True)}, "run1")
    assert first.exit_code == EXIT_GATE_KEPT
    before = _snapshot(out_dir)
    (finding_id,) = _finding_ids([_exploit(UNPROVEN)])
    assert {f"test_{finding_id}.py", "fixtures/run1.json", "fixtures/_meta.json"} <= set(before)

    report = _report(proven=False) if second == "candidate" else _rejected_report()
    result = _recording_run(out_dir, [_exploit(UNPROVEN)], {UNPROVEN: report}, "run2")

    assert result.exit_code == expected_exit
    assert _snapshot(out_dir) == before
    # The second run's own recordings went with its evidence.
    evidence = tmp_path / "gate-rej" / finding_id
    assert (evidence / "fixtures" / "run2.json").is_file()
    assert (evidence / f"test_{finding_id}.py").read_text(encoding="utf-8") == "# run2\n"


def test_a_multi_finding_rerun_keeps_an_earlier_kept_finding_folder(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    exploits = [_exploit(PROVEN), _exploit(UNPROVEN)]
    proven = {PROVEN: _report(proven=True), UNPROVEN: _report(proven=True)}
    assert _recording_run(out_dir, exploits, proven, "run1").exit_code == EXIT_GATE_KEPT
    before = _snapshot(out_dir)

    second = {PROVEN: _report(proven=True), UNPROVEN: _report(proven=False)}
    result = _recording_run(out_dir, exploits, second, "run2")

    assert result.exit_code == EXIT_GATE_KEPT
    assert (result.kept_count, result.candidate_count) == (1, 1)
    ordered = sorted(exploits, key=lambda e: e.pattern_id)
    ids = {e.pattern_id: fid for e, fid in zip(ordered, _finding_ids(ordered), strict=True)}
    after = _snapshot(out_dir)
    unproven_files = {k: v for k, v in before.items() if k.startswith(ids[UNPROVEN] + "/")}
    assert unproven_files
    assert {k: after.get(k) for k in unproven_files} == unproven_files
    assert not any(k.startswith(ids[UNPROVEN] + "/fixtures/run2") for k in after)
