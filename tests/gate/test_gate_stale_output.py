"""Reusing the same ``gate --out`` directory across runs.

``gate`` never deletes anything from ``--out``. A finding kept by an earlier
run against this directory, but not re-found (or not kept again) by the
current run, is left exactly as it was -- "not found again" is not evidence
the finding is fixed: a flaky planner miss, a NOT TESTED or aborted attempt,
or a target file that now declares a narrower ``weakness_classes`` can all
make a real, still-live finding vanish from one run's own result. The run
instead reports each one it did not touch, by id, so the operator can decide
for themselves whether to remove it. A finding the current run DOES keep
again is left to the usual generate/validate/write path and never named in
that report; a same-named kept test from THIS run is never lost, and two
different findings that collide on a short id still land in two distinct
places.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.gate._proven import proven_legs

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    ValidationReport,
)
from mylonite.exit_codes import EXIT_BUDGET, EXIT_GATE_KEPT
from mylonite.gate.orchestrator import (
    ScanOutcomeBundle,
    _finding_id,
    _leftover_earlier_findings,
    exploit_filename_for,
    gate_test_filename,
    run_gate,
)
from mylonite.scan.coverage import AbortReason, Coverage, ScanOutcome


def _outcome(**overrides: Any) -> ScanOutcome:
    base = dict(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=3,
        not_tested=0,
        findings=1,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )
    base.update(overrides)
    return ScanOutcome(**base)


def _exploit(pattern_id: str, weakness: str = "W4") -> ExploitRecord:
    return ExploitRecord(
        target_id="reference:vulnerable",
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id, channel="user-message", body="b", metadata={"weakness": weakness}
        ),
        response=AdapterResponse(
            payload_pattern_id=pattern_id, raw_response="r", tool_calls=[], metadata={}
        ),
        success_reason="r",
        compliance=ComplianceTags(owasp_asi=["ASI02"]),
    )


def _kept_report() -> ValidationReport:
    return ValidationReport(
        test_filename="test_x.py", kept=True, outcomes=proven_legs(), mutation_score=None
    )


class _Recorder:
    def __call__(self, **kwargs: Any) -> Any:
        return SimpleNamespace(opened=False, branch="b")


def _run(
    out_dir: Path,
    exploits: list[ExploitRecord],
    reports: dict[str, ValidationReport],
    *,
    record_fixture: bool = True,
    outcome: ScanOutcome | None = None,
) -> Any:
    def validate(test: GeneratedTest, finding_dir: Path) -> ValidationReport:
        if record_fixture:
            fixtures = finding_dir / "fixtures"
            fixtures.mkdir(parents=True, exist_ok=True)
            (fixtures / "abcdef012345.json").write_text('{"k": "v"}', encoding="utf-8")
            (fixtures / "_meta.json").write_text("{}", encoding="utf-8")
        return reports[test.exploit.pattern_id]

    return run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome or _outcome(), exploits=exploits),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="# t\n", exploit=e
        ),
        validate_fn=validate,
        open_pr_fn=_Recorder(),
        open_pr=False,
    )


def test_an_earlier_kept_multi_finding_not_refound_survives_and_is_listed(
    tmp_path: Path, capsys: Any
) -> None:
    out_dir = tmp_path / "gate"
    a, b = _exploit("pattern-a"), _exploit("pattern-b")
    first = _run(out_dir, [a, b], {"pattern-a": _kept_report(), "pattern-b": _kept_report()})
    assert first.exit_code == EXIT_GATE_KEPT
    a_dir, b_dir = out_dir / _finding_id(a), out_dir / _finding_id(b)
    assert a_dir.is_dir() and b_dir.is_dir()
    b_test = b_dir / gate_test_filename(_finding_id(b))
    b_before = b_test.read_bytes()
    b_fixture_before = (b_dir / "fixtures" / "abcdef012345.json").read_bytes()
    capsys.readouterr()

    # Run 2 only ever finds `a` again -- `b`'s folder is this gate's own
    # earlier output. Nothing here removes it: a flaky miss, a NOT TESTED
    # attempt or a narrower target scope could all explain its absence just
    # as easily as a real fix.
    second = _run(out_dir, [a], {"pattern-a": _kept_report()})

    assert second.exit_code == EXIT_GATE_KEPT
    assert a_dir.is_dir(), "the id this run kept again must not be disturbed"
    assert b_dir.is_dir(), "an earlier kept finding this run didn't re-find must survive"
    assert b_test.read_bytes() == b_before
    assert (b_dir / "fixtures" / "abcdef012345.json").read_bytes() == b_fixture_before
    out = capsys.readouterr().out
    assert _finding_id(b) in out
    assert "left in place" in out
    assert "not re-proven this run" in out


def test_a_single_finding_root_pair_not_refound_survives_and_is_listed(
    tmp_path: Path, capsys: Any
) -> None:
    out_dir = tmp_path / "gate"
    old = _exploit("pattern-old")
    first = _run(out_dir, [old], {"pattern-old": _kept_report()})
    assert first.exit_code == EXIT_GATE_KEPT
    old_id = _finding_id(old)
    old_test = out_dir / gate_test_filename(old_id)
    old_exploit = out_dir / exploit_filename_for(old_test.name)
    old_test_before = old_test.read_bytes()
    old_exploit_before = old_exploit.read_bytes()
    capsys.readouterr()

    new = _exploit("pattern-new")
    second = _run(out_dir, [new], {"pattern-new": _kept_report()})

    assert second.exit_code == EXIT_GATE_KEPT
    assert old_test.is_file() and old_test.read_bytes() == old_test_before
    assert old_exploit.is_file() and old_exploit.read_bytes() == old_exploit_before
    new_id = _finding_id(new)
    assert (out_dir / gate_test_filename(new_id)).is_file()
    out = capsys.readouterr().out
    assert old_id in out


def test_a_filtered_run_leaves_the_other_weakness_classs_test_untouched(
    tmp_path: Path, capsys: Any
) -> None:
    """A narrower scan (a target file declaring a narrower ``weakness_classes``,
    or the ``--weakness-class`` filter) means this run's own exploits never
    include the other class at all -- that must read exactly like "not
    re-found", not like a reason to remove it."""
    out_dir = tmp_path / "gate"
    w2, w4 = _exploit("pattern-w2", weakness="W2"), _exploit("pattern-w4", weakness="W4")
    first = _run(out_dir, [w2, w4], {"pattern-w2": _kept_report(), "pattern-w4": _kept_report()})
    assert first.exit_code == EXIT_GATE_KEPT
    w4_dir = out_dir / _finding_id(w4)
    w4_test_path = w4_dir / gate_test_filename(_finding_id(w4))
    w4_test_before = w4_test_path.read_bytes()
    capsys.readouterr()

    # A run scoped to W2 only (the filtered run) never even sees the W4 finding.
    second = _run(out_dir, [w2], {"pattern-w2": _kept_report()})

    assert second.exit_code == EXIT_GATE_KEPT
    assert w4_dir.is_dir()
    assert w4_test_path.read_bytes() == w4_test_before
    out = capsys.readouterr().out
    assert _finding_id(w4) in out


def test_a_user_file_inside_an_earlier_finding_folder_survives(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    a, b = _exploit("pattern-ua"), _exploit("pattern-ub")
    first = _run(out_dir, [a, b], {"pattern-ua": _kept_report(), "pattern-ub": _kept_report()})
    assert first.exit_code == EXIT_GATE_KEPT
    b_dir = out_dir / _finding_id(b)
    user_file = b_dir / "notes_from_the_reviewer.md"
    user_file.write_text("do not delete -- reviewed by hand\n", encoding="utf-8")
    user_conftest = b_dir / "conftest.py"
    user_conftest.write_text("# hand-added\n", encoding="utf-8")

    second = _run(out_dir, [a], {"pattern-ua": _kept_report()})

    assert second.exit_code == EXIT_GATE_KEPT
    assert user_file.read_text(encoding="utf-8") == "do not delete -- reviewed by hand\n"
    assert user_conftest.read_text(encoding="utf-8") == "# hand-added\n"


def test_a_same_id_kept_again_is_never_treated_as_stale(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    exploit = _exploit("pattern-same")
    first = _run(out_dir, [exploit], {"pattern-same": _kept_report()})
    assert first.exit_code == EXIT_GATE_KEPT
    test_path = out_dir / gate_test_filename(_finding_id(exploit))
    before = test_path.read_bytes()

    second = _run(out_dir, [exploit], {"pattern-same": _kept_report()})

    assert second.exit_code == EXIT_GATE_KEPT
    assert test_path.is_file()
    assert test_path.read_bytes() == before


def test_a_directory_shaped_like_an_id_without_the_marker_file_is_left_alone(
    tmp_path: Path, capsys: Any
) -> None:
    """A folder that merely looks like a finding id, but holds none of this
    gate's own ``exploit_*.json`` marker files, is a user's own -- never
    removed, and never named in the leftover report."""
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    lookalike = out_dir / "w4-abc123"
    lookalike.mkdir()
    (lookalike / "notes.txt").write_text("mine", encoding="utf-8")

    result = _run(out_dir, [_exploit("pattern-fresh")], {"pattern-fresh": _kept_report()})

    assert result.exit_code == EXIT_GATE_KEPT
    assert (lookalike / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert "w4-abc123" not in capsys.readouterr().out


def test_a_root_test_file_without_a_matching_exploit_marker_is_left_alone(
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    stray = out_dir / "test_w4-abc123.py"
    stray.write_text("# not ours\n", encoding="utf-8")

    result = _run(out_dir, [_exploit("pattern-fresh2")], {"pattern-fresh2": _kept_report()})

    assert result.exit_code == EXIT_GATE_KEPT
    assert stray.is_file()


def test_a_root_exploit_file_that_is_not_valid_json_is_left_alone(tmp_path: Path) -> None:
    """A ``test_<id>.py`` / ``exploit_<id>.json`` pair only counts as this
    gate's own marker when the exploit file actually parses as one of its
    records -- not merely by filename."""
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    fake_id = "w4-abc123"
    (out_dir / gate_test_filename(fake_id)).write_text("# mine\n", encoding="utf-8")
    fake_exploit = out_dir / exploit_filename_for(gate_test_filename(fake_id))
    fake_exploit.write_text("not json", encoding="utf-8")

    result = _run(out_dir, [_exploit("pattern-fresh3")], {"pattern-fresh3": _kept_report()})

    assert result.exit_code == EXIT_GATE_KEPT
    assert fake_exploit.read_text(encoding="utf-8") == "not json"


def test_colliding_short_ids_in_one_run_still_land_in_two_folders(tmp_path: Path) -> None:
    """Two different findings that hash to the same short id in the SAME
    run must never overwrite each other's folder (pre-existing de-dup,
    guarded here against the leftover report running before it)."""
    out_dir = tmp_path / "gate"

    class _FixedId:
        def __call__(self, exploit: ExploitRecord) -> str:
            return "w4-collide"

    import mylonite.gate.orchestrator as orch

    original = orch._finding_id
    orch._finding_id = _FixedId()  # type: ignore[assignment]
    try:
        a, b = _exploit("pattern-collide-a"), _exploit("pattern-collide-b")
        result = _run(
            out_dir,
            [a, b],
            {"pattern-collide-a": _kept_report(), "pattern-collide-b": _kept_report()},
        )
    finally:
        orch._finding_id = original  # type: ignore[assignment]

    assert result.exit_code == EXIT_GATE_KEPT
    assert (out_dir / "w4-collide").is_dir()
    assert (out_dir / "w4-collide-2").is_dir()


def test_an_aborted_scan_adds_the_abort_reason_to_the_leftover_note(
    tmp_path: Path, capsys: Any
) -> None:
    out_dir = tmp_path / "gate"
    a, b = _exploit("pattern-abort-a"), _exploit("pattern-abort-b")
    first = _run(
        out_dir, [a, b], {"pattern-abort-a": _kept_report(), "pattern-abort-b": _kept_report()}
    )
    assert first.exit_code == EXIT_GATE_KEPT
    capsys.readouterr()

    aborted = _outcome(
        coverage=Coverage.PARTIAL,
        abort=AbortReason.BUDGET_EXCEEDED,
        findings=1,
        exit_code=EXIT_BUDGET,
    )
    second = _run(out_dir, [a], {"pattern-abort-a": _kept_report()}, outcome=aborted)

    # The pre-existing "an abort always wins" exit-code rule is unaffected by
    # the leftover note: a kept finding alongside an abort still exits with
    # the abort's own code, not EXIT_GATE_KEPT.
    assert second.exit_code == EXIT_BUDGET
    out = capsys.readouterr().out
    assert _finding_id(b) in out
    assert "aborted" in out
    assert AbortReason.BUDGET_EXCEEDED.value in out


def test_a_partial_coverage_scan_adds_the_reason_to_the_leftover_note(
    tmp_path: Path, capsys: Any
) -> None:
    out_dir = tmp_path / "gate"
    a, b = _exploit("pattern-partial-a"), _exploit("pattern-partial-b")
    first = _run(
        out_dir, [a, b], {"pattern-partial-a": _kept_report(), "pattern-partial-b": _kept_report()}
    )
    assert first.exit_code == EXIT_GATE_KEPT
    capsys.readouterr()

    partial = _outcome(coverage=Coverage.PARTIAL, not_tested=2, findings=1)
    second = _run(out_dir, [a], {"pattern-partial-a": _kept_report()}, outcome=partial)

    assert second.exit_code == EXIT_GATE_KEPT
    out = capsys.readouterr().out
    assert _finding_id(b) in out
    assert "partial" in out


def _can_make_symlink(target: Path, link: Path) -> bool:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        return False
    return True


def test_a_symlink_or_junction_child_does_not_crash_the_listing(tmp_path: Path) -> None:
    """A symlink or junction sitting where a finding folder would be must
    never crash the leftover listing -- it is always skipped, since this
    code only ever reads, and a link into somewhere unexpected is never
    worth following just to decide what to print."""
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    real_target = tmp_path / "elsewhere"
    real_target.mkdir()
    (real_target / "exploit_sneaky.json").write_text(
        '{"pattern_id": "sneaky", "payload": {}}', encoding="utf-8"
    )
    link = out_dir / "w4-abc123"

    if not _can_make_symlink(real_target, link):
        pytest.skip("this platform/user cannot create a symlink or junction")

    # Must not raise, and must not report the link as a leftover finding --
    # it is never followed.
    leftovers = _leftover_earlier_findings(out_dir, set())

    assert leftovers == []


def test_a_symlinked_test_file_does_not_crash_the_listing(tmp_path: Path) -> None:
    out_dir = tmp_path / "gate"
    out_dir.mkdir()
    real_test = tmp_path / "real_test.py"
    real_test.write_text("# elsewhere\n", encoding="utf-8")
    link = out_dir / "test_w4-abc123.py"

    if not _can_make_symlink(real_test, link):
        pytest.skip("this platform/user cannot create a symlink")

    leftovers = _leftover_earlier_findings(out_dir, set())

    assert leftovers == []
