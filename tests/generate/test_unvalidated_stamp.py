"""`generate` never passes a candidate test off as a proven one.

A test written straight from a scan is a candidate until `mylonite validate`
keeps it, so it carries an UNVALIDATED header. Generating from a validation
that did not keep the test (rejected, or stable but not proven) is refused
unless `--unvalidated` is passed, and the result is stamped. `validate` removes
the header only on a KEPT verdict.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.contracts import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.exit_codes import EXIT_NOT_KEPT, EXIT_SUCCESS
from mylonite.generate import provenance
from mylonite.generate.provenance import (
    UNVALIDATED_MARKER,
    input_verdict,
    is_unvalidated,
    stamp_unvalidated,
    strip_unvalidated,
    sync_stamp,
)

runner = CliRunner()

_PID = "indirect-injection-note-body-direct"


def _exploit(pid: str = _PID) -> ExploitRecord:
    return ExploitRecord(
        target_id="reference:vulnerable",
        pattern_id=pid,
        payload=Payload(pattern_id=pid, channel="tool-result", body="x"),
        response=AdapterResponse(payload_pattern_id=pid, raw_response="ok"),
        success_reason="called the tool",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )


def _write_exploit(path: Path, pid: str = _PID) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_exploit(pid).model_dump(mode="json"), indent=2), encoding="utf-8")
    return path


def _report(*, kept: bool, build_ran: bool = True, test_filename: str = "t.py") -> ValidationReport:
    return ValidationReport(
        test_filename=test_filename,
        kept=kept,
        outcomes=[
            ValidationOutcome(
                stage="build", passed=build_ran, report_only=not build_ran, detail=""
            ),
            ValidationOutcome(stage="differential", passed=kept, detail=""),
        ],
    )


def _write_report(dir_path: Path, report: ValidationReport) -> None:
    (dir_path / "validation_report.json").write_text(report.model_dump_json(), encoding="utf-8")


def _emitted_source(out_dir: Path) -> str:
    (test_file,) = out_dir.glob("test_security_*.py")
    return test_file.read_text(encoding="utf-8")


# --- the stamp itself --------------------------------------------------------


def test_stamp_is_a_leading_header_that_strips_back_to_the_original() -> None:
    source = '"""doc"""\n\nimport pytest\n'
    stamped = stamp_unvalidated(source)
    assert stamped.startswith(UNVALIDATED_MARKER)
    assert "UNVALIDATED" in stamped
    assert "mylonite validate" in stamped
    assert is_unvalidated(stamped)
    assert not is_unvalidated(source)
    assert stamp_unvalidated(stamped) == stamped  # idempotent
    assert strip_unvalidated(stamped) == source
    assert strip_unvalidated(source) == source


def test_stamped_source_still_compiles() -> None:
    compile(stamp_unvalidated('"""doc"""\nX = 1\n'), "t.py", "exec")


# --- what counts as validated --------------------------------------------------


def test_input_verdict_reads_the_sibling_validation_report(tmp_path: Path) -> None:
    exploit = _write_exploit(tmp_path / "exploit_a.json")
    assert input_verdict(exploit) is None
    _write_report(tmp_path, _report(kept=True))
    assert input_verdict(exploit) == "KEPT"
    _write_report(tmp_path, _report(kept=True, build_ran=False))
    assert input_verdict(exploit) == "STABLE, NOT PROVEN"
    _write_report(tmp_path, _report(kept=False))
    assert input_verdict(exploit) == "REJECTED"
    (tmp_path / "validation_report.json").write_text("{not json", encoding="utf-8")
    assert input_verdict(exploit) == provenance.UNREADABLE


# --- the generate command ------------------------------------------------------


def test_generate_from_a_scan_stamps_the_test_and_says_so(tmp_path: Path) -> None:
    """The documented first run (scan, then generate, then validate) still works."""
    exploit = _write_exploit(tmp_path / "scans" / "s1" / "exploit_a.json")
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(exploit), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))
    assert "UNVALIDATED" in result.output
    assert f"mylonite validate {out_dir}" in result.output


def _kept_dir(tmp_path: Path) -> Path:
    """A folder as `generate` and then a KEPT `validate` leave it."""
    exploit = _write_exploit(tmp_path / "scans" / "s1" / "exploit_a.json")
    src = tmp_path / "validated"
    result = runner.invoke(app, ["generate", str(exploit), "--out", str(src)])
    assert result.exit_code == EXIT_SUCCESS, result.output
    (test_file,) = src.glob("test_security_*.py")
    _write_report(src, _report(kept=True, test_filename=test_file.name))
    return src


def test_generate_from_a_kept_validation_writes_an_unstamped_test(tmp_path: Path) -> None:
    src = _kept_dir(tmp_path)
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert not is_unvalidated(_emitted_source(out_dir))
    assert "UNVALIDATED" not in result.output


def test_generate_in_place_from_a_kept_validation_stays_unstamped(tmp_path: Path) -> None:
    src = _kept_dir(tmp_path)

    result = runner.invoke(app, ["generate", str(src), "--out", str(src)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert not is_unvalidated(_emitted_source(src))


def test_generate_kept_report_without_its_test_stamps(tmp_path: Path) -> None:
    src = tmp_path / "validated"
    exploit = _write_exploit(src / "exploit_a.json")
    _write_report(src, _report(kept=True))  # names a test that is not there
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(exploit), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))


def test_generate_kept_report_whose_test_was_edited_stamps(tmp_path: Path) -> None:
    src = _kept_dir(tmp_path)
    (test_file,) = src.glob("test_security_*.py")
    test_file.write_text(test_file.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))


def test_generate_prove_control_on_a_kept_validation_stamps(tmp_path: Path) -> None:
    """The KEPT report proved the standard test, not a control-efficacy one."""
    src = _kept_dir(tmp_path)
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir), "--prove-control"])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))


def test_generate_kept_folder_with_two_exploits_stamps_both(tmp_path: Path) -> None:
    """validate proves one exploit per folder, so the report cannot vouch for both."""
    src = _kept_dir(tmp_path)
    _write_exploit(src / "exploit_b.json", pid="another-finding")
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    tests = sorted(out_dir.rglob("test_security_*.py"))
    assert len(tests) == 2
    assert all(is_unvalidated(t.read_text(encoding="utf-8")) for t in tests)


def test_generate_stale_kept_report_next_to_a_replaced_exploit_stamps(tmp_path: Path) -> None:
    src = _kept_dir(tmp_path)
    (exploit,) = src.glob("exploit_*.json")
    report_mtime = (src / "validation_report.json").stat().st_mtime
    os.utime(exploit, (report_mtime + 60, report_mtime + 60))  # copied in after the keep
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))


@pytest.mark.parametrize(
    ("report", "label"),
    [
        (_report(kept=False), "REJECTED"),
        (_report(kept=True, build_ran=False), "STABLE, NOT PROVEN"),
    ],
)
def test_generate_refuses_a_validation_that_did_not_keep_the_test(
    tmp_path: Path, report: ValidationReport, label: str
) -> None:
    src = tmp_path / "validated"
    exploit = _write_exploit(src / "exploit_a.json")
    _write_report(src, report)
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir)])

    assert result.exit_code == EXIT_NOT_KEPT, result.output
    assert label in result.output
    assert "--unvalidated" in result.output
    assert not out_dir.exists()  # refused before anything was written
    assert exploit.is_file()


def test_generate_unvalidated_flag_writes_the_candidate_stamped(tmp_path: Path) -> None:
    src = tmp_path / "validated"
    _write_exploit(src / "exploit_a.json")
    _write_report(src, _report(kept=True, build_ran=False))
    out_dir = tmp_path / "gen"

    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir), "--unvalidated"])

    assert result.exit_code == EXIT_SUCCESS, result.output
    assert is_unvalidated(_emitted_source(out_dir))
    assert "UNVALIDATED" in result.output


def test_generate_refuses_an_unreadable_validation_report(tmp_path: Path) -> None:
    src = tmp_path / "validated"
    _write_exploit(src / "exploit_a.json")
    (src / "validation_report.json").write_text("{not json", encoding="utf-8")

    result = runner.invoke(app, ["generate", str(src), "--out", str(tmp_path / "gen")])

    assert result.exit_code == EXIT_NOT_KEPT, result.output


# --- validate clears the stamp only on KEPT ------------------------------------


@pytest.mark.parametrize("stamped", [True, False])
@pytest.mark.parametrize(
    ("report", "kept"),
    [
        (_report(kept=True), True),
        (_report(kept=True, build_ran=False), False),
        (_report(kept=False), False),
    ],
)
def test_sync_stamp_follows_the_latest_verdict(
    tmp_path: Path, report: ValidationReport, kept: bool, stamped: bool
) -> None:
    """KEPT removes the header; any other verdict adds it, to unstamped tests too."""
    test_path = tmp_path / "test_security_x.py"
    body = '"""doc"""\n'
    test_path.write_text(stamp_unvalidated(body) if stamped else body, encoding="utf-8")

    sync_stamp(test_path, report)

    assert is_unvalidated(test_path.read_text(encoding="utf-8")) is not kept


def test_sync_stamp_restamps_a_kept_test_that_later_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    test_path = tmp_path / "test_security_x.py"
    test_path.write_text(stamp_unvalidated('"""doc"""\n'), encoding="utf-8")

    sync_stamp(test_path, _report(kept=True))
    assert "Removed the UNVALIDATED header" in capsys.readouterr().out
    sync_stamp(test_path, _report(kept=False))

    assert is_unvalidated(test_path.read_text(encoding="utf-8"))
    out = capsys.readouterr().out
    assert "Added the UNVALIDATED header" in out
    assert "REJECTED" in out


def test_sync_stamp_says_nothing_when_nothing_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    test_path = tmp_path / "test_security_x.py"
    test_path.write_text('"""doc"""\n', encoding="utf-8")
    before = test_path.stat().st_mtime_ns

    sync_stamp(test_path, _report(kept=True))

    assert test_path.read_text(encoding="utf-8") == '"""doc"""\n'
    assert test_path.stat().st_mtime_ns == before
    assert "UNVALIDATED" not in capsys.readouterr().out


def test_strip_of_an_edited_header_removes_only_the_marker_and_known_lines() -> None:
    known = stamp_unvalidated("").splitlines()[1]
    edited = f"{UNVALIDATED_MARKER}\n{known}\n# reworded by hand\n'''doc'''\n"
    assert strip_unvalidated(edited) == "# reworded by hand\n'''doc'''\n"


def test_sync_stamp_flags_an_edited_header(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    test_path = tmp_path / "test_security_x.py"
    test_path.write_text(f"{UNVALIDATED_MARKER}\n# reworded\n'''doc'''\n", encoding="utf-8")

    sync_stamp(test_path, _report(kept=True))

    assert test_path.read_text(encoding="utf-8") == "# reworded\n'''doc'''\n"
    assert "header had been edited" in capsys.readouterr().out


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_user_comments_round_trip_byte_identical_through_reject_then_keep(
    tmp_path: Path, newline: str
) -> None:
    """A licence header right at the top survives being stamped and unstamped."""
    original = newline.join(
        ["# Copyright ACME", "# SPDX-License-Identifier: Apache-2.0", '"""doc"""', ""]
    ).encode("utf-8")
    test_path = tmp_path / "test_security_x.py"
    test_path.write_bytes(original)

    sync_stamp(test_path, _report(kept=False))
    stamped = test_path.read_bytes()
    assert stamped.startswith(UNVALIDATED_MARKER.encode())
    sync_stamp(test_path, _report(kept=True))

    assert test_path.read_bytes() == original


def test_sync_stamp_keeps_an_lf_file_lf(tmp_path: Path) -> None:
    test_path = tmp_path / "test_security_x.py"
    test_path.write_bytes(b'"""doc"""\nX = 1\n')

    sync_stamp(test_path, _report(kept=False))

    assert b"\r" not in test_path.read_bytes()


# --- the target the KEPT report was proved against ------------------------------

_TARGET_YAML = "family: myapp\ncommand: python\nargs: [-m, my_server]\nweakness_classes: [W2]\n"


def _kept_custom_dir(tmp_path: Path) -> Path:
    """A custom-target folder as `generate` and then a KEPT `validate` leave it."""
    scan = tmp_path / "scans" / "s1"
    scan.mkdir(parents=True)
    exploit = _exploit().model_copy(update={"target_id": "mcp:myapp"})
    (scan / "exploit_a.json").write_text(exploit.model_dump_json(), encoding="utf-8")
    (scan / "target.yaml").write_text(_TARGET_YAML, encoding="utf-8")
    src = tmp_path / "validated"
    result = runner.invoke(app, ["generate", str(scan), "--out", str(src)])
    assert result.exit_code == EXIT_SUCCESS, result.output
    assert (src / "target.yaml").is_file()
    (test_file,) = src.glob("test_security_*.py")
    _write_report(src, _report(kept=True, test_filename=test_file.name))
    return src


def _generate(src: Path, out_dir: Path, *extra: str) -> str:
    result = runner.invoke(app, ["generate", str(src), "--out", str(out_dir), *extra])
    assert result.exit_code == EXIT_SUCCESS, result.output
    return _emitted_source(out_dir)


def test_kept_custom_target_regenerates_unstamped(tmp_path: Path) -> None:
    src = _kept_custom_dir(tmp_path)
    assert not is_unvalidated(_generate(src, tmp_path / "gen"))


def test_kept_custom_target_with_the_same_target_file_regenerates_unstamped(
    tmp_path: Path,
) -> None:
    src = _kept_custom_dir(tmp_path)
    same = tmp_path / "same.yaml"
    same.write_text(_TARGET_YAML, encoding="utf-8")
    assert not is_unvalidated(_generate(src, tmp_path / "gen", "--target-file", str(same)))


def test_kept_custom_target_with_another_target_file_stamps(tmp_path: Path) -> None:
    """The source renders identically, but the test would run against an unproven app."""
    src = _kept_custom_dir(tmp_path)
    other = tmp_path / "other.yaml"
    other.write_text(_TARGET_YAML.replace("myapp", "otherapp"), encoding="utf-8")
    assert is_unvalidated(_generate(src, tmp_path / "gen", "--target-file", str(other)))


def test_kept_custom_target_whose_target_yaml_was_swapped_stamps(tmp_path: Path) -> None:
    src = _kept_custom_dir(tmp_path)
    target = src / "target.yaml"
    target.write_text(_TARGET_YAML.replace("myapp", "otherapp"), encoding="utf-8")
    report_mtime = (src / "validation_report.json").stat().st_mtime
    os.utime(target, (report_mtime + 60, report_mtime + 60))
    assert is_unvalidated(_generate(src, tmp_path / "gen"))


# --- gate builds its tests through its own path --------------------------------


def test_gate_generate_fn_never_stamps() -> None:
    """gate writes, then validates, then commits only what was kept: its tests
    never pass through the stamp."""
    from mylonite.gate.wiring import generate_fn

    generated = generate_fn(_exploit())
    assert not is_unvalidated(generated.source)
