"""Gate dirs name each finding by a short, stable id, and still say which pattern it is.

A folder per finding named after its full pattern id, plus the same slug again
in the test file name, pushed a committed gate dir past Windows' path limit.
The gate now names a finding ``<weakness>-<6 hex of sha256(pattern_id)>``
(e.g. ``w2-1a2b3c``), with ``test_<id>.py`` and ``exploit_<id>.json`` inside.
The full pattern id stays in the test's docstring, the exploit JSON, the
console summary and the PR body.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.gate.orchestrator import (
    ScanOutcomeBundle,
    _finding_id,
    _finding_ids,
    exploit_filename_for,
    gate_test_filename,
    run_gate,
)
from mylonite.plugins._reference.reference_pytest_generator import (
    GATE_ID_METADATA_KEY,
    ReferencePytestGenerator,
)
from mylonite.scan.coverage import Coverage, ScanOutcome


def _exploit(pattern_id: str, weakness: str | None = "W4") -> ExploitRecord:
    meta = {"weakness": weakness} if weakness else {}
    return ExploitRecord(
        target_id="reference:vulnerable",
        pattern_id=pattern_id,
        payload=Payload(pattern_id=pattern_id, channel="user-message", body="b", metadata=meta),
        response=AdapterResponse(
            payload_pattern_id=pattern_id, raw_response="r", tool_calls=[], metadata={}
        ),
        success_reason="r",
        compliance=ComplianceTags(owasp_asi=["ASI02"]),
    )


def test_a_finding_id_is_the_weakness_plus_a_stable_hash() -> None:
    pid = "excessive-agency-send-email-direct-unconfirmed"
    digest = hashlib.sha256(pid.encode("utf-8")).hexdigest()[:6]
    assert _finding_id(_exploit(pid)) == f"w4-{digest}"
    assert _finding_id(_exploit(pid)) == _finding_id(_exploit(pid))
    # No stamped weakness: the bundled catalogue still knows this pattern, so
    # the id does not change between a record that carries it and one that
    # does not.
    assert _finding_id(_exploit(pid, weakness=None)) == f"w4-{digest}"
    unknown = _exploit("not-a-catalogued-pattern", weakness=None).model_copy(
        update={"compliance": ComplianceTags()}
    )
    other = hashlib.sha256(b"not-a-catalogued-pattern").hexdigest()[:6]
    assert _finding_id(unknown) == f"f-{other}"


def test_colliding_ids_get_a_numbered_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    from mylonite.gate import orchestrator

    monkeypatch.setattr(orchestrator, "_finding_id", lambda _e: "w4-aaaaaa")
    ids = _finding_ids([_exploit("a"), _exploit("b"), _exploit("c")])
    assert ids == ["w4-aaaaaa", "w4-aaaaaa-2", "w4-aaaaaa-3"]


def test_file_names_follow_the_id() -> None:
    assert gate_test_filename("w4-1a2b3c") == "test_w4-1a2b3c.py"
    assert exploit_filename_for("test_w4-1a2b3c.py") == "exploit_w4-1a2b3c.json"


def test_the_bundled_generator_uses_the_gate_id_for_both_names() -> None:
    pid = "indirect-injection-note-body-direct"
    tagged = _exploit(pid)
    meta = {**tagged.payload.metadata, GATE_ID_METADATA_KEY: "w4-1a2b3c"}
    tagged = tagged.model_copy(
        update={"payload": tagged.payload.model_copy(update={"metadata": meta})}
    )
    generated = ReferencePytestGenerator().emit(tagged)
    assert generated.filename == "test_w4-1a2b3c.py"
    assert "'exploit_w4-1a2b3c.json'" in generated.source
    assert pid in generated.source.split('"""')[1]  # the module docstring names the pattern


def test_without_a_gate_id_the_generator_keeps_its_names() -> None:
    pid = "indirect-injection-note-body-direct"
    generated = ReferencePytestGenerator().emit(_exploit(pid))
    assert generated.filename == "test_security_indirect_injection_note_body_direct.py"
    assert f"'exploit_{pid}.json'" in generated.source


def _found(n: int) -> ScanOutcome:
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=n,
        not_tested=0,
        findings=n,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


def _kept(test: GeneratedTest, _dir: Path) -> ValidationReport:
    return ValidationReport(
        test_filename=test.filename,
        kept=True,
        outcomes=[ValidationOutcome(stage="build", passed=True, detail="ok")],
    )


def _run(tmp_path: Path, exploits: list[ExploitRecord], **kwargs: Any) -> tuple[Any, dict]:
    seen: dict[str, Any] = {}

    def _open_pr(**kw: Any) -> SimpleNamespace:
        seen.update(kw)
        return SimpleNamespace(opened=False, branch=None)

    result = run_gate(
        out_dir=tmp_path / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found(len(exploits)), exploits=exploits),
        generate_fn=kwargs.get("generate_fn", ReferencePytestGenerator().emit),
        validate_fn=_kept,
        open_pr_fn=_open_pr,
        open_pr=False,
    )
    return result, seen


def test_a_multi_finding_gate_writes_short_folders_and_maps_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a = _exploit("indirect-injection-note-body-direct", weakness="W2")
    b = _exploit("excessive-agency-send-email-direct-unconfirmed")
    result, seen = _run(tmp_path, [a, b])
    assert result.kept_count == 2
    out = tmp_path / "gate"
    printed = capsys.readouterr().out
    for exploit in (a, b):
        fid = _finding_id(exploit)
        folder = out / fid
        assert (folder / f"test_{fid}.py").is_file()
        record = json.loads((folder / f"exploit_{fid}.json").read_text(encoding="utf-8"))
        assert record["pattern_id"] == exploit.pattern_id
        # The emitted test loads the exploit file the gate wrote.
        assert f"'exploit_{fid}.json'" in (folder / f"test_{fid}.py").read_text(encoding="utf-8")
        assert f"{exploit.pattern_id} -> {folder / f'test_{fid}.py'}" in printed
        assert f"| `{exploit.pattern_id}` | `{fid}/test_{fid}.py` |" in seen["body"]
    # What the PR step is handed agrees with the disk.
    assert seen["kept_dirs"] == [out / _finding_id(a), out / _finding_id(b)] or seen[
        "kept_dirs"
    ] == [out / _finding_id(b), out / _finding_id(a)]
    for (_exploit_rec, report), kept_dir in zip(seen["findings"], seen["kept_dirs"], strict=True):
        assert (kept_dir / report.test_filename).is_file()
        assert (kept_dir / exploit_filename_for(report.test_filename)).is_file()


def test_a_third_party_generator_name_is_overridden(tmp_path: Path) -> None:
    def _other_generator(exploit: ExploitRecord) -> GeneratedTest:
        return GeneratedTest(
            framework="pytest",
            filename="test_some_very_long_third_party_name_for_this_finding.py",
            source="def test_x():\n    pass\n",
            exploit=exploit,
        )

    exploit = _exploit("indirect-injection-note-body-direct")
    result, seen = _run(tmp_path, [exploit], generate_fn=_other_generator)
    fid = _finding_id(exploit)
    assert result.kept is True
    assert (tmp_path / "gate" / f"test_{fid}.py").is_file()
    assert seen["findings"][0][1].test_filename == f"test_{fid}.py"


def test_a_rerun_over_an_old_style_gate_dir_does_not_crash(tmp_path: Path) -> None:
    out = tmp_path / "gate"
    old = out / "indirect_injection_note_body_direct"
    (old / "fixtures").mkdir(parents=True)
    (old / "test_security_indirect_injection_note_body_direct.py").write_text("", encoding="utf-8")
    (old / "fixtures" / ("a" * 64 + ".json")).write_text("{}", encoding="utf-8")
    a = _exploit("indirect-injection-note-body-direct", weakness="W2")
    b = _exploit("excessive-agency-send-email-direct-unconfirmed")
    result, _seen = _run(tmp_path, [a, b])
    assert result.kept_count == 2
    # The old folder is left as it was; cleaning it up is the operator's call.
    assert (old / "test_security_indirect_injection_note_body_direct.py").is_file()
    assert (out / _finding_id(a) / f"test_{_finding_id(a)}.py").is_file()


def test_a_test_that_loads_another_exploit_file_is_not_gated(tmp_path: Path) -> None:
    """A generator whose test loads an exploit file under some other name would
    commit a test that can never find its data, so the finding fails at
    generation instead."""

    def _mismatched(exploit: ExploitRecord) -> GeneratedTest:
        return GeneratedTest(
            framework="pytest",
            filename="test_x.py",
            source="EXPLOIT = 'exploit_some-other-name.json'\n",
            exploit=exploit,
        )

    exploit = _exploit("indirect-injection-note-body-direct")
    result, _seen = _run(tmp_path, [exploit], generate_fn=_mismatched)
    assert result.exit_code == 6
    assert not (tmp_path / "gate").exists()
