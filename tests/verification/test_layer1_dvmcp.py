"""Layer 1 (DVMCP) scaffolding tests — hermetic, no clone/network/scan.

Guards the catalogue scope mapping, port extraction, target-file construction,
bundle parsing, recall math, and the unlicensed-opt-in gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification.layer1_runnable import dvmcp
from verification.layer1_runnable import run as layer1_run

from mylonite.corpus import confusion_matrix
from verification import fetch


def test_catalogue_scope_and_mapping() -> None:
    in_scope = dvmcp.in_scope_challenges()
    # 1-7 and 10 are in scope; 8 and 9 (RCE / command injection) are not.
    assert {c.number for c in in_scope} == {1, 2, 3, 4, 5, 6, 7, 10}
    assert not dvmcp.CATALOGUE_BY_NUMBER[8].in_scope
    assert not dvmcp.CATALOGUE_BY_NUMBER[9].in_scope
    assert dvmcp.CATALOGUE_BY_NUMBER[2].weakness_classes == ("W1",)  # tool poisoning
    assert dvmcp.CATALOGUE_BY_NUMBER[6].weakness_classes == ("W2",)  # indirect injection
    # out-of-scope challenges map to no weakness class
    assert dvmcp.CATALOGUE_BY_NUMBER[8].weakness_classes == ()


def test_extract_port(tmp_path: Path) -> None:
    sp = tmp_path / "server.py"
    sp.write_text('uvicorn.run("server:mcp", host="0.0.0.0", port=8002)\n', encoding="utf-8")
    assert dvmcp.extract_port(sp) == 8002

    sp2 = tmp_path / "noport.py"
    sp2.write_text("x = 1\n", encoding="utf-8")
    assert dvmcp.extract_port(sp2, default=8005) == 8005
    with pytest.raises(ValueError, match="no uvicorn port"):
        dvmcp.extract_port(sp2)


def test_build_target_file() -> None:
    ch = dvmcp.CATALOGUE_BY_NUMBER[6]
    tf = dvmcp.build_target_file(ch, port=8006)
    assert tf.transport == "sse"
    assert tf.url == "http://localhost:8006/sse"
    assert tf.family == "dvmcp-c6"
    assert tf.weakness_classes == ["W2"]

    with pytest.raises(ValueError, match="out of Mylonite's scope"):
        dvmcp.build_target_file(dvmcp.CATALOGUE_BY_NUMBER[8], port=8008)


def test_weaknesses_from_bundle(tmp_path: Path) -> None:
    bundle = {"findings": [{"weakness_class": "W2"}, {"weakness_class": "W3"}, {"x": 1}]}
    p = tmp_path / "dvmcp-c6.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    assert layer1_run.weaknesses_from_bundle(p) == {"W2", "W3"}


def test_recall_rows_and_matrix() -> None:
    # Mylonite flagged challenge 2 (W1) and challenge 6 (W2); missed the rest.
    found = {2: {"W1"}, 6: {"W2", "W4"}}
    rows = layer1_run.recall_rows(found)
    assert len(rows) == 8  # in-scope count
    matrix = confusion_matrix(rows)
    assert matrix.tp == 2
    assert matrix.fn == 6
    assert matrix.fp == 0
    assert matrix.recall == pytest.approx(0.25)
    # every in-scope challenge is a positive (vulnerable target)
    assert all(r.expected_exploited for r in rows)


def test_score_reports_reads_directory(tmp_path: Path) -> None:
    (tmp_path / "dvmcp-c2.json").write_text(
        json.dumps({"findings": [{"weakness_class": "W1"}]}), encoding="utf-8"
    )
    _rows, matrix, report = layer1_run.score_reports(tmp_path)
    assert report["layer"] == "layer1-recall"
    assert matrix.tp == 1  # only challenge 2 scanned + found
    assert report["found"] == 1


# --- #136: untested is not missed ------------------------------------------


def test_is_exercised_reads_attempt_outcomes(tmp_path: Path) -> None:
    exercised = tmp_path / "exercised.json"
    exercised.write_text(json.dumps({"attempts": [{"outcome": "no_finding"}]}), encoding="utf-8")
    assert layer1_run.is_exercised(exercised) is True

    all_skipped = tmp_path / "skipped.json"
    all_skipped.write_text(
        json.dumps(
            {
                "attempts": [
                    {"outcome": "skipped_planner_no_engagement"},
                    {"outcome": "skipped_payload_not_delivered"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert layer1_run.is_exercised(all_skipped) is False

    # legacy finding-only bundle (no "attempts" key at all): a real finding
    # cannot exist without an exercised attempt, so it still counts.
    legacy_with_finding = tmp_path / "legacy_finding.json"
    legacy_with_finding.write_text(
        json.dumps({"findings": [{"weakness_class": "W1"}]}), encoding="utf-8"
    )
    assert layer1_run.is_exercised(legacy_with_finding) is True

    # legacy bundle with nothing in it at all: unresolvable -> not exercised
    # (fail toward "don't know", never toward "tested and clean").
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert layer1_run.is_exercised(empty) is False


def test_score_reports_marks_missing_report_as_untested_not_missed(tmp_path: Path) -> None:
    # No report at all for any in-scope challenge.
    _rows, matrix, report = layer1_run.score_reports(tmp_path)
    assert report["in_scope_challenges"] == 8
    assert report["exercised_challenges"] == 0
    assert report["untested_challenges"] == 8
    assert report["found"] == 0
    # Nothing was exercised, so "missed" (exercised-but-not-found) is 0, not 8.
    assert report["missed"] == 0
    assert matrix.tp == 0
    assert matrix.fn == 0
    # Recall is undefined with zero exercised challenges, not a spurious 1.0/0.0.
    assert report["recall"] is None
    for row in report["per_challenge"]:
        assert row["untested"] is True
        assert row["found"] is False


def test_score_reports_marks_all_skipped_report_as_untested_not_missed(tmp_path: Path) -> None:
    # Challenge 3's report exists but every attempt was skipped -- exercised
    # nothing. This must NOT count as a miss.
    (tmp_path / "dvmcp-c3.json").write_text(
        json.dumps(
            {
                "attempts": [
                    {"outcome": "skipped_planner_no_engagement"},
                    {"outcome": "not_applicable"},
                ],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    # Challenge 2 is genuinely exercised and clean (no_finding).
    (tmp_path / "dvmcp-c2.json").write_text(
        json.dumps({"attempts": [{"outcome": "no_finding"}], "findings": []}),
        encoding="utf-8",
    )
    # Challenge 4 is genuinely exercised and flags its expected weakness.
    (tmp_path / "dvmcp-c4.json").write_text(
        json.dumps(
            {
                "attempts": [{"outcome": "finding"}],
                "findings": [{"weakness_class": "W1"}],
            }
        ),
        encoding="utf-8",
    )
    _rows, matrix, report = layer1_run.score_reports(tmp_path)

    assert report["in_scope_challenges"] == 8
    assert report["exercised_challenges"] == 2  # c2, c4 -- NOT c3
    assert report["untested_challenges"] == 6  # c1, c3, c5, c6, c7, c10
    assert report["found"] == 1  # c4
    assert report["missed"] == 1  # c2 (exercised, not found)
    assert report["recall"] == pytest.approx(0.5)  # 1 found / 2 exercised
    assert matrix.tp == 1
    assert matrix.fn == 1

    by_cid = {row["challenge"]: row for row in report["per_challenge"]}
    assert by_cid["challenge3"]["untested"] is True
    assert by_cid["challenge3"]["found"] is False
    assert by_cid["challenge2"]["untested"] is False
    assert by_cid["challenge2"]["found"] is False
    assert by_cid["challenge4"]["untested"] is False
    assert by_cid["challenge4"]["found"] is True
    # a never-reported challenge is untested too
    assert by_cid["challenge1"]["untested"] is True


# --- #136 follow-up: `found` from a real scan directory, not a bare report --


def _write_real_scan_dir(tmp_path: Path, *, findings: int, weakness: str) -> Path:
    """A real `write_artefacts` output for one challenge: scan_report.json +
    one exploit per finding, stamped with `weakness` the way a real attack
    module does (`payload.metadata["weakness"] = seed.weakness`)."""
    from mylonite.contracts._types import (
        AdapterResponse,
        ComplianceTags,
        ExploitRecord,
        Payload,
        ScanAttempt,
        ScanReport,
    )
    from mylonite.scan.artefacts import write_artefacts
    from mylonite.scan.engine import ScanResult

    attempts = [
        ScanAttempt(
            seed_id=f"seed-{i}",
            pattern_id=f"seed-{i}",
            outcome="finding" if i < findings else "no_finding",
            verdict_mechanism="predicate",
            verdict_reason="caught" if i < findings else "rejected",
        )
        for i in range(max(findings, 1))
    ]
    report = ScanReport(
        target_id="mcp:dvmcp-c4",
        attack_modules=["prompt-injection-family"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=attempts,
        findings_count=findings,
        mylonite_version="0.10.4",
    )
    exploits = [
        ExploitRecord(
            target_id="mcp:dvmcp-c4",
            pattern_id=f"seed-{i}",
            payload=Payload(
                pattern_id=f"seed-{i}",
                channel="tool-result",
                body="x",
                metadata={"weakness": weakness},
            ),
            response=AdapterResponse(payload_pattern_id=f"seed-{i}", raw_response="ok"),
            success_reason="tool description mutated after approval",
            compliance=ComplianceTags(owasp_llm=["LLM01"]),
        )
        for i in range(findings)
    ]
    return write_artefacts(ScanResult(report=report, exploits=exploits), tmp_path)


def test_score_reports_resolves_found_from_a_real_scan_directory(tmp_path: Path) -> None:
    """Challenge 4 (W1) reported as the exact directory `mylonite scan
    --output-dir` writes, copied straight in under the family name -- the
    workflow `verification/runner.py` now tells an operator to use."""
    scratch = tmp_path / "scratch"
    scan_dir = _write_real_scan_dir(scratch, findings=1, weakness="W1")
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    import shutil

    shutil.copytree(scan_dir, reports_dir / "dvmcp-c4")

    _rows, matrix, report = layer1_run.score_reports(reports_dir)
    assert report["exercised_challenges"] == 1
    assert report["found"] == 1
    assert matrix.tp == 1
    by_cid = {row["challenge"]: row for row in report["per_challenge"]}
    assert by_cid["challenge4"]["found"] is True
    assert by_cid["challenge4"]["untested"] is False


def test_score_reports_errors_on_a_bare_scan_report_json_with_no_exploit_files(
    tmp_path: Path,
) -> None:
    """The exact historical mistake (#136 follow-up): an operator copies only
    `scan_report.json` -- which has no per-attempt weakness class -- instead
    of the whole scan directory. That must be a loud, named error, never a
    silent found=0."""
    from verification._scan_dir import ScanDirIntegrityError

    (tmp_path / "dvmcp-c4.json").write_text(
        json.dumps(
            {
                "target_id": "mcp:dvmcp-c4",
                "attack_modules": [],
                "provider": "anthropic",
                "model": "stub",
                "elapsed_seconds": 1.0,
                "attempts": [{"seed_id": "s", "pattern_id": "s", "outcome": "finding"}],
                "findings_count": 1,
                "mylonite_version": "0.10.4",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScanDirIntegrityError, match=r"exploit_\*\.json"):
        layer1_run.score_reports(tmp_path)


def test_fetch_dvmcp_requires_optin() -> None:
    # No network: the gate raises before any clone.
    with pytest.raises(RuntimeError, match="no LICENSE"):
        fetch.fetch_dvmcp()
    assert len(fetch.DVMCP_COMMIT) == 40
