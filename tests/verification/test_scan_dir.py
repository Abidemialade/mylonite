"""Tests for verification._scan_dir — the shared scan-directory loader.

Hermetic: builds real scan artefacts offline via
``mylonite.scan.artefacts.write_artefacts`` (no LLM, no network), the same
writer a live ``mylonite scan`` uses, so these tests exercise the real
on-disk shape rather than a hand-rolled approximation of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification._scan_dir import (
    EXERCISED_OUTCOMES,
    FINDING,
    NO_FINDING,
    ScanDirIntegrityError,
    load_scan_dir,
)

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


def test_exercised_outcomes_are_finding_and_no_finding() -> None:
    assert {FINDING, NO_FINDING} == EXERCISED_OUTCOMES


def _exploit(pattern_id: str, weakness: str) -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:dvmcp-c4",
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id, channel="tool-result", body="x", metadata={"weakness": weakness}
        ),
        response=AdapterResponse(payload_pattern_id=pattern_id, raw_response="ok"),
        success_reason="tool description mutated after approval",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )


def _write_real_scan_dir(
    tmp_path: Path, *, findings: int, extra_attempts: list[ScanAttempt] | None = None
) -> Path:
    """A real `write_artefacts` output: scan_report.json + one exploit per finding."""
    attempts = [
        ScanAttempt(
            seed_id=f"tool-description-mutate-{i}",
            pattern_id=f"tool-description-mutate-{i}",
            outcome="finding" if i < findings else "no_finding",
            verdict_mechanism="predicate",
            verdict_reason="caught" if i < findings else "rejected",
        )
        for i in range(max(findings, 1))
    ] + (extra_attempts or [])
    report = ScanReport(
        target_id="mcp:dvmcp-c4",
        attack_modules=["prompt-injection-family"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.5,
        attempts=attempts,
        findings_count=findings,
        mylonite_version="0.10.4",
    )
    exploits = [_exploit(f"tool-description-mutate-{i}", "W1") for i in range(findings)]
    result = ScanResult(report=report, exploits=exploits)
    return write_artefacts(result, tmp_path)


def test_load_scan_dir_reads_exercised_and_weakness_classes_from_real_artefacts(
    tmp_path: Path,
) -> None:
    scan_dir = _write_real_scan_dir(tmp_path, findings=1)
    result = load_scan_dir(scan_dir)
    assert result.exercised is True
    assert result.weakness_classes == {"W1"}


def test_load_scan_dir_clean_run_is_exercised_with_no_weaknesses(tmp_path: Path) -> None:
    scan_dir = _write_real_scan_dir(tmp_path, findings=0)
    result = load_scan_dir(scan_dir)
    assert result.exercised is True
    assert result.weakness_classes == frozenset()


def test_load_scan_dir_all_skipped_is_not_exercised(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "scan_report.json").write_text(
        json.dumps(
            {
                "attempts": [
                    {"outcome": "skipped_planner_no_engagement"},
                    {"outcome": "not_applicable"},
                ],
                "findings_count": 0,
            }
        ),
        encoding="utf-8",
    )
    result = load_scan_dir(scan_dir)
    assert result.exercised is False
    assert result.weakness_classes == frozenset()


def test_load_scan_dir_raises_when_directory_has_no_scan_report(tmp_path: Path) -> None:
    empty_dir = tmp_path / "not-a-scan-dir"
    empty_dir.mkdir()
    with pytest.raises(ScanDirIntegrityError, match=r"no scan_report\.json"):
        load_scan_dir(empty_dir)


def test_load_scan_dir_raises_when_finding_attempt_has_no_exploit_file(tmp_path: Path) -> None:
    """A partial copy: the report says a finding fired, but the exploit file
    that would name its weakness class was never copied alongside it."""
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "scan_report.json").write_text(
        json.dumps(
            {
                "attempts": [{"outcome": "finding"}],
                "findings_count": 1,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScanDirIntegrityError, match=r"exploit_\*\.json"):
        load_scan_dir(scan_dir)
