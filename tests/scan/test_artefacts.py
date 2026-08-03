"""Artefact writer + summary renderer tests."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
    ScanAttempt,
    ScanReport,
)
from mylonite.scan.artefacts import render_summary, write_artefacts
from mylonite.scan.engine import ScanResult

_SCHEMA_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "mylonite" / "schemas"


def _exploit(pattern_id: str = "test-pattern") -> ExploitRecord:
    return ExploitRecord(
        target_id="reference:vulnerable",
        pattern_id=pattern_id,
        payload=Payload(pattern_id=pattern_id, channel="tool-result", body="x"),
        response=AdapterResponse(payload_pattern_id=pattern_id, raw_response="ok"),
        success_reason="caught it",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )


def _result(*, findings: int = 1, aborted: str | None = None) -> ScanResult:
    attempts: list[ScanAttempt] = [
        ScanAttempt(
            seed_id=f"test-pattern-{i}",
            pattern_id=f"test-pattern-{i}",
            outcome="finding" if i < findings else "no_finding",
            verdict_mechanism="predicate" if i < findings else "llm",
            verdict_reason="caught" if i < findings else "rejected",
            error_detail=None,
        )
        for i in range(max(findings, 1))
    ]
    report = ScanReport(
        target_id="reference:vulnerable",
        attack_modules=["prompt-injection-family"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.5,
        attempts=attempts,
        findings_count=findings,
        aborted=aborted,
        mylonite_version="0.2.0",
    )
    exploits = [_exploit(f"test-pattern-{i}") for i in range(findings)]
    return ScanResult(report=report, exploits=exploits)


# --- write_artefacts --------------------------------------------------------


def test_write_artefacts_creates_timestamped_subdir(tmp_path: Path) -> None:
    result = _result(findings=1)
    scan_dir = write_artefacts(result, tmp_path)
    assert scan_dir.exists()
    assert scan_dir.parent == tmp_path


def test_write_artefacts_emits_report_and_one_exploit_per_finding(tmp_path: Path) -> None:
    result = _result(findings=2)
    scan_dir = write_artefacts(result, tmp_path)
    assert (scan_dir / "scan_report.json").exists()
    exploit_files = sorted(scan_dir.glob("exploit_*.json"))
    assert len(exploit_files) == 2


# --- G6 schema validation --------------------------------------------------


def test_exploit_record_files_validate_against_schema(tmp_path: Path) -> None:
    """The Phase 0 exploit_record.schema.json must validate every written exploit."""
    schema = json.loads((_SCHEMA_ROOT / "exploit_record.schema.json").read_text())
    scan_dir = write_artefacts(_result(findings=1), tmp_path)
    payload = json.loads(next(scan_dir.glob("exploit_*.json")).read_text())
    jsonschema.validate(payload, schema)


def test_scan_report_validates_against_schema(tmp_path: Path) -> None:
    """The new scan_report.schema.json must validate the written report (G6)."""
    schema = json.loads((_SCHEMA_ROOT / "scan_report.schema.json").read_text())
    scan_dir = write_artefacts(_result(findings=1), tmp_path)
    payload = json.loads((scan_dir / "scan_report.json").read_text())
    jsonschema.validate(payload, schema)


def test_write_artefacts_never_overwrites_existing_dir(tmp_path: Path) -> None:
    result = _result()
    first = write_artefacts(result, tmp_path)
    second = write_artefacts(result, tmp_path)
    assert first != second
    assert first.exists() and second.exists()


# --- render_summary --------------------------------------------------------


def test_render_summary_includes_finding_marker_and_counts() -> None:
    summary = render_summary(_result(findings=1))
    assert "FOUND" in summary
    assert "1 findings" in summary
    assert "anthropic" in summary


def test_render_summary_shows_aborted_when_set() -> None:
    summary = render_summary(_result(findings=0, aborted="budget_exceeded"))
    assert "budget_exceeded" in summary
    assert "aborted" in summary.lower()


def test_render_summary_surfaces_inconclusive_rate() -> None:
    """Issue #8: a 100%-fallback scan must not read as clean."""
    report = ScanReport(
        target_id="reference:vulnerable",
        attack_modules=["prompt-injection-family"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=[
            ScanAttempt(
                seed_id="s",
                pattern_id="s",
                outcome="no_finding",
                verdict_mechanism="llm",
                verdict_reason="LLM-judge inconclusive — LLM output not parseable as JSON",
            )
        ],
        findings_count=0,
        inconclusive_attempts=1,
        fallback_breakdown={"judge_unparseable_output": 1},
        mylonite_version="0.2.0",
    )
    summary = render_summary(ScanResult(report=report, exploits=[]))
    assert "inconclusive" in summary
    assert "1/1" in summary


def test_render_summary_ascii_safe_is_pure_ascii() -> None:
    """Issue #9: ascii_safe output must encode to ASCII so a non-UTF-8 console can't crash."""
    summary = render_summary(_result(findings=1), ascii_safe=True)
    summary.encode("ascii")  # must not raise
    assert "FOUND" in summary
    assert "✗" not in summary  # no ✗ glyph leaked


def test_render_summary_utf8_keeps_glyphs() -> None:
    summary = render_summary(_result(findings=1), ascii_safe=False)
    assert "✗ FOUND" in summary


def test_render_summary_survives_rich_markup_in_a_verdict_reason() -> None:
    """DCR-0004: a verdict_reason quoting target output like '[/bold]' raised
    MarkupError and crashed the CLI AFTER a successful scan."""
    report = ScanReport(
        target_id="reference:vulnerable",
        attack_modules=["prompt-injection-family"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=[
            ScanAttempt(
                seed_id="s[/bold]",
                pattern_id="s",
                outcome="no_finding",
                verdict_mechanism="llm",
                verdict_reason="the response echoed [/bold] verbatim",
            )
        ],
        findings_count=0,
        mylonite_version="0.2.0",
    )
    summary = render_summary(ScanResult(report=report, exploits=[]))
    assert "verbatim" in summary


@pytest.mark.parametrize(
    "pattern_id, expected_filename_part",
    [
        ("simple-id", "simple-id"),
        ("with/slash", "with-slash"),
        ("weird!chars@", "weird-chars"),
    ],
)
def test_sanitised_filename_for_exploit(
    tmp_path: Path, pattern_id: str, expected_filename_part: str
) -> None:
    record = ExploitRecord(
        target_id="t",
        pattern_id=pattern_id,
        payload=Payload(pattern_id=pattern_id, channel="tool-result", body="b"),
        response=AdapterResponse(payload_pattern_id=pattern_id, raw_response="r"),
        success_reason="reason",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )
    report = ScanReport(
        target_id="t",
        attack_modules=[],
        provider="p",
        model="m",
        elapsed_seconds=0.0,
        attempts=[
            ScanAttempt(
                seed_id=pattern_id,
                pattern_id=pattern_id,
                outcome="finding",
                verdict_mechanism="predicate",
                verdict_reason="r",
            )
        ],
        findings_count=1,
        mylonite_version="0.2.0",
    )
    scan_dir = write_artefacts(ScanResult(report=report, exploits=[record]), tmp_path)
    files = [f.name for f in scan_dir.glob("exploit_*.json")]
    assert any(expected_filename_part in f for f in files), files
