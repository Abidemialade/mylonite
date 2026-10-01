"""The ``verdicts.json`` sidecar and the per-class block in the scan summary.

Both appear only when an attempt was decided by the trace rule (or the target
carries a calibration summary), so reference, REST and replayed scans write and
print exactly what they did before.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mylonite.contracts import ScanAttempt, ScanReport
from mylonite.contracts._types import (
    AdapterResponse,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.scan.artefacts import (
    read_verdicts_calibration,
    render_summary,
    write_artefacts,
)
from mylonite.scan.class_verdict import CalibrationSummary
from mylonite.scan.engine import ScanConfig, ScanEngine, ScanResult

_W2 = "indirect-injection-note-body-direct"
_W4 = "excessive-agency-send-email-direct-unconfirmed"
_W4_B = "excessive-agency-send-email-via-note-injection"


def _attempt(seed_id: str, outcome: str, **evidence: str) -> ScanAttempt:
    return ScanAttempt(
        seed_id=seed_id,
        pattern_id=seed_id,
        outcome=outcome,  # type: ignore[arg-type]
        verdict_mechanism="predicate" if outcome in ("finding", "no_finding") else None,
        verdict_reason="r",
        error_detail=None,
        judge_evidence=dict(evidence),
    )


def _result(*attempts: ScanAttempt, calibration: CalibrationSummary | None = None) -> ScanResult:
    report = ScanReport(
        target_id="mcp:custom",
        attack_modules=["m"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=list(attempts),
        findings_count=sum(1 for a in attempts if a.outcome == "finding"),
        mylonite_version="0.10.5",
    )
    return ScanResult(report=report, exploits=[], calibration=calibration)


def _traced() -> ScanResult:
    return _result(
        _attempt(_W4, "finding", trace_outcome="dispatched-ok", proof_level="dispatched"),
        _attempt(
            _W2,
            "undecided",
            trace_outcome="dispatched-ok",
            calibrated="false",
            fallback_cause="MYL-INC-001",
        ),
        calibration=CalibrationSummary(
            status="failed",
            reason_code="MYL-INC-005",
            seed_status="failed",
            seed_reason_code="MYL-INC-006",
        ),
    )


# --- verdicts.json ---------------------------------------------------------------


def test_verdicts_json_records_classes_codes_proof_levels_and_the_certificate(
    tmp_path: Path,
) -> None:
    scan_dir = write_artefacts(_traced(), tmp_path)
    data = json.loads((scan_dir / "verdicts.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.1"
    assert data["target_id"] == "mcp:custom"
    classes = {c["weakness"]: c for c in data["classes"]}
    assert classes["W4"]["status"] == "FINDING"
    assert classes["W4"]["proof_levels"] == ["dispatched"]
    assert classes["W2"]["status"] == "NOT TESTED"
    assert classes["W2"]["codes"] == ["MYL-INC-001", "MYL-INC-005", "MYL-INC-006"]
    assert data["codes"] == {"MYL-INC-001": 1, "MYL-INC-005": 1, "MYL-INC-006": 1}
    assert data["proof_levels"] == {"dispatched": 1}
    assert data["evidence_tiers"] == {"state": 0, "trace": 1, "judge-only": 0}
    assert classes["W4"]["evidence_tiers"] == {"state": 0, "trace": 1, "judge-only": 0}
    assert data["counts"] == {"finding": 1, "resisted": 0, "server_reported": 0, "not_tested": 1}
    assert data["calibration"]["status"] == "failed"
    assert data["calibration"]["reason_code"] == "MYL-INC-005"


def test_no_verdicts_json_without_a_trace_or_a_calibration(tmp_path: Path) -> None:
    scan_dir = write_artefacts(_result(_attempt(_W4, "no_finding")), tmp_path)
    assert not (scan_dir / "verdicts.json").exists()


def test_the_calibration_reads_back_from_a_saved_directory(tmp_path: Path) -> None:
    result = _traced()
    scan_dir = write_artefacts(result, tmp_path)
    assert read_verdicts_calibration(scan_dir) == result.calibration


def test_reading_back_degrades_to_none(tmp_path: Path) -> None:
    assert read_verdicts_calibration(tmp_path) is None
    (tmp_path / "verdicts.json").write_text("{not json", encoding="utf-8")
    assert read_verdicts_calibration(tmp_path) is None
    (tmp_path / "verdicts.json").write_text('{"calibration": null}', encoding="utf-8")
    assert read_verdicts_calibration(tmp_path) is None


def test_a_saved_directory_renders_the_same_class_block(tmp_path: Path) -> None:
    result = _traced()
    scan_dir = write_artefacts(result, tmp_path)
    reloaded = ScanResult(
        report=ScanReport.model_validate_json(
            (scan_dir / "scan_report.json").read_text(encoding="utf-8")
        ),
        exploits=[],
        calibration=read_verdicts_calibration(scan_dir),
    )
    assert _class_block(render_summary(reloaded, ascii_safe=True)) == _class_block(
        render_summary(result, ascii_safe=True)
    )


# --- the summary block -------------------------------------------------------------


def _class_block(summary: str) -> list[str]:
    lines = summary.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("classes:"))
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.startswith("  "):
            break
        block.append(line)
    return block


def test_the_summary_prints_one_line_per_class_with_its_codes() -> None:
    block = _class_block(render_summary(_traced(), ascii_safe=True))
    assert block[0].startswith("classes:")
    w2 = next(line for line in block if line.strip().startswith("W2"))
    w4 = next(line for line in block if line.strip().startswith("W4"))
    assert "NOT TESTED" in w2
    assert "[MYL-INC-001, MYL-INC-005, MYL-INC-006]" in w2
    assert "FINDING" in w4
    assert "proof: dispatched" in w4


def test_the_summary_prints_the_calibration_status() -> None:
    summary = render_summary(_traced(), ascii_safe=True)
    line = next(x for x in summary.splitlines() if x.startswith("calibration:"))
    assert "failed" in line
    assert "MYL-INC-005" in line
    assert "MYL-INC-006" in line


def test_a_certified_calibration_names_its_tools() -> None:
    result = _result(
        _attempt(_W4, "no_finding", trace_outcome="not-called", negative_basis="trace"),
        calibration=CalibrationSummary(
            status="certified",
            reason_code=None,
            seed_status="not_declared",
            seed_reason_code=None,
            certified_tools=("send_email",),
        ),
    )
    summary = render_summary(result, ascii_safe=True)
    line = next(x for x in summary.splitlines() if x.startswith("calibration:"))
    assert "certified" in line and "send_email" in line
    assert "RESISTED" in "\n".join(_class_block(summary))


def test_a_server_reported_class_is_labelled() -> None:
    result = _result(
        _attempt(
            _W4,
            "no_finding",
            trace_outcome="dispatched-error",
            negative_basis="server-reported",
            reason_code="MYL-SRV-001",
        )
    )
    block = _class_block(render_summary(result, ascii_safe=True))
    w4 = next(line for line in block if line.strip().startswith("W4"))
    assert "RESISTED (server-reported)" in w4
    assert "[MYL-SRV-001]" in w4


def test_no_class_block_without_a_trace_outcome() -> None:
    summary = render_summary(
        _result(_attempt(_W4, "finding"), _attempt(_W4_B, "no_finding")), ascii_safe=True
    )
    assert "classes:" not in summary
    assert "calibration:" not in summary


# --- the engine carries the adapter's calibration -----------------------------------


class _Module:
    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="stub-pattern",
            name="stub",
            summary="test",
            target_kinds=["mcp"],
            compliance=ComplianceTags(owasp_llm=["LLM01"]),
        )

    def generate_payloads(self, target: TargetDescriptor) -> list[Payload]:
        del target
        return []


class _Adapter:
    def __init__(self, summary: CalibrationSummary | None) -> None:
        self._summary = summary

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="stub-target", kind="mcp", system_prompt="x", tools=[])

    async def invoke(self, payload: Payload) -> AdapterResponse:  # pragma: no cover
        raise AssertionError("no payloads")

    async def close(self) -> None:
        return None

    def calibration_summary(self) -> CalibrationSummary | None:
        return self._summary


class _PlainAdapter(_Adapter):
    calibration_summary = None  # type: ignore[assignment]


async def _run(adapter: Any) -> ScanResult:
    engine = ScanEngine(
        config=ScanConfig(
            target_id="custom:stub",
            provider="anthropic",
            model="stub-model",
            max_llm_calls=5,
            max_concurrent=1,
            output_dir=Path(".mylonite/scans"),
        ),
        adapter=adapter,
        attack_modules=[_Module()],
        customiser=object(),  # type: ignore[arg-type]
        judge=object(),  # type: ignore[arg-type]
    )
    return await engine.run()


@pytest.mark.asyncio
async def test_the_engine_carries_the_adapters_calibration() -> None:
    summary = CalibrationSummary(
        status="certified", reason_code=None, seed_status="passed", seed_reason_code=None
    )
    assert (await _run(_Adapter(summary))).calibration == summary


@pytest.mark.asyncio
async def test_an_adapter_without_calibration_leaves_it_none() -> None:
    assert (await _run(_PlainAdapter(None))).calibration is None


# --- mylonite report on a saved directory --------------------------------------------


def test_report_on_a_saved_directory_prints_the_same_class_block(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from mylonite.cli import app

    result = _traced()
    scan_dir = write_artefacts(result, tmp_path)
    out = CliRunner().invoke(app, ["report", str(scan_dir)]).output
    # The separator differs by console encoding, so compare the parts around it.
    assert "W2  NOT TESTED [MYL-INC-001, MYL-INC-005, MYL-INC-006] (1 not tested)" in out
    assert "W4  FINDING" in out and "proof: dispatched (1 finding)" in out
    assert "calibration: failed [MYL-INC-005, MYL-INC-006]; seed control: failed" in out
