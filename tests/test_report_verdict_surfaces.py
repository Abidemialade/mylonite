"""SARIF level and the bundle's proof claim follow the verdict, on recorded runs.

Each case drives ``mylonite report --sarif --json`` on a directory a real run
wrote:

- ``examples/reference_validation/``: a validation of the reference twins that
  was kept with a passing build and differential leg (KEPT). Its report carries
  a top-level ``provenance`` key the recording script adds, which
  ``ValidationReport`` does not accept, so the test copies the report and
  exploit without that key.
- ``tests/fixtures/report_verdicts/rejected_not_reproduced/``: a validation of
  a custom target (the public MCP "everything" server) on a hosted model, where
  the attack reproduced 0/3 and the run was rejected. Copied unchanged from the
  run's output directory.
- ``tests/verification/fixtures/dvmcp-c4/``: a scan with one finding that was
  never validated.

GitHub code scanning shows ``level`` and ``security-severity``; a finding
nothing proved must not land there as a High error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app

ROOT = Path(__file__).resolve().parents[1]
KEPT_DIR = ROOT / "examples" / "reference_validation"
REJECTED_DIR = ROOT / "tests" / "fixtures" / "report_verdicts" / "rejected_not_reproduced"
SCAN_DIR = ROOT / "tests" / "verification" / "fixtures" / "dvmcp-c4"

runner = CliRunner()


def _export(artefact_dir: Path, tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    sarif = tmp_path / "out.sarif"
    bundle = tmp_path / "finding.json"
    result = runner.invoke(
        app, ["report", str(artefact_dir), "--sarif", str(sarif), "--json", str(bundle)]
    )
    assert result.exit_code == 0, result.output
    sarif_doc = json.loads(sarif.read_text(encoding="utf-8"))
    bundle_doc = json.loads(bundle.read_text(encoding="utf-8"))
    results = sarif_doc["runs"][0]["results"]
    findings = bundle_doc["findings"]
    assert len(results) == 1 and len(findings) == 1
    return results[0], findings[0]


def _kept_dir(tmp_path: Path) -> Path:
    """The recorded KEPT validation, minus the recorder's ``provenance`` key."""
    out = tmp_path / "kept"
    out.mkdir()
    report = json.loads((KEPT_DIR / "validation_report.json").read_text(encoding="utf-8"))
    report.pop("provenance", None)
    (out / "validation_report.json").write_text(json.dumps(report), encoding="utf-8")
    for exploit in KEPT_DIR.glob("exploit_*.json"):
        (out / exploit.name).write_bytes(exploit.read_bytes())
    return out


def test_recorded_kept_validation_is_an_error_with_severity_and_claim(tmp_path: Path) -> None:
    from mylonite._twin_fidelity import PROOF_CLAIM_BOUNDARY, PROOF_CLAIM_SERVER

    result, finding = _export(_kept_dir(tmp_path), tmp_path)
    assert result["level"] == "error"
    assert result["properties"]["verdict"] == "KEPT"
    assert "security-severity" in result["properties"]
    claims = (PROOF_CLAIM_SERVER, PROOF_CLAIM_BOUNDARY)
    assert any(c in result["message"]["text"] for c in claims)
    assert finding["proof"]["verdict"] == "KEPT"
    assert finding["proof"]["claim"] in claims
    assert finding["proof"]["status"] == "kept"


def test_recorded_rejected_validation_is_a_note_with_no_claim(tmp_path: Path) -> None:
    from mylonite._twin_fidelity import PROOF_CLAIM_BOUNDARY, PROOF_CLAIM_SERVER

    result, finding = _export(REJECTED_DIR, tmp_path)
    assert result["level"] == "note"
    assert result["properties"]["verdict"] == "REJECTED"
    assert "security-severity" not in result["properties"]
    text = result["message"]["text"]
    assert PROOF_CLAIM_SERVER not in text and PROOF_CLAIM_BOUNDARY not in text
    assert "not reproduced on this model" in text
    assert finding["proof"]["verdict"] == "REJECTED"
    assert finding["proof"]["claim"] is None
    assert finding["proof"]["status"] == "not reproduced on this model"
    # The counts still say what was shown.
    assert finding["proof"]["vuln_fired"] == 0


def test_recorded_scan_finding_is_a_warning_marked_unvalidated(tmp_path: Path) -> None:
    result, finding = _export(SCAN_DIR, tmp_path)
    assert result["level"] == "warning"
    assert result["properties"]["verdict"] == "UNVALIDATED"
    assert "security-severity" not in result["properties"]
    assert "not validated" in result["message"]["text"].lower()
    assert finding["proof"] is None


@pytest.mark.parametrize("artefact_dir", [REJECTED_DIR, SCAN_DIR])
def test_nothing_unproven_reaches_code_scanning_as_an_error(
    artefact_dir: Path, tmp_path: Path
) -> None:
    result, _ = _export(artefact_dir, tmp_path)
    assert result["level"] != "error"
