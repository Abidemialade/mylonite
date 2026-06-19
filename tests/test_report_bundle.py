"""R5: machine-readable JSON finding bundle (dashboards / SIEM / bots)."""

from __future__ import annotations

import json
from typing import Any


def _exploit(
    weakness: str, *, effect: str = "unprobed", metadata: dict[str, str] | None = None
) -> Any:
    from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload

    pid = f"finding-{weakness.lower()}"
    md = {"weakness": weakness}
    md.update(metadata or {})
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(pattern_id=pid, channel="tool-result", body="x", metadata=md),
        response=AdapterResponse(
            payload_pattern_id=pid,
            raw_response="the agent followed the injection",
            tool_calls=["read_note", "send_email"],
            metadata={"effect_confirmed": effect},
        ),
        success_reason=f"{weakness} weakness reproduced on the target",
        compliance=ComplianceTags(owasp_llm=["LLM01"], nist_ai_rmf=["MEASURE-2.7"]),
    )


def _report(*, kept: bool = True) -> Any:
    from mylonite.contracts._types import ReproducibilityEvidence, ValidationReport

    return ValidationReport(
        test_filename="test_security_finding.py",
        kept=kept,
        reproducibility=ReproducibilityEvidence(iterations=5, vuln_fired=5, guard_resisted=5),
    )


def test_bundle_structure_and_reuses_finding_data() -> None:
    from mylonite.report.bundle import to_bundle

    bundle = to_bundle([(_exploit("W2", effect="true"), _report())])
    assert bundle["schema_version"]
    assert bundle["tool"]["name"] == "Mylonite" and bundle["tool"]["version"]
    f = bundle["findings"][0]
    assert f["pattern_id"] == "finding-w2"
    assert f["target_id"] == "mcp:myapp"
    assert f["weakness_class"] == "W2"
    assert f["severity"] == "High"  # W2 + confirmed effect
    # compliance reused verbatim
    assert "LLM01" in f["compliance"]["owasp_llm"]
    assert "MEASURE-2.7" in f["compliance"]["nist_ai_rmf"]
    # localization (R4) — the implicated tool/field
    assert f["localization"]["tool"] == "read_note"
    assert f["localization"]["kind"] == "data"
    # differential proof (R2)
    assert f["proof"]["vuln_fired"] == 5 and f["proof"]["iterations"] == 5
    assert f["proof"]["kept"] is True
    json.dumps(bundle)  # fully serialisable


def test_bundle_carries_proven_control_and_attack_shape() -> None:
    from mylonite.report.bundle import to_bundle

    ex = _exploit("W2", metadata={"synthetic_control": "W2", "attack_shape": "memory_poisoning"})
    f = to_bundle([(ex, _report())])["findings"][0]
    assert f["proven_control"] == "W2"
    assert f["attack_shape"] == "memory_poisoning"


def test_bundle_without_report_has_null_proof() -> None:
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W1"), None)])["findings"][0]
    assert f["proof"] is None
    assert f["proven_control"] is None
    assert f["attack_shape"] == "static"  # default when unstamped


def test_bundle_empty() -> None:
    from mylonite.report.bundle import to_bundle

    assert to_bundle([])["findings"] == []
