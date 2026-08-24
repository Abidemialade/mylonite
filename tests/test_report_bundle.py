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

    ex = _exploit("W2", metadata={"synthetic_control": "W2", "attack_shape": "static"})
    f = to_bundle([(ex, _report())])["findings"][0]
    assert f["proven_control"] == "W2"
    assert f["attack_shape"] == "static"


def test_bundle_without_report_has_null_proof() -> None:
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W1"), None)])["findings"][0]
    assert f["proof"] is None
    assert f["proven_control"] is None
    assert f["attack_shape"] == "static"  # default when unstamped


def test_bundle_recommendation_absent_without_a_target() -> None:
    """PR6: additive — every existing (target-less) caller keeps getting
    recommendation: null, not a missing key that would break strict parsers."""
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W3"), _report())])["findings"][0]
    assert f["recommendation"] is None


def test_bundle_recommendation_present_with_a_target() -> None:
    """The bundle's recommendation is the SAME shape build_pr_body renders —
    both go through recommend.to_dict, so they cannot describe one finding
    two different ways."""
    from mylonite.gate.recommend import TargetContext, recommend, to_dict
    from mylonite.report.bundle import to_bundle

    ex = _exploit("W2")
    report = _report()
    target = TargetContext(target_id="mcp:myapp")
    f = to_bundle([(ex, report)], target=target)["findings"][0]
    assert f["recommendation"] == to_dict(recommend(ex, report, target=target))
    json.dumps(f)  # still fully serialisable with the recommendation present


def test_bundle_schema_version_bumped_for_the_additive_recommendation_key() -> None:
    from mylonite.report.bundle import SCHEMA_VERSION, to_bundle

    assert SCHEMA_VERSION == "1.1"
    assert to_bundle([])["schema_version"] == "1.1"


def test_bundle_empty() -> None:
    from mylonite.report.bundle import to_bundle

    assert to_bundle([])["findings"] == []


def test_bundle_redacts_secret_shaped_success_reason() -> None:
    """Mirrors the sarif.py DCR-0021 fix: this bundle is written to disk
    unconditionally (report --json / gate), and a real exfil finding's
    success_reason can narrate the exfiltrated value itself."""
    from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
    from mylonite.report.bundle import to_bundle

    secret = "sk-live" + "abcdefghijklmnopqrstuvwxyz"
    pid = "finding-w3"
    ex = ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(
            pattern_id=pid, channel="tool-result", body="x", metadata={"weakness": "W3"}
        ),
        response=AdapterResponse(
            payload_pattern_id=pid, raw_response="ok", tool_calls=["fetch"], metadata={}
        ),
        success_reason=f"exfiltrated {secret} to the attacker endpoint",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )
    f = to_bundle([(ex, None)])["findings"][0]
    assert secret not in f["success_reason"]
