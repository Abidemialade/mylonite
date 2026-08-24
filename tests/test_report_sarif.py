"""SARIF 2.1.0 output (R1) — GitHub code-scanning integration + proof (R2)."""

from __future__ import annotations

import json
from typing import Any


def _exploit(weakness: str, *, effect: str = "unprobed") -> Any:
    from mylonite.contracts._types import (
        AdapterResponse,
        ComplianceTags,
        ExploitRecord,
        Payload,
    )

    pid = f"finding-{weakness.lower()}"
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(
            pattern_id=pid, channel="tool-result", body="x", metadata={"weakness": weakness}
        ),
        response=AdapterResponse(
            payload_pattern_id=pid,
            raw_response="the agent followed the injection",
            tool_calls=["read_note", "send_email"],
            metadata={"effect_confirmed": effect},
        ),
        success_reason=f"{weakness} weakness reproduced on the target",
        compliance=ComplianceTags(owasp_llm=["LLM01"], nist_ai_rmf=["MEASURE-2.7"]),
    )


def _report(*, kept: bool, vuln: int, guard_resisted: int | None, iters: int = 5) -> Any:
    from mylonite.contracts._types import ReproducibilityEvidence, ValidationReport

    return ValidationReport(
        test_filename="test_security_finding.py",
        kept=kept,
        reproducibility=ReproducibilityEvidence(
            iterations=iters,
            vuln_fired=vuln,
            guard_resisted=guard_resisted,
            guard_fired=(iters - guard_resisted) if guard_resisted is not None else None,
            rate_gap=((vuln - (iters - guard_resisted)) / iters)
            if guard_resisted is not None
            else None,
        ),
    )


def test_to_sarif_structure_and_differential_proof() -> None:
    from mylonite.report.sarif import to_sarif

    doc = to_sarif([(_exploit("W2", effect="true"), _report(kept=True, vuln=5, guard_resisted=5))])
    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Mylonite"
    assert run["tool"]["driver"]["rules"]  # a rule per finding shape
    res = run["results"][0]
    assert res["ruleId"] == "finding-w2"
    assert res["level"] == "error"  # W2 + effect → High → error
    # R2: the differential proof is surfaced in the message.
    assert "5/5" in res["message"]["text"]
    assert "safeguard" in res["message"]["text"].lower()
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # GitHub code scanning dedups alerts across commits via partialFingerprints.
    assert res["partialFingerprints"]["mylonitePatternLocus/v1"]
    props = res["properties"]
    assert props["security-severity"] == "8.0"  # GitHub numeric severity for High
    assert "LLM01" in props["tags"] and "MEASURE-2.7" in props["tags"]
    json.dumps(doc)  # fully serialisable / self-contained


def test_partial_fingerprint_is_stable_and_distinct() -> None:
    """The fingerprint keys on the finding's IDENTITY (pattern + weakness + locus + target),
    not a line number — so GitHub keeps the same weakness one alert across commits, and two
    different weakness classes are two alerts."""
    from mylonite.report.sarif import to_sarif

    def fp(exploit: object) -> str:
        r = to_sarif([(exploit, None)])["runs"][0]["results"][0]
        return str(r["partialFingerprints"]["mylonitePatternLocus/v1"])

    # Same finding twice → identical fingerprint (stable dedup).
    assert fp(_exploit("W2")) == fp(_exploit("W2"))
    # Different weakness class → different fingerprint (distinct alert).
    assert fp(_exploit("W2")) != fp(_exploit("W1"))


def test_to_sarif_levels_by_severity() -> None:
    from mylonite.report.sarif import to_sarif

    doc = to_sarif([(_exploit("W1"), None)])  # W1, no effect → Medium → warning
    res = doc["runs"][0]["results"][0]
    assert res["level"] == "warning"
    assert res["properties"]["security-severity"] == "5.0"
    # No validation report → no differential proof, but still a valid result.
    assert "differential" not in res["message"]["text"].lower()


def test_to_sarif_localizes_finding_to_a_logical_location() -> None:
    """R4: the result pins the finding to its locus (the implicated tool/field) via a
    SARIF logicalLocation, and names it in the message — so code scanning shows WHERE."""
    from mylonite.report.sarif import to_sarif

    res = to_sarif([(_exploit("W2"), None)])["runs"][0]["results"][0]
    logical = res["locations"][0]["logicalLocations"]
    assert logical[0]["name"] == "read_note"  # the returned-content tool (first call)
    assert "returned content" in logical[0]["fullyQualifiedName"]
    assert "Located at:" in res["message"]["text"]
    assert "read_note" in res["message"]["text"]


def test_to_sarif_recommendation_absent_without_a_target() -> None:
    """PR6: additive — no `mylonite.recommendation` property key at all when
    no target is supplied, so every existing (target-less) caller/consumer
    of a result's properties keeps working unchanged."""
    from mylonite.report.sarif import to_sarif

    res = to_sarif([(_exploit("W3"), None)])["runs"][0]["results"][0]
    assert "mylonite.recommendation" not in res["properties"]


def test_to_sarif_recommendation_present_with_a_target() -> None:
    """The SARIF property is the SAME shape the JSON bundle carries — both go
    through recommend.to_dict, so they cannot describe one finding two
    different ways."""
    from mylonite.gate.recommend import TargetContext, recommend, to_dict
    from mylonite.report.sarif import to_sarif

    ex = _exploit("W2", effect="true")
    report = _report(kept=True, vuln=5, guard_resisted=5)
    target = TargetContext(target_id="mcp:myapp")
    doc = to_sarif([(ex, report)], target=target)
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["mylonite.recommendation"] == to_dict(
        recommend(ex, report, target=target)
    )
    json.dumps(doc)  # still fully serialisable with the recommendation present


def test_to_sarif_recommendation_never_uses_result_fixes() -> None:
    """SARIF's result.fixes[].artifactChanges requires a real artifact URI +
    region to apply a patch against, which a remote MCP tool doesn't have —
    the recommendation rides in properties only, never fixes."""
    from mylonite.gate.recommend import TargetContext
    from mylonite.report.sarif import to_sarif

    res = to_sarif([(_exploit("W4"), None)], target=TargetContext(target_id="mcp:myapp"))["runs"][
        0
    ]["results"][0]
    assert "fixes" not in res


def test_to_sarif_empty() -> None:
    from mylonite.report.sarif import to_sarif

    doc = to_sarif([])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_to_sarif_redacts_secret_shaped_success_reason() -> None:
    """DCR-0021: this artefact is uploaded to GitHub code scanning, and a real
    exfil finding's success_reason can narrate the exfiltrated value itself."""
    from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
    from mylonite.report.sarif import to_sarif

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
    res = to_sarif([(ex, None)])["runs"][0]["results"][0]
    assert secret not in res["message"]["text"]
