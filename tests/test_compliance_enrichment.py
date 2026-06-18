"""NIST auto-derivation + the wired compliance mapper (2e)."""

from __future__ import annotations

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
)
from mylonite.plugins._reference.reference_compliance_mapper import ReferenceComplianceMapper
from mylonite.taxonomy.compliance import enrich_with_nist


def test_enrich_with_nist_derives_from_owasp_llm() -> None:
    out = enrich_with_nist(ComplianceTags(owasp_llm=["LLM01"]))
    assert "MEASURE-2.7" in out.nist_ai_rmf  # MEASURE-2.7 cross-references LLM01


def test_enrich_with_nist_from_asi_nonempty_and_idempotent() -> None:
    out = enrich_with_nist(ComplianceTags(owasp_asi=["ASI01"]))
    assert out.nist_ai_rmf  # ASI01 has NIST cross-refs
    assert enrich_with_nist(out).nist_ai_rmf == out.nist_ai_rmf  # idempotent


def test_enrich_with_nist_noop_without_owasp() -> None:
    assert enrich_with_nist(ComplianceTags()).nist_ai_rmf == []


def test_compliance_mapper_derives_nist() -> None:
    exploit = ExploitRecord(
        target_id="mcp:custom",
        pattern_id="p",
        payload=Payload(pattern_id="p", channel="user-message", body="x"),
        response=AdapterResponse(payload_pattern_id="p", raw_response="", tool_calls=[]),
        success_reason="x",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )
    enriched = ReferenceComplianceMapper().map(exploit)
    assert "MEASURE-2.7" in enriched.nist_ai_rmf
