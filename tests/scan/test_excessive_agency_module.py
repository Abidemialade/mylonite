"""ExcessiveAgencyAttackModule tests (mirror of test_prompt_injection_module.py)."""

from __future__ import annotations

from mylonite.contracts import AttackModule, ComplianceTags, TargetDescriptor
from mylonite.plugins._reference.excessive_agency_module import (
    ExcessiveAgencyAttackModule,
)
from mylonite.scan.seeds import SEED_CATALOGUE


def _mcp_descriptor() -> TargetDescriptor:
    """Kitchen-sink-family MCP descriptor used by the existing v0.2.x tests."""
    return TargetDescriptor(
        target_id="reference:vulnerable", kind="mcp", system_prompt="x", tools=[]
    )


def _unknown_family_descriptor() -> TargetDescriptor:
    """Family-unmapped MCP descriptor — applicable_targets filter yields nothing."""
    return TargetDescriptor(target_id="mcp:nosuch:scope", kind="mcp", system_prompt="x", tools=[])


def test_module_satisfies_attack_module_protocol() -> None:
    assert isinstance(ExcessiveAgencyAttackModule(), AttackModule)


def test_attack_metadata_returns_umbrella_pattern() -> None:
    meta = ExcessiveAgencyAttackModule().attack_metadata()
    assert meta.id == "excessive-agency-family"
    assert "mcp" in meta.target_kinds
    assert isinstance(meta.compliance, ComplianceTags)
    assert "LLM06" in meta.compliance.owasp_llm
    assert "ASI02" in meta.compliance.owasp_asi


def test_generate_payloads_emits_only_w3_and_w4_for_kitchen_sink() -> None:
    """``reference:vulnerable`` resolves to the kitchen-sink family; emitted
    seeds are W3+W4 ∩ kitchen-sink (PR 2 + PR 5 of v0.2.2)."""
    module = ExcessiveAgencyAttackModule()
    payloads = list(module.generate_payloads(_mcp_descriptor()))
    weaknesses = {p.metadata["weakness"] for p in payloads}
    assert weaknesses == {"W3", "W4"}
    expected_count = sum(
        1
        for s in SEED_CATALOGUE
        if s.weakness in {"W3", "W4"} and "kitchen-sink" in s.applicable_targets
    )
    assert len(payloads) == expected_count


def test_emitted_payloads_carry_required_metadata() -> None:
    module = ExcessiveAgencyAttackModule()
    required = {"seed_id", "weakness", "predicate", "setup", "drive", "needs_customisation"}
    for payload in module.generate_payloads(_mcp_descriptor()):
        assert required.issubset(payload.metadata), (
            f"payload {payload.pattern_id} missing metadata keys: "
            f"{required - payload.metadata.keys()}"
        )
        assert payload.metadata["needs_customisation"] == "true"


def test_skips_non_mcp_targets() -> None:
    rag_target = TargetDescriptor(target_id="rag", kind="rag", tools=[])
    assert list(ExcessiveAgencyAttackModule().generate_payloads(rag_target)) == []


def test_emits_nothing_for_unknown_target_family() -> None:
    """An mcp: target whose family is not in any seed's applicable_targets gets zero payloads."""
    module = ExcessiveAgencyAttackModule()
    payloads = list(module.generate_payloads(_unknown_family_descriptor()))
    assert payloads == []
