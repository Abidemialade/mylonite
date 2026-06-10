"""PromptInjectionAttackModule tests."""

from __future__ import annotations

from mylonite.contracts import AttackModule, ComplianceTags, TargetDescriptor
from mylonite.plugins._reference.prompt_injection_module import (
    PromptInjectionAttackModule,
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
    assert isinstance(PromptInjectionAttackModule(), AttackModule)


def test_attack_metadata_returns_umbrella_pattern() -> None:
    meta = PromptInjectionAttackModule().attack_metadata()
    assert meta.id == "prompt-injection-family"
    assert "mcp" in meta.target_kinds
    assert isinstance(meta.compliance, ComplianceTags)
    assert "LLM01" in meta.compliance.owasp_llm
    assert "ASI01" in meta.compliance.owasp_asi


def test_generate_payloads_emits_one_per_seed() -> None:
    module = PromptInjectionAttackModule()
    payloads = list(module.generate_payloads(_mcp_descriptor()))
    assert len(payloads) == len(SEED_CATALOGUE)


def test_emitted_payloads_carry_required_metadata() -> None:
    module = PromptInjectionAttackModule()
    required = {"seed_id", "weakness", "predicate", "setup", "drive", "needs_customisation"}
    for payload in module.generate_payloads(_mcp_descriptor()):
        assert required.issubset(payload.metadata), (
            f"payload {payload.pattern_id} missing metadata keys: "
            f"{required - payload.metadata.keys()}"
        )
        assert payload.metadata["needs_customisation"] == "true"


def test_skips_non_mcp_targets() -> None:
    """The attack module is MCP-only; non-MCP descriptors get no payloads."""
    rag_target = TargetDescriptor(target_id="rag", kind="rag", tools=[])
    assert list(PromptInjectionAttackModule().generate_payloads(rag_target)) == []


def test_emits_nothing_for_unknown_target_family() -> None:
    """An mcp: target whose family is not in any seed's applicable_targets gets zero payloads."""
    module = PromptInjectionAttackModule()
    payloads = list(module.generate_payloads(_unknown_family_descriptor()))
    assert payloads == []
