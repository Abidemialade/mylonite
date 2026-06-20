"""W1 + W2 prompt-injection AttackModule.

Yields seed-shape Payloads from ``mylonite.scan.seeds.SEED_CATALOGUE``. The
plugin itself makes no LLM calls — per the eng review's layered architecture,
``PayloadCustomiser`` is what refines each seed body against the
specific target, and ``ScanEngine`` drives the customisation pass
between ``generate_payloads`` and ``adapter.invoke``.

Metadata wiring is the contract between this plugin, the customiser, the
adapter, and the judge: every emitted Payload carries ``seed_id``,
``weakness``, ``predicate``, ``setup``, ``drive``, and
``needs_customisation`` keys so each downstream layer can find what it
needs without modifying the ``AttackModule`` Protocol (design note
keeps the contract locked; the engine validates metadata at runtime).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from mylonite.contracts import (
    AttackModuleBase,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.contracts.attack_module import CONTRACT_VERSION
from mylonite.scan import seeds
from mylonite.scan.seeds import SeedPattern

_W1_W2 = frozenset({"W1", "W2"})


def _payload_from_seed(seed: SeedPattern) -> Payload:
    return Payload(
        pattern_id=seed.pattern_id,
        channel=seed.channel,
        body=seed.seed_body,
        metadata={
            "seed_id": seed.pattern_id,
            "weakness": seed.weakness,
            "predicate": seed.predicate,
            "setup": seed.setup,
            "drive": seed.drive,
            "needs_customisation": "true",
        },
    )


class PromptInjectionAttackModule(AttackModuleBase):
    """W1 (tool-description smuggling) + W2 (indirect injection) attack family."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="prompt-injection-family",
            name="Prompt-injection family (W1 + W2)",
            summary=(
                "Surfaces seeded tool-description-instruction smuggling (W1) "
                "and indirect injection via note body (W2) against MCP-style "
                "agents. Each seed is a small declarative attack shape; the "
                "ScanEngine customises the body per target before delivery."
            ),
            target_kinds=["mcp"],
            compliance=ComplianceTags(
                owasp_llm=["LLM01", "LLM05"],
                owasp_asi=["ASI01", "ASI02", "ASI06"],
                mitre_atlas=["AML.T0051"],
            ),
            references=[
                "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
            ],
        )

    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:
        # MCP-only attack family — refuse to emit payloads for other kinds so
        # the engine doesn't waste calls on incompatible targets.
        if target.kind != "mcp":
            return
        # Selection resolved centrally (descriptor-first) via the seeds module
        # namespace, so a single patch point governs applicability and custom
        # targets can opt in by declaring weakness_classes. This module owns the
        # W1+W2 family ONLY — without this filter it re-emits the W3/W4 seeds the
        # ExcessiveAgency module already owns, double-counting attempts and
        # findings for the same pattern_id (#5). Mirrors that module's `_W3_W4`.
        for seed in seeds.seeds_for_descriptor(target):
            if seed.weakness in _W1_W2:
                yield _payload_from_seed(seed)
