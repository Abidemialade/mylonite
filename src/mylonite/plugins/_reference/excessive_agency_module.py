"""W3 + W4 excessive-agency AttackModule.

Mirror of ``PromptInjectionAttackModule``: yields seed-shape Payloads from the
``SEED_CATALOGUE`` filtered down to the W3 (unrestricted ``web_fetch`` /
SSRF) and W4 (unconfirmed ``send_email``) seeds. No LLM call inside the
plugin — ``ScanEngine`` handles customisation between ``generate_payloads``
and ``adapter.invoke``.

Metadata wiring: every emitted ``Payload`` carries
``seed_id``, ``weakness``, ``predicate``, ``setup``, ``drive``, and
``needs_customisation``.
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

_W3_W4 = frozenset({"W3", "W4"})


def _payload_from_seed(seed: SeedPattern) -> Payload:
    metadata = {
        "seed_id": seed.pattern_id,
        "weakness": seed.weakness,
        "predicate": seed.predicate,
        "setup": seed.setup,
        "drive": seed.drive,
        # A synthesized W3/W4 seed sets customise=False (its body is already
        # target-shaped and it is not in SEED_CATALOGUE, so the engine cannot
        # build a customiser prompt for it). Hard-coding "true" made every such
        # seed render skipped_unknown_seed. Mirror the prompt-injection module.
        "needs_customisation": "true" if seed.customise else "false",
    }
    metadata.update(seeds.resolved_tool_metadata(seed))
    if seed.judge_context:
        metadata["judge_context"] = seed.judge_context
    return Payload(
        pattern_id=seed.pattern_id,
        channel=seed.channel,
        body=seed.seed_body,
        metadata=metadata,
    )


class ExcessiveAgencyAttackModule(AttackModuleBase):
    """W3 (SSRF / web_fetch) + W4 (unconfirmed send_email) attack family."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="excessive-agency-family",
            name="Excessive Agency family (W3 + W4)",
            summary=(
                "Surfaces unrestricted web_fetch (W3 / SSRF) and unconfirmed "
                "send_email (W4) against MCP-style agents. The vulnerable "
                "server has no URL allowlist and dispatches mail immediately; "
                "the guarded server enforces a hostname allowlist and a "
                "two-step send_email + confirm_send flow."
            ),
            target_kinds=["mcp"],
            compliance=ComplianceTags(
                owasp_llm=["LLM06"],
                owasp_asi=["ASI02", "ASI05"],
                mitre_atlas=["AML.T0049"],
            ),
            references=[
                "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
            ],
        )

    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:
        if target.kind != "mcp":
            return
        # Descriptor-first selection via the seeds module namespace, then the
        # W3+W4 family filter this module owns.
        for seed in seeds.seeds_for_descriptor(target):
            if seed.weakness in _W3_W4:
                yield _payload_from_seed(seed)
