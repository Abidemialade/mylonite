"""End-to-end (real ScanEngine + real attack modules) coverage of the
--allow-no-seed-arm exemption (#181b).

A declared W2 with no seed_arm must never read as a trustworthy clean pass.
Before this fix, `seeds_for_descriptor` returned ZERO W2 seeds for a target
with no plant capability, so a [W2, W4] scan under --allow-no-seed-arm could
run to completion on W4 alone and report `Coverage.EXERCISED` /
`trustworthy_clean=True` -- W2 was never attempted at all, silently.

The fix keeps seed_coverage's W2 catalogue (seed_note) seeds SCHEDULED even
with no plant capability -- so they reach the adapter and get an honest
`skipped_no_seed_arm` (NOT_TESTED) each, forcing `Coverage.PARTIAL` -- while
still reporting the class `uncoverable` (the CLI-layer refusal, tested
separately in tests/mcp_plugin/test_cli_targets_refusal.py, still fires
without --allow-no-seed-arm and is exempted only with it).

This module drives the REAL `ScanEngine` with the REAL attack modules (so
seed selection, customisation dispatch and judging all go through the actual
production path) and a purpose-built adapter stub whose `invoke()` raises
`SeedArmUnavailable` for exactly the seeds whose `setup` needs a plant --
mirroring what `MCPSessionAdapterBase._run_setup` actually does for a
"seed_note" setup with no declared `seed_arm` (verified: it falls through to
the generic seed_arm check for every family, there is no seed_note-specific
in-process-store special case outside the reference adapter).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mylonite.contracts._types import AdapterResponse, Payload, TargetDescriptor, ToolSpec
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
from mylonite.scan._types import SeedArmUnavailable, Verdict
from mylonite.scan.coverage import Coverage, ScanOutcome
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine


class _NoSeedArmAdapter:
    """A custom target with `send_email` on its surface but NO seed_arm.

    Mirrors exactly what an operator running --allow-no-seed-arm gets: the
    literal W4 catalogue seed (no_setup) is applicable and gets a real
    engagement; any seed_note-setup seed (the W2 kitchen seeds) hits
    SeedArmUnavailable, the same exception MCPSessionAdapterBase._run_setup
    raises for a "seed_note" setup with `self._spec.seed_arm is None`.
    """

    def __init__(self) -> None:
        self.invoked_setups: list[str] = []

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(
            target_id="mcp:acme",
            kind="mcp",
            system_prompt="x",
            tools=[ToolSpec(name="send_email", description="send an email")],
            weakness_classes=["W2", "W4"],
            can_plant_untrusted_content=False,
        )

    async def invoke(self, payload: Payload) -> AdapterResponse:
        setup = payload.metadata.get("setup", "")
        self.invoked_setups.append(setup)
        if setup not in ("no_setup", ""):
            raise SeedArmUnavailable(
                f"setup arm {setup!r} has no implementation for family 'acme' and the "
                "target declares no seed_arm; indirect-injection attempt not exercised",
                attempt_metadata={"family": "acme", "setup": setup},
            )
        # The literal no_setup W4 seed: a real engagement (send_email called),
        # judged as resisted by the stub judge below.
        return AdapterResponse(
            payload_pattern_id=payload.pattern_id,
            raw_response="done",
            tool_calls=["send_email"],
            metadata={},
        )

    async def close(self) -> None:
        return None


class _CustomiserStub(PayloadCustomiser):
    def __init__(self) -> None:
        pass

    async def customise(self, seed: Any, target: Any) -> Payload:
        del target
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
            },
        )


class _ResistedJudgeStub:
    """A fixed, decisive 'resisted' verdict for every attempt that reaches it
    (only the no_setup W4 seed does; the W2 seeds never get this far)."""

    async def judge(self, payload: Payload, response: AdapterResponse) -> Verdict:
        del payload, response
        return Verdict(success=False, reason="resisted", mechanism="predicate")


def _config() -> ScanConfig:
    return ScanConfig(
        target_id="mcp:acme",
        provider="anthropic",
        model="stub-model",
        max_llm_calls=50,
        max_concurrent=2,
        output_dir=Path(".mylonite/scans"),
    )


@pytest.mark.asyncio
async def test_w2_and_w4_with_no_seed_arm_is_partial_not_trustworthy_clean() -> None:
    """The end-to-end scenario --allow-no-seed-arm is meant to make honest:
    W4 gets a real, decided verdict; W2's seeds are scheduled, reach the
    adapter, and come back skipped_no_seed_arm. The scan must NOT read as a
    trustworthy clean pass."""
    adapter = _NoSeedArmAdapter()
    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[PromptInjectionAttackModule(), ExcessiveAgencyAttackModule()],
        customiser=_CustomiserStub(),
        judge=_ResistedJudgeStub(),  # type: ignore[arg-type]
    )
    result = await engine.run()

    # The W2 seed_note seeds were genuinely SCHEDULED and reached the adapter
    # (not silently dropped to zero seeds) -- this is the fix under test.
    assert "seed_note" in adapter.invoked_setups

    outcome = ScanOutcome.from_report(result.report)
    assert outcome.coverage is Coverage.PARTIAL
    assert outcome.trustworthy_clean is False
    assert any(a.outcome == "skipped_no_seed_arm" for a in result.report.attempts)


@pytest.mark.asyncio
async def test_w2_only_with_no_seed_arm_is_not_trustworthy_clean() -> None:
    """A W2-only declaration with no seed_arm: every attempt is
    skipped_no_seed_arm, so coverage never reaches EXERCISED at all."""

    class _W2OnlyAdapter(_NoSeedArmAdapter):
        async def describe(self) -> TargetDescriptor:
            return TargetDescriptor(
                target_id="mcp:acme",
                kind="mcp",
                system_prompt="x",
                tools=[ToolSpec(name="send_email", description="send an email")],
                weakness_classes=["W2"],
                can_plant_untrusted_content=False,
            )

    adapter = _W2OnlyAdapter()
    engine = ScanEngine(
        config=_config(),
        adapter=adapter,
        attack_modules=[PromptInjectionAttackModule(), ExcessiveAgencyAttackModule()],
        customiser=_CustomiserStub(),
        judge=_ResistedJudgeStub(),  # type: ignore[arg-type]
    )
    result = await engine.run()

    assert adapter.invoked_setups, "the W2 seeds must have been scheduled, not dropped to zero"
    assert all(setup == "seed_note" for setup in adapter.invoked_setups)

    outcome = ScanOutcome.from_report(result.report)
    assert outcome.trustworthy_clean is False
    assert outcome.coverage is not Coverage.EXERCISED
    assert all(a.outcome == "skipped_no_seed_arm" for a in result.report.attempts)
