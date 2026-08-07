"""DCR-0002: ``_run_target_scan``'s live re-drive must not filter attack
modules to a hardcoded 2-id allowlist.

Root cause: ``testkit._run_target_scan`` used to do::

    modules = [
        m
        for m in discover("mylonite.attack_modules")
        if m.attack_metadata().id in {"prompt-injection-family", "excessive-agency-family"}
    ]

So a pattern_id owned by ANY OTHER discovered module -- including a
third-party plugin author's own ``AttackModule``, registered via the very
entry-point mechanism Mylonite's extension contracts document as public API
-- got dropped before payload generation even started: the re-drive silently
produced zero payloads/attempts for that pattern_id, which surfaces upstream
(``assert_target_resists``/``assert_control_holds``) as a misleading
"inconclusive: ... likely a replay/fixture problem" error rather than the
real cause.

The fix passes every discovered module through and relies on the engine's
existing ``pattern_id_filter`` to scope the re-drive precisely --
``discover()`` already instantiates every module regardless of any later
filtering (see ``mylonite.plugins.registry.discover``), so nothing is saved
by pre-filtering, and ``ScanEngine.run()`` already drops any payload whose
pattern_id doesn't match the filter.
"""

from __future__ import annotations

from collections.abc import Iterable
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite import testkit
from mylonite.contracts import (
    AdapterResponse,
    AttackModuleBase,
    AttackPattern,
    ComplianceTags,
    Payload,
    TargetDescriptor,
)
from mylonite.contracts.attack_module import CONTRACT_VERSION
from mylonite.plugins._mcp import factory as factory_module

_THIRD_PARTY_PATTERN_ID = "third-party-attack-pattern"


class _ThirdPartyAttackModule(AttackModuleBase):
    """Stands in for a plugin author's own ``AttackModule``, registered via
    entry points exactly like Mylonite's own bundled modules -- but under an
    id outside the old hardcoded 2-id allowlist."""

    contract_version = CONTRACT_VERSION

    def attack_metadata(self) -> AttackPattern:
        return AttackPattern(
            id="third-party-attack-family",
            name="Third-party attack family",
            summary="A plugin author's own attack module (not one Mylonite ships).",
            target_kinds=["mcp", "custom"],
            compliance=ComplianceTags(),
            references=[],
        )

    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:
        del target
        yield Payload(
            pattern_id=_THIRD_PARTY_PATTERN_ID,
            channel="tool-result",
            body="third-party payload body",
            metadata={
                "seed_id": _THIRD_PARTY_PATTERN_ID,
                "weakness": "W_THIRD_PARTY",
                # Deliberately unregistered: the judge then resolves cleanly to
                # success=False WITHOUT any LLM call, so this test needs no
                # completion_fn / LiteLLM stubbing at all.
                "predicate": "not-a-registered-predicate",
                "setup": "none",
                "drive": "none",
                "needs_customisation": "false",
            },
        )


class _FakeAdapter:
    """Minimal ``AsyncTargetAdapter`` double -- no subprocess, no LLM calls."""

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="mcp:faketarget", kind="mcp")

    async def invoke(self, payload: Payload) -> AdapterResponse:
        return AdapterResponse(payload_pattern_id=payload.pattern_id, raw_response="ok")


def test_run_target_scan_includes_third_party_attack_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pattern_id owned by a module OUTSIDE the old 2-id allowlist must still
    get a payload generated (and an attempt recorded) for the re-drive, scoped
    precisely by ``pattern_id_filter`` -- not silently dropped to zero because
    the owning module never made it into the engine's ``attack_modules`` list.
    """

    def fake_discover(group: str) -> list[Any]:
        assert group == "mylonite.attack_modules"
        return [_ThirdPartyAttackModule()]

    monkeypatch.setattr("mylonite.plugins.registry.discover", fake_discover)

    def fake_build_adapter_for_spec(spec: Any, **kwargs: Any) -> Any:
        del spec, kwargs
        return _FakeAdapter()

    monkeypatch.setattr(factory_module, "build_adapter_for_spec", fake_build_adapter_for_spec)

    result = testkit._run_target_scan(
        spec=SimpleNamespace(family="faketarget"),
        scope=None,
        pattern_id=_THIRD_PARTY_PATTERN_ID,
        model="stub-model",
        provider="stub",
        controls=None,
        completion_fn=None,
    )

    attempts = result.report.attempts
    assert len(attempts) == 1, (
        "expected exactly one attempt for the third-party pattern_id; got "
        f"{attempts!r} -- the owning module was filtered out before payload "
        "generation could even start"
    )
    assert attempts[0].pattern_id == _THIRD_PARTY_PATTERN_ID
    assert attempts[0].outcome != "skipped_invalid_metadata"
