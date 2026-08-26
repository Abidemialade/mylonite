"""Regression tests for the W2 seed-selection gap on custom targets.

Pins the W2 seed-selection gap: a custom
target whose tools form a plant+recall pair (write_file/read_file) received
ZERO W2 seeds and aborted with "no seeds applicable to family custom", even
with weakness_classes and a fully-specified seed_arm declared exactly per the
docs.

Two individually-correct code paths, each assuming the other covered the case:

* ``seed_synth.synthesize_seeds`` SKIPS synthesising a W2 seed when a
  plant/recall pair exists, deferring to "the kitchen-sink W2 seeds".
* ``seeds_for_descriptor``'s kitchen-sink fallback required
  ``family in s.applicable_targets`` for any non-``no_setup`` seed — target
  IDENTITY. A custom family is never in a bundled seed's applicable_targets.

The gate now asks about CAPABILITY (can this target plant?) rather than
identity (is this target one of ours?).
"""

from __future__ import annotations

from mylonite.contracts._types import TargetDescriptor, ToolSpec
from mylonite.scan.seed_synth import synthesize_seeds
from mylonite.scan.seeds import seeds_for_descriptor


def _tool(name: str, props: dict) -> ToolSpec:
    return ToolSpec(name=name, description="d", json_schema={"type": "object", "properties": props})


_PLANT_RECALL_TOOLS = [
    _tool("write_file", {"path": {"type": "string"}, "content": {"type": "string"}}),
    _tool("read_file", {"path": {"type": "string"}}),
    _tool("list_directory", {"path": {"type": "string"}}),
]


def _descriptor(*, can_plant: bool, tools: list[ToolSpec] | None = None) -> TargetDescriptor:
    return TargetDescriptor(
        target_id="mcp:custom:sandbox",
        kind="mcp",
        system_prompt="",
        notes="",
        tools=_PLANT_RECALL_TOOLS if tools is None else tools,
        data_sources=[],
        weakness_classes=["W2"],
        can_plant_untrusted_content=can_plant,
    )


def test_custom_target_with_a_seed_arm_now_gets_w2_seeds() -> None:
    """THE bug: this returned [] and aborted with no_payloads."""
    seeds = seeds_for_descriptor(_descriptor(can_plant=True))
    assert seeds, "a custom target that CAN plant must receive W2 seeds"
    assert all(s.weakness == "W2" for s in seeds)


def test_the_two_paths_no_longer_both_defer() -> None:
    """Pins the interlock itself: synth skips exactly when a plant/recall pair
    exists, so the fallback MUST cover that case or nothing does."""
    d = _descriptor(can_plant=True)
    assert synthesize_seeds(d) == [], "synth is expected to defer here"
    assert seeds_for_descriptor(d), "so the fallback must not also defer"


def test_target_that_cannot_plant_still_gets_no_planting_seed() -> None:
    """DCR-0031 must survive: a target with no way to plant must not be handed a
    seed whose setup expects one — that produced silent failures, not findings."""
    seeds = seeds_for_descriptor(_descriptor(can_plant=False))
    assert [s for s in seeds if s.setup != "no_setup"] == []


def test_capability_not_identity_decides() -> None:
    """Same tools, same declared classes — only the capability flag differs."""
    assert seeds_for_descriptor(_descriptor(can_plant=True)) != seeds_for_descriptor(
        _descriptor(can_plant=False)
    )


def test_descriptor_defaults_to_cannot_plant() -> None:
    """Fail-safe: an adapter that never sets the flag must not accidentally
    unlock planting seeds."""
    d = TargetDescriptor(target_id="mcp:custom:x", kind="mcp", weakness_classes=["W2"])
    assert d.can_plant_untrusted_content is False


def test_synth_still_covers_a_target_with_no_plant_recall_pair() -> None:
    """The other half of the interlock: when there is NO plant/recall pair,
    synthesis is responsible, and must still fire."""
    processor = [_tool("summarize_document", {"text": {"type": "string"}})]
    seeds = synthesize_seeds(_descriptor(can_plant=False, tools=processor))
    assert any(s.weakness == "W2" for s in seeds)
