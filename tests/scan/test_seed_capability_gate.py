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

A later fix narrowed ``synthesize_seeds``'s deferral further still: it only
defers to the kitchen-sink catalogue seed when that seed's own recall tool
(hard-keyed to a literal ``read_note``) is actually on the target's surface.
``write_file``/``read_file`` is a real plant+recall pair under a different
name, so when the target has ALSO confirmed it can plant
(``can_plant_untrusted_content=True``), it is now covered by synthesis
itself rather than handed off to a catalogue seed that could never do
anything but report "not applicable" against it. The same capability gate
that already applied to the kitchen-sink seed_note seed applies here too —
the role classifier's pick is a hint about tool SHAPE, never proof that a
plant actually round-trips, so ``can_plant_untrusted_content=False`` still
withholds the generic seed and leaves the (non-coverage) placeholder in
place, exactly as before.
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


def test_synth_covers_a_non_note_shaped_plant_recall_pair_itself() -> None:
    """The interlock is narrower than it used to be: synth only defers to the
    kitchen-sink fallback when the hand-authored catalogue seed can actually
    reach the target's recall tool (it is hard-keyed to a literal
    ``read_note``). ``write_file``/``read_file`` is a real plant+recall pair
    under a different name, so synth now covers it itself instead of handing
    off to a catalogue seed that would only ever report "not applicable"."""
    d = _descriptor(can_plant=True)
    synthesized = synthesize_seeds(d)
    assert len(synthesized) == 1
    assert synthesized[0].pattern_id == "synth-w2-store-recall-write_file-read_file"
    selected = seeds_for_descriptor(d)
    assert [s.pattern_id for s in selected] == [synthesized[0].pattern_id]


def test_synth_withholds_the_generic_seed_for_a_structural_pair_without_capability() -> None:
    """Review finding 1: scheduling a seed that reaches a real, judge-decided
    verdict directly (no ``SeedArmUnavailable`` backstop) off a NAME-based
    hint alone would let a heuristically-matched pair that never actually
    round-trips report a silent clean result or finding. The structural pair
    (`write_file`/`read_file`) is identical to the capable case above; only
    ``can_plant_untrusted_content`` differs, and that alone must zero out
    synthesis for this class."""
    assert synthesize_seeds(_descriptor(can_plant=False)) == []


def test_the_two_paths_never_both_defer() -> None:
    """The interlock's real invariant: for a target that CAN plant, synthesis
    and the catalogue fallback must never both produce nothing, or W2 silently
    vanishes. Whichever path covers it, at least one W2 seed exists."""
    d = _descriptor(can_plant=True)
    combined = [*synthesize_seeds(d), *seeds_for_descriptor(d)]
    assert any(
        getattr(s, "weakness_class", None) == "W2"
        or "w2" in str(getattr(s, "pattern_id", "")).lower()
        for s in combined
    ), "neither synthesis nor the fallback produced a W2 seed for a plantable target"


def test_target_that_cannot_plant_gets_w2_seeds_that_report_not_tested() -> None:
    """DCR-0031's real invariant survives, refined by #181b: a target with no
    CONFIRMED way to plant must never be handed a planting seed that FAILS
    SILENTLY -- a structurally plausible pair (`write_file`/`read_file`) is
    only a HINT (`tool_roles.py`'s own docstring), never authoritative for a
    verdict, so `can_plant_untrusted_content=False` must still withhold the
    generic store_recall seed here, exactly as it withholds the kitchen-sink
    seed_note seed. It may still be handed the deliberate W2 placeholder(s)
    (so --allow-no-seed-arm's "these will report NOT TESTED" promise holds
    instead of the class silently vanishing to zero seeds) -- each one hits
    SeedArmUnavailable at runtime and reports skipped_no_seed_arm, never a
    silent failure. This fixture's tools have no `send_email`, so the two
    send_email-literal-keyed W2 seeds (#211) are excluded regardless of
    plant capability; only the broader tool-chain seed remains."""
    seeds = seeds_for_descriptor(_descriptor(can_plant=False))
    planting = [s for s in seeds if s.setup != "no_setup"]
    assert [s.pattern_id for s in planting] == ["indirect-injection-note-body-tool-chain"]


def test_capability_decides_whether_w2_counts_as_coverage() -> None:
    """The seed SET can now be identical whether or not the target can plant
    (the #181b placeholder deliberately schedules the same catalogue seeds a
    capable target would get, so they still report NOT TESTED rather than
    vanishing) -- what capability actually decides is whether that seed
    counts as real COVERAGE. `seed_coverage.uncoverable` is where that shows
    up: W2 is coverable when the target can plant, and stays uncoverable
    (with its reason) when it can't, even though `seeds_for_descriptor`
    returns seeds either way. The full runtime difference (a real attempt vs
    a guaranteed skipped_no_seed_arm) is exercised end-to-end in
    tests/scan/test_allow_no_seed_arm_coverage.py."""
    from mylonite.scan.seeds import seed_coverage

    assert "W2" not in seed_coverage(_descriptor(can_plant=True)).uncoverable
    assert "W2" in seed_coverage(_descriptor(can_plant=False)).uncoverable


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
