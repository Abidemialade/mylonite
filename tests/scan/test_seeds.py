"""Seed catalogue contract tests.

The Phase 1 scan engine validates seed-predicate references at startup; these
tests pin the same invariants at import time so a mis-named predicate or a
seed with empty compliance tags fails CI rather than at first scan.
"""

from __future__ import annotations

import pytest

# Eagerly import the MCP plugin package so the v0.2.2 per-target predicates
# register before SeedPattern.predicate lookups run. The engine triggers this
# import via adapter construction in production; the catalogue test does it
# directly.
import mylonite.plugins._mcp  # noqa: F401
from mylonite.contracts._types import ComplianceTags, TargetDescriptor
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
from mylonite.scan.predicates import PredicateNotFound, lookup_predicate, registered_names
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern, seeds_for_descriptor, target_family


def test_catalogue_is_non_empty() -> None:
    assert len(SEED_CATALOGUE) > 0, "SEED_CATALOGUE must not be empty"


def test_catalogue_covers_all_four_weaknesses() -> None:
    """v0.2.1 ships ≥1 seed per weakness W1-W4 (full Phase 1 acceptance criterion)."""
    weaknesses = {s.weakness for s in SEED_CATALOGUE}
    assert weaknesses == {
        "W1",
        "W2",
        "W3",
        "W4",
    }, f"expected W1-W4 coverage; got {sorted(weaknesses)}"


def test_every_seed_pattern_id_is_unique() -> None:
    ids = [s.pattern_id for s in SEED_CATALOGUE]
    assert len(ids) == len(set(ids)), f"duplicate pattern_id in catalogue: {ids}"


@pytest.mark.parametrize("seed", SEED_CATALOGUE, ids=[s.pattern_id for s in SEED_CATALOGUE])
def test_seed_predicate_resolves_in_registry(seed: SeedPattern) -> None:
    """Every seed's predicate string must resolve in the predicate registry.

    This is the same invariant the engine enforces at startup (see PR 6);
    catching it here means a broken seed fails ``pytest`` long before any
    LLM call is made.
    """
    fn = lookup_predicate(seed.predicate)
    assert callable(fn), f"predicate {seed.predicate!r} for {seed.pattern_id!r} is not callable"


@pytest.mark.parametrize("seed", SEED_CATALOGUE, ids=[s.pattern_id for s in SEED_CATALOGUE])
def test_seed_has_non_empty_compliance(seed: SeedPattern) -> None:
    """Every seed must carry at least one OWASP LLM tag.

    Compliance metadata is the foundation of the Phase 6 paid tier (audit
    evidence). Empty compliance is treated as a design bug, not just a lint
    issue.
    """
    assert isinstance(seed.compliance, ComplianceTags)
    assert len(seed.compliance.owasp_llm) > 0, f"seed {seed.pattern_id!r} has no OWASP LLM tags"


def test_lookup_predicate_raises_on_missing_key() -> None:
    with pytest.raises(PredicateNotFound) as excinfo:
        lookup_predicate("nonexistent_predicate")
    assert "nonexistent_predicate" in str(excinfo.value)


@pytest.mark.parametrize("seed", SEED_CATALOGUE, ids=[s.pattern_id for s in SEED_CATALOGUE])
def test_every_seed_has_non_empty_applicable_targets(seed: SeedPattern) -> None:
    """Every seed must declare at least one target family it applies to.

    The attack modules filter ``SEED_CATALOGUE`` by ``family in
    seed.applicable_targets``; a seed with empty applicable_targets would
    never emit a payload regardless of which target is being scanned.
    """
    assert seed.applicable_targets, (
        f"seed {seed.pattern_id!r} has empty applicable_targets — would never emit"
    )


def test_kitchen_sink_family_has_all_v0_2_1_seeds() -> None:
    """The 8 seeds shipped through v0.2.1 all apply to the kitchen-sink family."""
    kitchen_sink_seeds = [s for s in SEED_CATALOGUE if "kitchen-sink" in s.applicable_targets]
    assert len(kitchen_sink_seeds) == 8, (
        f"expected 8 kitchen-sink seeds (the v0.2.1 catalogue); got "
        f"{len(kitchen_sink_seeds)}: {[s.pattern_id for s in kitchen_sink_seeds]}"
    )


def test_each_v0_2_2_target_family_has_at_least_one_seed() -> None:
    """v0.2.2 ships ≥1 seed per bundled MCP target family."""
    families = {f for s in SEED_CATALOGUE for f in s.applicable_targets}
    assert {"kitchen-sink", "filesystem", "fetch", "github"}.issubset(families), (
        f"missing target families in SEED_CATALOGUE: {families}"
    )


# Per plan-eng-review T4: seed bodies must literally contain the target's
# primary tool name so the customiser-pass-through pattern in recorded
# integration tests routes correctly.
_FAMILY_PRIMARY_TOOLS = {
    "filesystem": {"write_file", "read_file"},  # at least one must appear
    "fetch": {"fetch"},
    "github": {"create_issue", "get_issue", "add_issue_comment"},
}


@pytest.mark.parametrize(
    "seed",
    [s for s in SEED_CATALOGUE if "kitchen-sink" not in s.applicable_targets],
    ids=[s.pattern_id for s in SEED_CATALOGUE if "kitchen-sink" not in s.applicable_targets],
)
def test_v0_2_2_seed_body_names_target_tool(seed: SeedPattern) -> None:
    """Each v0.2.2 seed body must reference a tool of its target family."""
    target = seed.applicable_targets[0]
    expected_tools = _FAMILY_PRIMARY_TOOLS.get(target, set())
    matched = [t for t in expected_tools if t in seed.seed_body]
    assert matched, (
        f"seed {seed.pattern_id!r} body must name at least one of "
        f"{sorted(expected_tools)} (target family={target!r}); none found in:\n"
        f"{seed.seed_body}"
    )


# --- #4 descriptor-driven seed applicability --------------------------------


def _descriptor(target_id: str, weakness_classes: list[str] | None = None) -> TargetDescriptor:
    return TargetDescriptor(
        target_id=target_id,
        kind="mcp",
        weakness_classes=weakness_classes or [],
    )


@pytest.mark.parametrize(
    "target_id",
    [
        "reference:vulnerable",
        "reference:guarded",
        "mcp:filesystem:/sandbox",
        "mcp:fetch",
        "mcp:github:owner/repo",
        "mcp:unknown-family",
    ],
)
def test_seeds_for_descriptor_matches_legacy_family_mapping(target_id: str) -> None:
    """Golden: with no weakness_classes, selection is byte-for-byte the legacy logic.

    Guards the 3 bundled families + reference + unknown against any drift from
    the descriptor-first refactor.
    """
    family = target_family(target_id)
    legacy = [s for s in SEED_CATALOGUE if family in s.applicable_targets]
    assert seeds_for_descriptor(_descriptor(target_id)) == legacy


def test_seeds_for_descriptor_weakness_classes_selects_kitchen_sink_shapes() -> None:
    """A custom target declaring weakness_classes gets the matching kitchen-sink seeds."""
    got = seeds_for_descriptor(_descriptor("mcp:triagent", weakness_classes=["W2", "W4"]))
    assert got, "expected W2+W4 kitchen-sink seeds for a custom target"
    assert {s.weakness for s in got} == {"W2", "W4"}
    assert all("kitchen-sink" in s.applicable_targets for s in got)


def test_attack_modules_resolve_selection_dynamically() -> None:
    """Double-binding footgun fixed: patching seeds.seeds_for_descriptor reaches both modules."""
    from mylonite.scan import seeds as seeds_mod

    sentinel = [s for s in SEED_CATALOGUE if s.weakness == "W4"][:1]

    pi = PromptInjectionAttackModule()
    ea = ExcessiveAgencyAttackModule()
    desc = _descriptor("mcp:filesystem:/sandbox")

    original = seeds_mod.seeds_for_descriptor
    try:
        seeds_mod.seeds_for_descriptor = lambda _d: sentinel  # type: ignore[assignment]
        pi_ids = [p.pattern_id for p in pi.generate_payloads(desc)]
        ea_ids = [p.pattern_id for p in ea.generate_payloads(desc)]
    finally:
        seeds_mod.seeds_for_descriptor = original  # type: ignore[assignment]

    # Both modules honoured the patched selection (proves dynamic resolution).
    assert pi_ids == [sentinel[0].pattern_id]
    assert ea_ids == [sentinel[0].pattern_id]  # W4 passes the excessive-agency filter


def test_registry_contains_all_v0_2_1_predicates() -> None:
    expected = {
        # Phase 1 (W1+W2)
        "send_email_to_attacker",
        "planner_summarised_against_user_intent",
        "read_note_returned_poisoned_content_acted_on",
        # v0.2.1 (W3+W4)
        "web_fetch_to_unauthorised_url",
        "send_email_without_confirmation",
    }
    assert expected.issubset(registered_names())
