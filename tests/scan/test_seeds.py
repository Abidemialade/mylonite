"""Seed catalogue contract tests.

The Phase 1 scan engine validates seed-predicate references at startup; these
tests pin the same invariants at import time so a mis-named predicate or a
seed with empty compliance tags fails CI rather than at first scan.
"""

from __future__ import annotations

import pytest

from mylonite.contracts._types import ComplianceTags
from mylonite.scan.predicates import PredicateNotFound, lookup_predicate, registered_names
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern


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
    """The 8 seeds shipped through v0.2.1 all apply to the kitchen-sink family.

    v0.2.2's new MCP-server-shaped seeds will tag ``filesystem``, ``fetch``,
    or ``github`` instead; pinning the kitchen-sink count here makes that
    addition explicit rather than implicit.
    """
    kitchen_sink_seeds = [s for s in SEED_CATALOGUE if "kitchen-sink" in s.applicable_targets]
    assert len(kitchen_sink_seeds) == 8, (
        f"expected 8 kitchen-sink seeds (the v0.2.1 catalogue); got "
        f"{len(kitchen_sink_seeds)}: {[s.pattern_id for s in kitchen_sink_seeds]}"
    )


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
