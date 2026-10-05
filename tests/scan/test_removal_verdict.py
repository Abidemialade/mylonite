"""Rule 1b: a confirmed removal can only raise a dispatch to "effect-confirmed".

The opt-in removal check (``effect_probe.removal``) feeds one boolean to the
verdict rule. These tests pin that it never resists, never makes an attempt
inconclusive and never clears: across every evidence combination, adding it
either leaves the decision unchanged or turns it into a finding at
"effect-confirmed", and only under the guard rule 1b names.
"""

from __future__ import annotations

import itertools
from dataclasses import replace
from typing import Any, get_args

import pytest

from mylonite.scan.effect_verdict import EffectEvidence, TraceOutcome, decide

_OUTCOMES = get_args(TraceOutcome)
_LINKS = ("unlinked", "token-linked", "handle-linked", "dispatched-tool-linked")
_MARKER_KINDS = ("none", "payload", "exfil", "fixed")
_EFFECTS = ("true", "false", "unattributed", "errored", "deferred", "unprobed")


def _ev(**kwargs: Any) -> EffectEvidence:
    base: dict[str, Any] = {
        "trace_outcome": "dispatched-ok",
        "link": "dispatched-tool-linked",
        "effect_confirmed": "unattributed",
        "marker_kind": "none",
        "marker_linked": False,
        "calibrated": False,
        "confirm_capable": True,
        "any_deferred": False,
        "removal_confirmed": True,
    }
    base.update(kwargs)
    return EffectEvidence(**base)


def test_the_batch_2_shape_is_raised_to_effect_confirmed() -> None:
    """confirm_only, an unattributed probe read, a tool-linked delete."""
    decision = decide(_ev(), predicate=None)
    assert (decision.kind, decision.proof_level) == ("finding", "effect-confirmed")
    assert decision.negative_basis is None and decision.reason_code is None


@pytest.mark.parametrize(
    "change",
    [
        {"confirm_capable": False},
        {"any_deferred": True},
        {"removal_confirmed": False},
        {"effect_confirmed": "deferred"},
        *({"trace_outcome": o} for o in _OUTCOMES if o != "dispatched-ok"),
    ],
)
def test_rule_1b_needs_every_part_of_its_guard(change: dict[str, Any]) -> None:
    evidence = _ev(**change)
    decision = decide(evidence, predicate=None)
    assert decision == decide(replace(evidence, removal_confirmed=False), predicate=None)


def test_removal_only_ever_raises_across_every_input() -> None:
    combos = itertools.product(
        _OUTCOMES,
        _LINKS,
        _EFFECTS,
        _MARKER_KINDS,
        (True, False),  # marker_linked
        (True, False),  # calibrated
        (True, False),  # confirm_capable
        (True, False),  # any_deferred
        (True, False, None),  # predicate
    )
    for outcome, link, effect, kind, linked, cal, capable, deferred, predicate in combos:
        evidence = _ev(
            trace_outcome=outcome,
            link=link,
            effect_confirmed=effect,
            marker_kind=kind,
            marker_linked=linked,
            calibrated=cal,
            confirm_capable=capable,
            any_deferred=deferred,
        )
        with_removal = decide(evidence, predicate=predicate)
        without = decide(replace(evidence, removal_confirmed=False), predicate=predicate)
        if with_removal == without:
            continue
        # The only change rule 1b may make.
        assert (with_removal.kind, with_removal.proof_level) == ("finding", "effect-confirmed")
        assert capable and outcome == "dispatched-ok" and not deferred
        assert effect != "deferred"
        assert with_removal.negative_basis is None and with_removal.reason_code is None


def test_a_missing_or_non_true_removal_key_reads_false() -> None:
    for value in (None, "false", "unavailable", "errored", "True"):
        metadata = {"trace_outcome": "dispatched-ok"}
        if value is not None:
            metadata["removal_confirmed"] = value
        evidence = EffectEvidence.from_metadata(metadata)
        assert evidence is not None and evidence.removal_confirmed is False
    evidence = EffectEvidence.from_metadata(
        {"trace_outcome": "dispatched-ok", "removal_confirmed": "true"}
    )
    assert evidence is not None and evidence.removal_confirmed is True


def test_a_hold_the_effect_probe_saw_is_never_overridden() -> None:
    """The fixed probe read "deferred": the target's own state shows the action
    held. A confirmed removal must not turn that into effect-confirmed."""
    for capable in (True, False):
        evidence = _ev(effect_confirmed="deferred", confirm_capable=capable)
        decision = decide(evidence, predicate=None)
        assert decision.proof_level != "effect-confirmed"
        assert decision == decide(replace(evidence, removal_confirmed=False), predicate=None)
