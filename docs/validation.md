# The validation engine (the moat)

The attack library finds weaknesses. The **validation engine** is what makes
Mylonite's output trustworthy — it proves a generated security test *means*
what it claims, then ships that proof as a fast, offline CI gate. This is the
moat: the novel piece is not the exploits, it's the machinery that separates a
real, reproducible weakness from a plausible-looking but vacuous assertion.

## Two tiers: live discovery, offline gate

Mylonite deliberately splits work into two tiers that run at different times,
in different places, under different cost models.

**Tier 1 — discovery + validation (LIVE, periodic).**
`mylonite scan` finds an exploit and `mylonite validate` proves it is
meaningful. Both make real LLM calls (Haiku by default), because the thing
under test — an agent's behaviour — is non-deterministic and can only be
exercised live. This is the expensive, stochastic tier. You run it
periodically: when you build a new agent capability, change a system prompt,
add a tool, or on a schedule — not on every commit.

**Tier 2 — the committed regression test (OFFLINE, per-PR).**
`mylonite generate` emits a pytest file that, at the CI gate, replays a
*recorded* reproduction of the attack against the guarded twin. No API key. No
network. No LLM call. It is a normal, fast, deterministic pytest. That is what
runs on every pull request: if a future change re-opens the weakness, the
recorded attack now succeeds against the guard and the test fails.

The recorded fixtures (the `(model, messages)` → response pairs the replay
looks up) and an `exploit_*.json` are produced once, during the live tier, and
committed alongside the test. After that the gate is offline forever — until
something that changes the recorded pairs (a planner / judge / customiser
prompt, a tool schema, or the model) forces a re-record.

## "Isn't this a tautology?"

The sharpest objection: *a generated test that replays a recorded attack and
asserts the guard holds — isn't that circular? You recorded the guard holding,
then you assert the guard holds.*

No, and the answer is the whole point of the engine. Three things break the
circle, all of them at the **live validation tier**, before any fixture is
committed:

1. **The differential proof.** At validation time the
   [`DifferentialValidator`](concepts.md#the-validation-engine-mylonites-moat)
   runs the *same* attack against **both** twins — the deliberately-unguarded
   variant and the guarded one. A test is only kept if the exploit **fires on
   the vulnerable twin and resists on the guarded twin**. A vacuous test
   (asserting something trivially true) cannot show this differential: it would
   pass on *both* sides. The differential is the discrimination signal a
   tautology can never produce.

2. **The 5-run flakiness filter.** Because the behaviour is stochastic, a
   single run is weak evidence. The validator repeats the differential across
   five iterations and keeps the test only if the vulnerable twin fires
   reliably (`>= iterations - 1` by default) **and** the guarded twin resists
   *every single run* (a guard that leaks even once is not a guard). The
   reported **reproducibility fraction** is `min(fires, resists) / iterations`.

3. **The honest-fail gate.** The committed offline test's
   `testkit.assert_guard_holds` does not silently pass when its evidence is
   missing. A stale, absent, corrupt, or version-mismatched fixture, or an
   inconclusive run, **raises** rather than reporting green. A gate that passes
   without evidence is worse than no gate, so the testkit inspects recorder
   state after the replay and refuses to vouch for a run it cannot stand
   behind.

Together these mean the recorded reproduction is not "the guard holding by
construction" — it is a reproduction that *demonstrably discriminated* between
guarded and unguarded behaviour, reliably, at record time, and whose offline
replay is honest about its own evidence.

## What the numbers mean

Every validation reports three headline figures.

- **`kept`** — the gating verdict. `kept = build ∧ differential ∧ flakiness`.
  The test built and collected under pytest, showed the differential at all,
  *and* showed it reliably across the flakiness filter. Only a kept test is
  worth committing.
- **Reproducibility fraction** — the flakiness-stage metric,
  `min(vulnerable fires, guarded resists) / iterations`. How dependably the
  test discriminates run-to-run; `1.0` means it fired and resisted on every
  iteration.
- **Mutation score** (report-only) — the fraction of the four bundled
  kitchen-sink weakness families (W1–W4) that show the differential (the
  vulnerable twin fired ≥1 seed in the family **and** the guarded twin resisted
  it). It is computed for free from the scans already run and gives a coverage
  read across the weakness bank, not just the single exploit under test.

A fourth stage, **metamorphic-lite**, applies one neutral paraphrase of the
exploit body and re-checks the differential once. It is reported, not gating —
a cheap robustness read that catches the most brittle over-fit tests.

## MVP scope: the bundled reference twin

For the MVP, the "guarded twin" the engine validates against is the **bundled
reference agent** — [the Quarry](quarry.md)'s `mcp_kitchen_sink` server in its
vulnerable and guarded variants. That bundled twin *is* the differential
oracle, which is why importing the testkit transitively imports the reference
adapter. Pointing the engine at a **consumer-owned** agent (your app's real AI
layer, with your own guarded/unguarded variants) is a later phase. The
machinery — differential, flakiness, mutation score, honest-fail gate — is the
part that generalises; the bundled twin is the ground truth it is proven
against today.
