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

## Beyond the bundled twin: the control-efficacy oracle

The differential above proves a weakness is real by comparing a *vulnerable*
build to a *guarded* one. But on a **real target you don't have two builds of**,
the sharper question is not "is there a weakness?" — it's *"which safeguard is
actually carrying the security, and does it hold?"* That is what the
**control-efficacy oracle** (`validate --prove-control`) answers, and it is the
deepened moat.

The move is to **hold the model constant and vary only the safeguard**. Mylonite
synthesizes a *guarded twin* of any real target by applying a canonical control
at the **adapter boundary** — a `ControlServerShim` that wraps the live target
(W1 tool-description sanitiser, W2 untrusted-data envelope, W3 egress
allowlist, W4 confirm-gate). The same model, the same tools, the same target;
the only thing that changes between the two legs is whether the control is in
the planner's path. A finding is kept only when the attack **fires on the raw
target and is resisted with the control applied** — which proves the *control*,
not the model's mood, is what stopped it. It is scored as a control-contribution
rate gap across the same flakiness filter.

Two honesty properties make this trustworthy:

- **The plant and the effect probe always bypass the shim.** The attacker plants
  on the raw session and the effect probe reads the raw session; only the
  *planner's view* is guarded. So the control is measured against an undiluted
  attack, never a hobbled one.
- **It is a boundary proxy, stated as one.** Mylonite enforces the control at
  the adapter boundary, not inside your server. The emitted test and the gating
  PR say so explicitly and point you at a server-side fix — the test is a
  load-bearing-control regression gate, with the proxy caveat on the label.

`mylonite ablate` generalises this across a target's whole control set: it
toggles each safeguard and reports which are **load-bearing**, which are
**security-theater** (the attack fires with or without them), and — with
`--redundancy` — which are **redundant** (another control already covers the
weakness).

### Holding under an adaptive attacker

`validate --prove-control --adaptive` drives the *guarded* leg under the
[adaptive loop](concepts.md#adaptive-attacks-and-tool-chaining-synthesis), with
the active control fed to the strategist so it crafts injections to evade *that
specific* defense. The verdict then separates a control that **holds under
adaptive pressure** from one that **holds against static probes but falls to an
adaptive attacker** — grading control *robustness*, which a single-shot check
can't see.

## The bundled reference twin

The bundled **reference agent** — [the Quarry](quarry.md)'s `mcp_kitchen_sink`
server in its vulnerable and guarded variants — remains the ground-truth twin
for the seeded-vulnerability differential, which is why importing the testkit
transitively imports the reference adapter. The machinery — differential,
flakiness, mutation score, honest-fail gate, control-efficacy oracle — is the
part that generalises to a consumer-owned agent (via `--target-file` and the
synthetic guarded twin); the bundled twin is the ground truth it is proven
against.
