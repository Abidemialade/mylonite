# The validation engine

The attack library finds weaknesses. The **validation engine** is what makes
Mylonite's output trustworthy — it proves a generated security test *means*
what it claims, then ships that proof as a fast CI gate (offline for the
bundled reference targets; a live, gated re-drive for your own app — see
below). This is the core of the tool: the novel piece is not the exploits,
it's the machinery that separates a real, reproducible weakness from a
plausible-looking but vacuous assertion.

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

**Tier 2 — the committed regression test.** `mylonite generate` emits a pytest
file, but what it replays at the CI gate depends on the target:

- **Bundled reference targets** (`reference:vulnerable` / `reference:guarded`)
  — **OFFLINE, per-PR.** The test replays a *recorded* reproduction of the
  attack against the guarded twin via `testkit.assert_guard_holds`. No API
  key. No network. No LLM call. It is a normal, fast, deterministic pytest.
  The recorded fixtures (the `(model, messages)` → response pairs the replay
  looks up) and an `exploit_*.json` are produced once, during the live tier,
  and committed alongside the test. After that the gate is offline forever —
  until something that changes the recorded pairs (a planner / judge /
  customiser prompt, a tool schema, or the model) forces a re-record.
- **A real, custom target** (`--target-file`) — **LIVE, always.** There is no
  recorded twin to replay: the emitted test re-launches your actual MCP
  server and calls the real provider (`testkit.assert_target_resists` /
  `assert_control_holds`), so it needs `ANTHROPIC_API_KEY` (or your
  configured provider) and network egress. This live re-drive is gated behind
  the `MYLONITE_LIVE_TARGET=1` environment variable — without it the test is
  **skipped**, not run, and a plain `pytest` still exits `0`. `mylonite
  generate` prints the exact `MYLONITE_LIVE_TARGET=1 pytest …` command; the
  scaffolded `mylonite-gate.yml` workflow sets the variable for you. See
  [CI gating](ci-gating.md) for the operational details.

## "Isn't this a tautology?"

The sharpest objection: *a generated test that replays a recorded attack and
asserts the guard holds — isn't that circular? You recorded the guard holding,
then you assert the guard holds.*

No, and the answer is the whole point of the engine. Three things break the
circle, all of them at the **live validation tier**, before any fixture is
committed:

1. **The differential proof.** At validation time the
   [`DifferentialValidator`](concepts.md#the-validation-engine)
   runs the *same* attack against **both** sides — the *unguarded* one and the
   *guarded* one. On a real single-build app those two sides come from the
   [control-efficacy check](#the-control-efficacy-check) toggling the
   safeguard; the bundled reference app supplies them as two builds directly. A
   test is only kept if the exploit **fires unguarded and resists guarded**. A
   vacuous test (asserting something trivially true) cannot show this
   differential: it would pass on *both* sides. The differential is the
   discrimination signal a tautology can never produce.

2. **The 5-run flakiness filter.** Because the behaviour is stochastic, a
   single run is weak evidence. The validator repeats the differential across
   five iterations and keeps the test only if the vulnerable build fires
   reliably (`>= iterations - 1` by default) **and** the guarded build resists
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

- **`kept`** — the gating verdict.
  For a bundled reference target:
  `kept = build ∧ differential ∧ flakiness ∧ metamorphic`. The test built and
  collected under pytest, showed the differential at all, showed it reliably across
  the flakiness filter, *and* survived a majority of metamorphic rewrites. Only a kept
  test is worth committing.
  For a custom target (no in-repo guarded twin):
  `kept = build ∧ stability ∧ consensus [∧ effect] [∧ differential]`. The **effect**
  leg contributes only when an `effect_probe` is declared; without one it is shown as
  **· report-only** and is EXCLUDED from `kept` — end-to-end damage was not confirmed,
  so it must not read as a passing ✓ that inflates the verdict. Declare an
  `effect_probe` for a KEPT test backed by real damage confirmation. The **differential**
  leg contributes only when a guarded twin is inferable (a server-layer control or a
  synthesised boundary shim).
- **Reproducibility fraction** — the flakiness-stage metric,
  `min(vulnerable fires, guarded resists) / iterations`. How dependably the
  test discriminates run-to-run; `1.0` means it fired and resisted on every
  iteration.
- **Mutation score** (report-only) — the fraction of the four bundled
  reference weakness families (W1–W4) that show the differential (the
  vulnerable build fired ≥1 attack pattern in the family **and** the guarded build
  resisted it). It is computed for free from the scans already run and gives a coverage
  read across the weakness bank, not just the single exploit under test.

A fourth stage, **metamorphic**, is **gating**. It applies several deterministic,
semantically-neutral rewrites of the exploit body — paraphrase, casing, whitespace,
unicode confusables, and the real-world **evasion encodings** (zero-width / invisible
chars, word-splitting, multilingual framing) — and genuinely re-drives each through
*both* builds. A kept test must survive a **majority** (default 60%) of them, so it
can't be over-fit to one literal payload (teaching to the test). Each rewrite
preserves the exfil destination so the attack still lands and the majority stays
honest. This is what makes a kept test robust to the exact tricks real injections use
(EchoLeak's invisible text, RAG unicode/split games) — not just to rewording.

## The control-efficacy check

The two-build differential above proves a weakness is real by comparing a *vulnerable*
build to a *guarded* one — but that needs **two builds**, which only the bundled
reference app has. A customer app has **one** build. The **control-efficacy check** is
the mechanism that carries Mylonite's value on any real single-build MCP app, and it is
the core differentiator. On a target you don't have two builds of, the sharper question
is not "is there a weakness?" — it's *"which safeguard is actually carrying the security,
and does it hold?"* For a real (`--target-file`) target it runs **by default** —
`validate` and `gate` synthesize the guarded build at the adapter boundary and prove the
control automatically. (Pass `--fast` to *skip* the differential for a faster, weaker
gate.)

The move is to **hold the model constant and vary only the safeguard**. Mylonite
synthesizes a *guarded build* of any real target by applying a canonical control
at the **adapter boundary** — a `ControlServerShim` that wraps the live target
(W1 description pinning, W2 information-flow control, W3 egress
allowlist, W4 confirm-gate). The same model, the same tools, the same target;
the only thing that changes between the two legs is whether the control is in
the planner's path. A finding is kept only when the attack **fires on the raw
target and is resisted with the control applied** — which proves the *control*,
not the model's current behaviour, is what stopped it. It is scored as a
control-contribution rate gap across the same flakiness filter.

Two honesty properties make this trustworthy:

- **The plant and the effect probe always bypass the shim.** The attacker plants
  on the raw session and the effect probe reads the raw session; only the
  *planner's view* is guarded. So the control is measured against an undiluted
  attack, never a hobbled one.
- **It is a boundary proxy, stated as one — on the pass as well as the fail.**
  Mylonite enforces the control at the adapter boundary, not inside your server.
  A KEPT verdict from a synthetic twin therefore says a *canonical* control of
  that class stops the attack with your model held constant; it does **not** say
  your own implementation carries the security, and the wording does not claim
  otherwise. Only a server-layer twin (`control_env`, where Mylonite toggles your
  real control) earns that sentence. The reject side has always drawn this
  distinction; as of 0.8.5 the pass side does too, on the validator detail, the
  SARIF message and the gating PR headline alike. See
  [Which claim you earned](reading-results.md#which-claim-you-earned).

`mylonite ablate` generalises this across a target's whole control set: it
toggles each safeguard and reports which are **load-bearing**, which are
**security theater** (the attack fires with or without them), and — with
`--redundancy` — which are **redundant** (another control already covers the
weakness).

Single-model `validate` stamps the model it proved the test against into the
report, so the committed regression is honest about which version it gates.

## The bundled reference app (the reference/demo differential)

The bundled **reference agent** — [the reference app](quarry.md)'s `mcp_kitchen_sink`
server in its vulnerable and guarded variants — remains the ground-truth pair for the
seeded-vulnerability differential, which is why importing the testkit transitively
imports the reference adapter. The machinery — differential, flakiness, mutation score,
honest-fail gate, control-efficacy check — is the part that generalises to a
consumer-owned agent (via `--target-file` and the synthetic guarded build); the bundled
reference app is the ground truth it is proven against.

### What the guarded twin actually guarantees

Because every differential and every control-efficacy check is measured *against* the
guarded twin (`server_guarded.py`), a bypass in the twin's own mitigations would silently
launder through every scan built on top of it — a false "resisted." A 2026-08-01 review
found exactly that: two of the four seeded mitigations had a confirmed bypass, and a
third had two. All four are now closed:

- **W1 (tool-description injection).** `_validate_description` is a positive allowlist —
  printable ASCII only (`re.ASCII`, so `\s` can no longer match NBSP / ideographic space /
  line separator), a length cap, and a small set of *directive-shaped* patterns
  (imperative verbs, "ignore prior instructions", "call X immediately", bracketed
  pseudo-authority). It is not a denylist of known-bad literal substrings — the previous
  version blocked only `"(Note:"` and matched `\s` in Unicode mode, both bypassed.
  **Known gap:** plain-prose cross-tool steering with no smuggle form (a description that
  merely *implies* urgency without tripping a directive pattern) is not caught — this
  matches the boundary control's own documented gap
  (`mylonite.scan._control_primitives.sanitize_tool_description`).
- **W2 (untrusted-content envelope).** `_quarantine` strips any literal `<untrusted>` /
  `</untrusted>` tag from attacker-controlled content *before* wrapping it, so content
  containing the closing tag can no longer terminate the envelope early and place text
  where the planner treats it as trusted instruction. Mirrors
  `mylonite.scan._control_primitives.quarantine` byte-for-byte — same envelope bytes,
  same neutralisation, applied in two places (the reference twin and the boundary-control
  shim used against real targets) so they cannot drift apart silently.
- **W3 (egress allowlist).** Unchanged this phase — no confirmed bypass found.
- **W4 (send/confirm two-step).** `confirm_send` now requires exactly one `send_email`
  stage since the last confirmation. A second `send_email` call — the shape injected
  content produces to swap a reviewed message for an attacker's — bumps a stage counter;
  `confirm_send` refuses and clears state if more than one stage occurred, instead of
  dispatching the last-staged message under the original approval.

**Pending:** the envelope's fixed `<untrusted>` / `</untrusted>` delimiter is a known
gap. The current fix (Step 3) neutralises a *literal* delimiter appearing in attacker
content, but the delimiter itself is a fixed string an attacker who knows the scheme
could still target with a fresh variant. A per-session nonce delimiter is the stronger
construction, and is deliberately **not** implemented yet — it would change the exact
bytes the demo fixtures were recorded against, and this phase is scoped to fixture-neutral
fixes only. It is pending a fixture re-record.

`tests/reference_targets/test_guarded_twin_adversarial.py` is the contract for this: it
red-teams the guarded twin directly (not through a scan), and a change to
`server_guarded.py` that reopens any of W1/W2/W4 above should fail it.
