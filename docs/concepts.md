# Concepts

## The AI attack surface — and why it's the right scope

Most apps today are *hybrids*: a traditional codebase with an AI/agentic
layer bolted on. Tomorrow's apps are AI-native: the AI/agentic layer is the
whole product. Either way, the unit Mylonite targets is the same:

- the **system prompt** the agent runs under,
- the **tool / function schemas** it can call,
- the **RAG pipeline** that feeds it untrusted data,
- the **agent planner and memory** that decide what to do next.

Mylonite stops at that boundary. Traditional code paths — auth, billing,
SQL — are ceded to SAST/DAST tools. This is both a market choice and a
technical one: the validation-engine moat below has power only where
behaviour is non-deterministic, which is exactly the AI layer.

## What "validated regression test" means

A *scan* that produces a report tells you what was wrong yesterday. A
*regression test* in your repo tells you what cannot regress tomorrow.
Mylonite's intended primary artefact is the latter — a committed, gating
test that fails if a future code change reintroduces the same weakness.

The hard part is proving the test is meaningful, not just plausible.

## The validation engine — Mylonite's moat

The validation engine that lands in Phase 2 layers four mechanisms:

1. **Build / collect** — the generated test must compile and run.
2. **Differential seeded-vulnerability oracle** — the generated test must
   FAIL against a deliberately-unguarded variant of the target *and* PASS
   against the guarded variant. This is what proves the test *means* what
   it claims; without it you can't tell "found a real weakness" from
   "asserted something trivially true."
3. **Flakiness filter (5 runs)** — LLM stochasticity makes single-run
   evidence weak. Tests are kept only if they hold across at least five
   repeated runs.
4. **Metamorphic robustness** — the same exploit, paraphrased / re-encoded
   / lowered in case, must still fail on the vulnerable variant. This
   catches brittle, over-fit tests.

Phase 0 ships the contracts, the bundled threat taxonomy, and the
**vulnerable reference MCP agent** under
[`reference_targets/mcp_kitchen_sink/`](https://github.com/Abidemialade/mylonite/tree/main/reference_targets/mcp_kitchen_sink)
that the differential oracle will use as its ground truth.

## Adaptive attacks and tool-chaining synthesis

The default scan is single-shot per seed. Two **opt-in** modes deepen it — same
AI-layer scope, same differential-validation bar, more app-specific reach. Both
need a session-capable target (e.g. the bundled `reference:*` twins) and leave
the single-shot path unchanged when off.

- **`--adaptive` (the adaptive loop).** When an indirect-injection attempt does
  not fire — typically an aligned planner refusing a poisoned note — an LLM
  strategist re-crafts the *injection* from the planner trace and the judge's
  reason, then retries against a fresh session within an attempt budget. It
  auto-discovers how to plant and drive from the target's own tool surface, so a
  single-shot miss can still become a finding.

- **`--synthesize` (tool-chaining synthesis).** Synthesizes an exploit that
  requires *combining several of the target's own tools* to reach a harmful sink
  (e.g. `read_note → send_email`) — the app-specific depth a generic probe
  library can't reach, because it doesn't know your tool graph. The chain is
  executed (single drive first, then multi-turn steering if needed) and only
  counts as a finding if it **differentially validates**: the sink is reached on
  the vulnerable twin and blocked on the guarded twin, across the flakiness
  filter. A validated chain emits a replay-backed regression test.

Both reuse the same moat below — a finding is never "the agent did something,"
only "a weakness that fires on the vulnerable variant and is blocked on the
guarded one."

## Where Phase 0 stopped

Phase 0 was foundations only. What it put in place:

- Five versioned extension contracts (attack module, target adapter, test
  generator, validator, compliance mapper).
- A bundled threat taxonomy: OWASP LLM Top 10 (2025), OWASP Agentic
  Security Initiative (2026), MITRE ATLAS (`v2026.05`), NIST AI RMF.
- The deliberately-vulnerable reference MCP agent and its guarded twin.
- OSS scaffolding.

What Phase 0 deliberately left to later phases:

- The LLM-driven exploit-finding agent (Phase 1 — **since delivered**: the
  scan loop works today; see the [Quickstart](quickstart.md)).
- A real (non-stub) pytest generator (Phase 1).
- The differential-oracle validator (Phase 2).
- A GitHub Action that opens a PR with a committed test (Phase 3).
- A community attack-pattern registry (Phase 4).
- More target adapters (RAG, custom HTTP) and a jest generator (Phase 5).
- Audit-evidence packs (Phase 6).
