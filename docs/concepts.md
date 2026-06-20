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

The default scan is single-shot per seed. Three **opt-in** modes deepen it —
same AI-layer scope, same differential-validation bar, more app-specific reach.
All need a session-capable target; both the bundled `reference:*` twins and
**real MCP targets** (`--target-file`, via stateful stdio sessions) qualify.
They leave the single-shot path unchanged when off.

- **`--adaptive` (the adaptive loop).** When an indirect-injection attempt does
  not fire — typically an aligned planner refusing a poisoned note — an LLM
  strategist re-crafts the *injection* from the planner trace and the judge's
  reason, then retries against a fresh session within an attempt budget. It
  auto-discovers how to plant and drive from the target's own tool surface, so a
  single-shot miss can still become a finding. Runs on real MCP targets, not
  just the reference twins.

- **`--synthesize` (tool-chaining synthesis).** Synthesizes an exploit that
  requires *combining several of the target's own tools* to reach a harmful sink
  (e.g. `read_note → send_email`) — the app-specific depth a generic probe
  library can't reach, because it doesn't know your tool graph. The chain is
  executed (single drive first, then effect-trace-aware multi-turn steering if
  needed) and only counts as a finding if it **differentially validates**: the
  sink is reached on the raw target and blocked on the guarded twin, across the
  flakiness filter. Works against `--target-file` custom targets via the
  synthetic guarded twin. A validated chain emits a replay-backed regression
  test.

- **`--memory` (stateful memory poisoning).** Models the cross-session
  "zombie agent" shape single-turn scans miss: poison is planted *once*, persists
  across unrelated turns, and is retrieved and acted on a *later* turn. Same
  differential bar — fires on the vulnerable twin, resisted on the guarded one whose
  control quarantines the *recalled* memory — and it confirms the poison actually
  resurfaced (else NOT TESTED, never a false clean). See [Attack modes](attack-modes.md).

All reuse the same moat below — a finding is never "the agent did something,"
only "a weakness that fires on the raw/vulnerable variant and is blocked on the
guarded one."

> The real-world evasion encodings (zero-width / split / multilingual) that used to be a
> standalone, report-only `--obfuscate` tier are now folded into the **gating**
> metamorphic layer of the oracle (see [The validation engine](validation.md)), so a
> *kept* test must survive re-encoding — not merely report on it.

## Control efficacy — which safeguard is load-bearing?

On a real target you don't ship two builds of, the question shifts from "is
there a weakness?" to "which safeguard is actually carrying the security, and
does it hold?" Mylonite answers it by **holding the model constant and varying
only the safeguard**: it synthesizes a *guarded twin* of any real target by
applying a canonical control (W1–W4) at the adapter boundary, then keeps a
finding only when the attack fires on the raw target and is resisted with the
control applied. For a real (`--target-file`) target this differential runs **by
default** in `validate`/`gate`, proving the control load-bearing (add `--adaptive` to
grade whether it survives an adaptive attacker; `--prove-control` is a back-compat
no-op, `--fast` skips it);
`mylonite ablate` scores the whole control set as load-bearing / theater /
redundant. The plant and effect probe always bypass the boundary shim, so the
control is measured against an undiluted attack. Full treatment in
[the validation engine](validation.md#beyond-the-bundled-twin-the-control-efficacy-oracle).

### When the controls live in the server, not the adapter

The boundary shim synthesizes a guarded twin by guarding the *planner's view* —
which works when Mylonite can add the control. But many real MCP apps bake their
guards into the **server itself**, toggled by an env var or a security profile
(e.g. `SECURITY_PROFILE=strict`). The shim can't strip a guard it doesn't own, so
its "raw" side would still be fully guarded — and ablation would (correctly but
uselessly) classify every control `no-attack`, because the attack never fires on
the raw side.

For those targets, declare in your target file **how to run the server with its
guards off**, and Mylonite drives a genuinely raw side:

- `control_env` — a per-weakness map of env vars that *disable* one server-layer
  guard. `mylonite ablate` uses it to toggle controls individually: the raw side
  disables all of them; the "only control C" side leaves just C on. This restores
  per-control load-bearing/theater attribution on a server-layer architecture.
- `vulnerable_launch` — an alternate `command`/`args`/`env` that starts a fully
  **unguarded** variant. `validate --prove-control` and `scan --synthesize` use it
  as the raw side of their differential.

```yaml
family: my-agent
command: python
args: [-m, my_agent.server]
weakness_classes: [W2, W4]
# Per-control env toggles (ablation): each disables ONE server guard.
control_env:
  W2: { DISABLE_DATA_MARKING: "1" }
  W4: { AUTONOMY_OVERRIDE: "full" }
# Or a single fully-unguarded launch (prove-control / synthesize):
vulnerable_launch:
  env: { SECURITY_PROFILE: "off" }
```

Both fields are optional and additive: omit them and behaviour is exactly as
before. Launching a deliberately-unguarded server is a real action — it is gated
by `--authorize`, announced loudly, and env **values are never logged** (they may
carry secrets). If a declared raw launch doesn't actually disable the guard, the
raw side simply never fires and Mylonite says so rather than reporting a wrong
verdict.

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
