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

The validation engine layers four mechanisms:

1. **Build / collect** — the generated test must compile and run.
2. **Differential oracle** — the generated test must FAIL against an
   *unguarded* variant of the target *and* PASS against the *guarded*
   variant. This is what proves the test *means* what it claims; without it
   you can't tell "found a real weakness" from "asserted something trivially
   true." On a real single-build app the
   [control-efficacy oracle](#control-efficacy-which-safeguard-is-load-bearing)
   below produces this differential by toggling the safeguard; the bundled
   reference twins produce it directly (two builds).
3. **Flakiness filter (5 runs)** — LLM stochasticity makes single-run
   evidence weak. Tests are kept only if they hold across at least five
   repeated runs.
4. **Metamorphic robustness** — the same exploit, paraphrased / re-encoded
   / lowered in case, must still fail when the safeguard is off. This
   catches brittle, over-fit tests.

The framework ships the contracts, the bundled threat taxonomy, and the
**vulnerable reference MCP agent** under
[`reference_targets/mcp_kitchen_sink/`](https://github.com/Abidemialade/mylonite/tree/main/reference_targets/mcp_kitchen_sink)
that the reference differential uses as its ground truth.

> The real-world evasion encodings (zero-width / split / multilingual) that used to be a
> standalone, report-only `--obfuscate` tier are now folded into the **gating**
> metamorphic layer of the oracle (see [The validation engine](validation.md)), so a
> *kept* test must survive re-encoding — not merely report on it.

## Control efficacy — which safeguard is load-bearing?

This is the headline validation mechanism — the **control-efficacy oracle**, and
the moat. A customer app has **one** build, so the classic two-build differential
(fail-on-vulnerable, pass-on-guarded) only applies to the bundled reference twins.
The control-efficacy oracle generalises the idea to *any* single-build MCP app: it
**holds the model constant and varies only the safeguard**, synthesizing a *guarded
twin* of any real target by applying a canonical control (W1–W4) at the adapter
boundary, then keeps a finding only when the attack fires on the raw target and is
resisted with the control applied — proving the *control*, not the model's mood,
carries the security. For a real (`--target-file`) target this differential runs **by
default** in `validate`/`gate` (`--prove-control` is a back-compat no-op, `--fast`
skips it); `mylonite ablate` scores the whole control set as load-bearing / theater /
redundant. The plant and effect probe always bypass the boundary shim, so the
control is measured against an undiluted attack. Full treatment in
[the validation engine](validation.md#the-control-efficacy-oracle-the-moat).

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
  **unguarded** variant. `validate` uses it as the raw side of its differential.

```yaml
family: my-agent
command: python
args: [-m, my_agent.server]
weakness_classes: [W2, W4]
# Per-control env toggles (ablation): each disables ONE server guard.
control_env:
  W2: { DISABLE_DATA_MARKING: "1" }
  W4: { AUTONOMY_OVERRIDE: "full" }
# Or a single fully-unguarded launch (the raw side of the differential):
vulnerable_launch:
  env: { SECURITY_PROFILE: "off" }
```

Both fields are optional and additive: omit them and behaviour is exactly as
before. Launching a deliberately-unguarded server is a real action — it is gated
by `--authorize`, announced loudly, and env **values are never logged** (they may
carry secrets). If a declared raw launch doesn't actually disable the guard, the
raw side simply never fires and Mylonite says so rather than reporting a wrong
verdict.

## Built to extend

Everything above is reached through five versioned extension contracts — attack
module, target adapter, test generator, validator, and compliance mapper — shipped as
stable `Protocol`s with JSON schemas, reference implementations, and entry-point-based
plugin loading. The bundled threat taxonomy (OWASP LLM Top 10 2025, OWASP Agentic
Security Initiative 2026, MITRE ATLAS `v2026.05`, NIST AI RMF) and the
deliberately-vulnerable reference agent are part of that foundation. To add a target
type, an attack class, a test framework, or a compliance mapping, see
[Plugin authoring](plugin-authoring.md) and the [architecture map](architecture.md).
