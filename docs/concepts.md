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
technical one: the validation engine below only has discriminating power where
behaviour is non-deterministic, which is exactly the AI layer.

## What "validated regression test" means

A *scan* that produces a report tells you what was wrong yesterday. A
*regression test* in your repo tells you what cannot regress tomorrow.
Mylonite's intended primary artefact is the latter — a committed, gating
test that fails if a future code change reintroduces the same weakness.

The hard part is proving the test is meaningful, not just plausible.

## The validation engine

The validation engine layers four mechanisms:

1. **Build / collect** — the generated test must compile and run.
2. **Differential oracle** — the generated test must FAIL against an
   *unguarded* variant of the target *and* PASS against the *guarded*
   variant. This is what proves the test *means* what it claims; without it
   you can't tell "found a real weakness" from "asserted something trivially
   true." On a real single-build app the
   [control-efficacy check](#control-efficacy-which-safeguard-is-load-bearing)
   below produces this differential by toggling the safeguard; the bundled
   reference app produces it directly (two builds).
3. **Repeat-run filter** — LLM stochasticity makes single-run evidence weak.
   The differential is repeated (five iterations by default, three under `gate`)
   and judged on rates: a success-rate gap of at least 50%, no leak at all on the
   guarded build, and the guarded build having *positively resisted* on at least
   60% of runs. See [the validation engine](validation.md) for the full set.
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

This is the headline validation mechanism — the **control-efficacy check**, and
the core differentiator. A customer app has **one** build, so the classic two-build
differential (fail-on-vulnerable, pass-on-guarded) only applies to the bundled reference
app. The control-efficacy check generalises the idea to *any* single-build MCP app: it
**holds the model constant and varies only the safeguard**, synthesizing a *guarded
build* of any real target by applying a canonical control (W1–W4) at the adapter
boundary, then keeps a finding only when the attack fires on the raw target and is
resisted with the control applied — proving the *control*, not the model's current
behaviour, carries the security. For a real (`--target-file`) target this differential
runs **by default** in `validate`/`gate` (`--fast` skips it); `mylonite ablate` (hidden
and experimental — see [docs/experimental.md](experimental.md)) scores the whole control
set as load-bearing / theater / redundant. The plant and effect probe
always bypass the boundary shim, so
the control is measured against an undiluted attack. Full treatment in
[the validation engine](validation.md#the-control-efficacy-check).

### When the controls live in the server, not the adapter

The boundary shim synthesizes a guarded build by guarding the *planner's view* —
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
  **unguarded** variant. `validate` uses it as the raw side of its differential —
  on its own it changes only the raw side; the guarded side stays Mylonite's
  boundary shim. Declaring `control_env` for the weakness is what makes the
  guarded side your server's own guard, and that is what earns the
  server-layer claim.

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

### Add a kill switch to your own guard

`control_env` only works if your server actually reads the variable and turns
the guard off when it's set. That's a small, deliberate change to your code —
not a target-file setting Mylonite can apply for you. Until you make it,
Mylonite's control-efficacy check runs against its own boundary stand-in: a
canonical W1–W4 control it applies at the adapter layer, between your server
and the planner. That proves the attack is real and that *this kind* of
control closes it. It does not prove **your** implementation is what's holding
— for that, Mylonite has to be able to switch your guard off and on itself.

The change is the same shape in any language: read one environment variable,
once, at the point your guard would otherwise run, and skip it when the
variable is set.

**Python** (an illustrative data-marking guard, the same shape as the boundary
stand-in's own `quarantine()` — see
[`mylonite.scan._control_primitives`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/scan/_control_primitives.py)):

```python
import os

DISABLE_DATA_MARKING = os.environ.get("DISABLE_DATA_MARKING") == "1"


def quarantine(content: str, *, source: str) -> str:
    """Mark content read from an untrusted source so a later turn can refuse
    to act on it. The guard Mylonite's control-efficacy check is proving."""
    if DISABLE_DATA_MARKING:
        return content  # kill switch: behave exactly like the unguarded build
    return f"<untrusted source={source}>{content}</untrusted>"
```

**TypeScript** (an MCP server built on `@modelcontextprotocol/sdk`):

```typescript
const disableDataMarking = process.env.DISABLE_DATA_MARKING === "1";

function quarantine(content: string, source: string): string {
  if (disableDataMarking) {
    return content; // kill switch: behave exactly like the unguarded build
  }
  return `<untrusted source="${source}">${content}</untrusted>`;
}
```

Then declare the same variable in your target file, scoped to the weakness
class it disables:

```yaml
control_env:
  W2: { DISABLE_DATA_MARKING: "1" }
```

With that in place, `mylonite validate` / `gate` / `ablate` launch your server
twice — once with the variable set (your guard off) and once without (your
guard on) — and the kept finding's claim upgrades from "a canonical control of
this class stops the attack" to **"your own control is load-bearing"** — the
only claim surface that earns that wording (see
[Which claim you earned](reading-results.md#which-claim-you-earned)). The same
toggle is what `testkit.assert_control_holds` re-drives in the committed gate
test — see [the testkit API](testkit.md#assert_control_holds-live-the-control-efficacy-gate).

A kill switch is a test-time escape hatch, not a runtime feature: gate it
behind an environment variable nothing in production sets, keep it out of your
default config, and never let a request header or user input reach it.

## Built to extend

Everything above is reached through five versioned extension contracts — attack
module, target adapter, test generator, validator, and compliance mapper — shipped as
stable `Protocol`s with JSON schemas, reference implementations, and entry-point-based
plugin loading. The bundled threat taxonomy (OWASP LLM Top 10 2025, OWASP Agentic
Security Initiative 2026, MITRE ATLAS `v2026.05`, NIST AI RMF) and the
deliberately-vulnerable reference agent are part of that foundation. To add a target
type, an attack class, a test framework, or a compliance mapping, see
[Plugin authoring](plugin-authoring.md) and the [architecture map](architecture.md).
