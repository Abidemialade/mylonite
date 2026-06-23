# Attack modes

Mylonite has one default attack engine and three opt-in deepening modes. All four
exercise the same four [weakness classes](weakness-classes.md) and feed the same
[validation oracle](validation.md) — they differ in *how hard they push*.

| Mode | Flag | What it adds | When to use it |
|------|------|--------------|----------------|
| Single-shot | *(default)* | One crafted attempt per seed | Baseline; fast; the CI-gating default |
| Adaptive | `--adaptive` | A strategist re-crafts the injection on failure | An aligned planner that resists the first try |
| Synthesis | `--synthesize` | Chains 2+ of the target's own tools to a sink | App-specific multi-step exploits |
| Memory poisoning | `--memory` | Plant → persist → retrieve across turns | The cross-session "zombie agent" threat |

---

## Single-shot (the default)

For each applicable seed, the engine customises a payload, invokes the target once,
and judges the result. With `--runs > 1` it applies a **scan-time flakiness filter**:
a payload only counts as a finding if it fires in a strict majority of runs, rejecting
a one-in-N fluke.

This is the fast, deterministic baseline and what `gate` uses by default. It's all you
need when the target follows injected instructions readily. Source:
`mylonite.scan.engine.ScanEngine`.

```bash
mylonite scan reference:vulnerable
```

---

## Adaptive

*The strategist refinement loop.*

`--adaptive` turns a single failed attempt into a **conversation with a red-team
strategist**. When an indirect-injection seed doesn't fire — typically because an
*aligned* planner refused the poisoned note — an LLM strategist inspects the planner's
trace and the judge's reason, **re-crafts the injection body**, and retries against a
fresh session, within a budget (default 4 attempts).

The loop carries its learning across attempts: each refinement is informed by why the
last one failed. With `--verbose-strategist` you can watch each round live (the
injection tried, the planner's tool calls, why it failed) — payloads are redacted
before display.

This matters because a one-shot test under-reports a class that a determined attacker
*would* eventually land. When a control is in force, the strategist can even be told
which defense is active so it crafts payloads to evade *that specific* control —
grading control robustness, not just presence. Source:
`mylonite.scan.attack_loop.AdaptiveAttackDriver`.

```bash
mylonite scan reference:vulnerable --adaptive --verbose-strategist
```

> The loop **auto-discovers** how to plant and retrieve from the target's tool surface
> (`discover_attack_plan`) — it finds a content-storing tool, mints an id into it, and
> drives a retrieval that surfaces the planted content back to the planner. On a custom
> target this is what lets indirect injection work with near-zero configuration.

---

## Synthesis

*App-specific tool-chaining.*

A real agent's most interesting weaknesses aren't single tool calls — they're
*chains*: read a note → follow its instruction → fetch a URL → exfiltrate. `--synthesize`
discovers these. It inspects the target's tool surface, identifies a **plantable
source** (a note/issue/file store) and a **harmful sink** (send_email, web_fetch,
write_file), synthesizes a chain that connects them, and then **differentially
validates** the whole chain against the twins — a chain is a finding only if it reaches
the sink on the vulnerable twin and is blocked on the guarded one.

This is the difference between "your `send_email` tool can be abused" and "here is the
exact 3-tool sequence, starting from a note an attacker can plant, that reaches
`send_email` — and here's the regression test for it." Source:
`mylonite.scan.chain_synth` / `chain_driver` / `chain_validator` /
`synthesis_runner`. Reference-twin targets first; a custom `--target-file` uses the
synthetic guarded twin.

```bash
mylonite scan reference:vulnerable --synthesize
```

---

## Memory poisoning

*The cross-turn shape.*

Single-turn tests plant and retrieve in one breath. The real-world threat is slower and
nastier: poison is planted **once**, persists in the agent's store across unrelated
turns, and is retrieved and acted on in a **later, innocent** turn — the
"**zombie agent**" / cross-session slow-drip. The agent has effectively "forgotten" the
content is attacker-controlled.

`--memory` models exactly this over one persistent session:

1. **Turn 1 — plant.** The attacker stores poisoned content (a raw tool call).
2. **Intervening benign turns.** The agent does normal work; the poison lies dormant.
3. **Final turn — retrieve + act.** An innocent request surfaces the dormant poison and
   the agent acts on it.

It is the **same differential moat** applied to memory poisoning: the attack fires on
the vulnerable twin and is resisted on the guarded one (whose `UntrustedEnvelopeControl`
quarantines the *recalled* memory). It also confirms the poison actually resurfaced in
the retrieval turn (`cross_turn_delivered`) — so a non-delivery reads as **NOT TESTED**,
never as a false clean pass. Source: `mylonite.scan.memory_poison`
(`MemoryPoisoningDriver` / `MemoryPoisonValidator` / `MemoryPoisonRunner`).

```bash
mylonite scan reference:vulnerable --memory
# or against your app's synthetic W2-guarded twin:
mylonite scan --target-file app.yaml --authorize me --memory
```

> `--synthesize` and `--memory` are distinct flows and mutually exclusive — pass only
> one. Both are reference-twin-first; custom targets use the synthetic guarded twin.

---

## Composing modes with the model roles

Every mode honours Mylonite's **three model roles** — set them independently to make
the test realistic:

- `--planner-model` — the agent under test. An *aligned* model refuses injection even
  on a vulnerable target, hiding the weakness; point this at a representatively
  exploitable model so the class stays testable.
- `--customiser-model` — the attacker (payload crafting + the adaptive strategist).
- `--judge-model` — the verdict (only when the deterministic predicate is inconclusive).

```bash
mylonite scan --target-file app.yaml --authorize me \
  --planner-model claude-haiku-4-5 --customiser-model claude-sonnet-4-6 --adaptive
```

---

## Limitations (read this)

These modes deepen coverage; they are not a guarantee of exhaustive attack discovery.
The **validation oracle is the moat — not attack cleverness.** Two honest limits:

- **The attacker is an aligned model, so it under-explores injection.** The strategist
  (`--customiser-model`) is itself a safety-aligned LLM. Against an obviously-malicious
  goal it may **decline to craft a more effective payload**. When that happens the
  adaptive loop aborts and the attempt is reported as **skipped (attacker refusal)** with
  the reason *"alignment refusal … NOT evidence the target is safe"* — never as a clean
  pass. This is a tooling ceiling: do not read a refusal as a secure target, and bring
  your own payload corpus when you need to push harder. Mylonite will not jailbreak its
  own attacker.

- **`--synthesize` / `--memory` need a real surface, and say so when it's missing.** They
  discover a plant + sink (synthesis) or plant + recall (memory) from the tool surface.
  When the surface exposes none — and you haven't declared a `seed_arm` /
  `control_config.consequential_tools` to point them at the right tools — the run reports
  **NOT TESTED** (a non-zero exit), never a clean `no_finding`. Declare those fields in
  your [`target.yaml`](target-file.md) to exercise an app whose tool names don't match
  the discovery heuristics.
