# Attack modes

Mylonite runs a single-shot attack engine that exercises the four
[weakness classes](weakness-classes.md) (W1–W4) and feeds the
[validation oracle](validation.md) — the part that actually carries Mylonite's value.

---

## Single-shot (the engine)

For each applicable attack pattern, the engine customises a payload, invokes the target once,
and judges the result. The engine itself supports a **scan-time flakiness filter**
(`ScanEngineConfig.runs`): with `runs > 1` a payload only counts as a finding if it fires in
a strict majority of runs, rejecting a one-in-N fluke — but the `scan` CLI does not currently
expose this as a flag, so it always runs with `runs=1`. The flakiness filter you *will* hit
from the CLI is `validate`'s 5-iteration default (see [The validation engine](validation.md)).

This is the fast, deterministic baseline and what `gate` uses by default. It's all you
need when the target follows injected instructions readily. Source:
`mylonite.scan.engine.ScanEngine`.

```bash
mylonite scan reference:vulnerable
```

---

## Why the probes look innocuous

A synthesised payload is written to read as a **routine operation**, not as an attack.
The W3 egress probe asks the agent to fetch a plausible third-party endpoint; the W4
probe is a plain operational request; the black-box W2 document embeds its instruction
in an ordinary-looking retention note.

That is deliberate, and it is the difference between measuring your target and measuring
the planner's content filter. A payload that names `attacker.example.com/exfil` or opens
with `IMPORTANT SYSTEM INSTRUCTION` is declined by an aligned model on sight — which
tells you nothing about whether your server enforces anything. Published tool-poisoning
research reports substantial attack-success rates against production agents on live MCP
servers precisely because the malicious action is dressed as legitimate tool use.

Two things are deliberately *not* softened:

- **The judge's context still names the attack plainly.** Only the payload needs to look
  routine; blunting the judge would trade one false-negative source for another.
- **Probe destinations are RFC 2606 reserved** (`.example.net` / `.example.com`) and
  therefore non-routable, so a probe can never leave your lab. Being outside any sane
  allowlist is what makes the egress probe valid; looking innocuous is what stops it
  being refused before your server is ever asked.

The bundled reference seeds keep their historical literals — those are load-bearing for
the committed replay fixtures the offline gate uses.

## How many probes you get

Synthesis is bounded per weakness class, and the ceiling **scales with the number of
tools your target exposes**. Every probe costs roughly a customiser call, a few planner
turns and a judge call, all drawn from one scan-wide `--max-llm-calls` budget, so an
unbounded fan-out on a large surface would exhaust the budget and starve later seeds.

If the ceiling drops any candidates, the scan says so and names the tools it did not
probe. Raise `--max-llm-calls` and re-run, or name the tools that matter in the target
file's `control_config`, to cover them. A capped run never reads as a fully-probed one.

---

## Composing the model roles

The scan honours Mylonite's **three model roles** — set them independently to make
the test realistic:

- `--planner-model` — the agent under test. An *aligned* model refuses injection even
  on a vulnerable target, hiding the weakness; point this at a representatively
  exploitable model so the class stays testable.
- `--customiser-model` — the attacker (payload crafting).
- `--judge-model` — the verdict (only when the deterministic predicate is inconclusive).

```bash
mylonite scan --target-file app.yaml --authorize my-app \
  --planner-model claude-haiku-4-5 --customiser-model claude-sonnet-4-6
```

---

## Limitations (read this)

The single-shot engine is not a guarantee of exhaustive attack discovery. The
**validation oracle is the core differentiator — not attack cleverness.** One honest limit:

- **The attacker is an aligned model, so it under-explores injection.** The payload
  crafter (`--customiser-model`) is itself a safety-aligned LLM. Against an
  obviously-malicious goal it may **decline to craft a more effective payload**. When
  that happens the attempt is reported as **skipped (attacker refusal)** with the reason
  *"alignment refusal … NOT evidence the target is safe"* — never as a clean pass. This
  is a tooling ceiling: do not read a refusal as a secure target, and bring your own
  payload corpus when you need to push harder. Mylonite will not jailbreak its own
  attacker.
