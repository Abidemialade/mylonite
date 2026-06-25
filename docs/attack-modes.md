# Attack modes

Mylonite runs a single-shot attack engine that exercises the four
[weakness classes](weakness-classes.md) (W1–W4) and feeds the
[validation oracle](validation.md) — the part that actually carries Mylonite's value.

---

## Single-shot (the engine)

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

## Composing the model roles

The scan honours Mylonite's **three model roles** — set them independently to make
the test realistic:

- `--planner-model` — the agent under test. An *aligned* model refuses injection even
  on a vulnerable target, hiding the weakness; point this at a representatively
  exploitable model so the class stays testable.
- `--customiser-model` — the attacker (payload crafting).
- `--judge-model` — the verdict (only when the deterministic predicate is inconclusive).

```bash
mylonite scan --target-file app.yaml --authorize me \
  --planner-model claude-haiku-4-5 --customiser-model claude-sonnet-4-6
```

---

## Limitations (read this)

The single-shot engine is not a guarantee of exhaustive attack discovery. The
**validation oracle is the moat — not attack cleverness.** One honest limit:

- **The attacker is an aligned model, so it under-explores injection.** The payload
  crafter (`--customiser-model`) is itself a safety-aligned LLM. Against an
  obviously-malicious goal it may **decline to craft a more effective payload**. When
  that happens the attempt is reported as **skipped (attacker refusal)** with the reason
  *"alignment refusal … NOT evidence the target is safe"* — never as a clean pass. This
  is a tooling ceiling: do not read a refusal as a secure target, and bring your own
  payload corpus when you need to push harder. Mylonite will not jailbreak its own
  attacker.
