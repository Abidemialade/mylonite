# Keystone: land ONE real external differential (handoff)

> **The goal.** The moat's strongest proof is a single committed regression test built
> from a **non-self-seeded** target — one Mylonite did *not* author — that **fires on the
> unguarded app, is resisted once the control is applied, holds across the 5-run flakiness
> gate, and emits a validated test**. The in-repo reference twins already prove this; this
> is about proving it on third-party ground truth (DVMCP).

> **Why it isn't done in-session.** It needs (a) DVMCP challenge servers *running*, (b) a
> live LLM key, and critically (c) a planner model that actually *falls* for the attack —
> Claude Haiku 4.5 resisted all 8 in-scope challenges (recall 0/8), so a robust model
> yields no positive to differentiate. Plus the usual local friction (git TLS, Norton). So
> this is a maintainer-run step. Everything below is the exact recipe.

## Prerequisites

- An LLM API key (`ANTHROPIC_API_KEY`, or another provider for the weaker-model path).
- `git` working (this machine: prepend `git -c http.sslBackend=schannel` — `fetch.py`
  already does this when cloning DVMCP).
- DVMCP ships **no LICENSE file**, so the fetch is opt-in (`--include-unlicensed`); it is
  cloned at a pinned commit and never vendored.

## Path A — control-efficacy oracle on a DVMCP app-flaw challenge (preferred)

This holds the model constant and varies only the safeguard (the control-shim differential),
so it doesn't depend on a weaker model — *provided* the challenge's harmful action lands
without the model having to "agree to overreach" (an app-flaw, like the reference W4).

```powershell
$env:ANTHROPIC_API_KEY = "sk-..."
$env:PYTHONUTF8 = "1"

# 1. clone DVMCP at the pinned commit (no LICENSE -> explicit opt-in)
python -m verification.runner layer1 fetch --include-unlicensed

# 2. start the in-scope challenge servers (DVMCP's Dockerfile, or `python server.py`
#    per challenge dir). SSE ports are 9000 + N. Start an app-flaw challenge first
#    (e.g. c3 file_manager / an unconfirmed-action challenge).

# 3. emit a Mylonite target.yaml per in-scope challenge (reads each port from server.py)
python -m verification.runner layer1 emit-targets

# 4. prove the control carries security on ONE challenge (differential-by-default):
mylonite validate --target-file verification/.cache/dvmcp/targets/c3.yaml `
    --authorize dvmcp-c3 --iterations 5

# 5. if it KEPT, the emitted test under .mylonite/ IS the keystone artifact. Commit it.
```

Success = `validate` reports **KEPT**: the attack fired on the raw target and was resisted
with the control across 5/5 runs. That committed test is the external keystone.

## Path B — manufacture a positive with a weaker planner, then prove the guard closes it

If every robust-model attack resists (DVMCP recall 0), use a weaker/older planner *only to
produce a positive*, then show the control closes it. The differential still holds the
(weak) model constant across raw-vs-guarded, so the proof is about the control, not the
model.

```powershell
# Point the PLANNER (agent-under-test) at a weaker model; keep judge/customiser strong.
mylonite scan --target-file verification/.cache/dvmcp/targets/c6.yaml `
    --authorize dvmcp-c6 --planner-model <weaker-or-older-model>
mylonite generate --latest --out .mylonite/generated/keystone
mylonite validate .mylonite/generated/keystone `
    --target-file verification/.cache/dvmcp/targets/c6.yaml --iterations 5
```

`--planner-model` needs a model that is representatively exploitable (an older/smaller model
or a non-Claude provider key). The InjecAgent `record --elicit-positives` mode is the
analogous lever for the benchmark side, but note it produced 0/15 even on Haiku — pick a
genuinely weaker model.

## What to record when it lands

Update [`FINDINGS.md`](FINDINGS.md) (the "Layer 1 — DVMCP recall" section) with the
challenge, the model, and the differential result, and commit the emitted test. That single
external differential converts the keystone from "proven on our own twins" to "proven on a
target we didn't author" — the strongest version of the moat claim.

## Caveats

- Run DVMCP only with explicit authorization — it is a deliberately-vulnerable external
  server. Layer 1 is intentionally **excluded** from the scheduled CI workflow for this
  reason.
- Samples are small and cost-bounded; one KEPT external differential is the milestone, not
  a leaderboard number.
