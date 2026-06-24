# Keystone: land ONE real external differential (handoff)

> **The goal.** The moat's strongest proof is a single committed regression test built
> from a **non-self-seeded** target — a real open-source MCP server Mylonite did *not*
> author — that **fires on the unguarded app, is resisted once the control is applied,
> holds across the 5-run flakiness gate, and emits a validated test**. The in-repo
> reference twins already prove this; this is about proving it in the wild.

> **The chosen approach:** use
> the **control-efficacy oracle**, which holds the model constant and varies only the
> safeguard — so we prove the *control* is load-bearing **without needing to out-fool a
> frontier model**. This is why robust-model resistance (DVMCP recall 0/8) is not a
> blocker: an app-design flaw (an unconfirmed `send_email`, an un-allowlisted egress) is
> demonstrable regardless of model. Target **real OSS MCP servers with a known app-design
> flaw** (below), not CTF challenges.

> **Why it isn't done in-session.** It needs (a) the target server installed + *running*,
> (b) a live LLM key, and (c) network/SSL access (this machine: corporate-proxy TLS +
> Norton friction). So this is a maintainer-run step. Everything below is the exact recipe.

## Chosen targets (the approved external-proof path)

### Primary — W4 unconfirmed consequential action: `mcp-server-email`

`Shy2593666979/mcp-server-email` (**MIT**, Python, stdio). Exposes `send_email` with **no
confirmation/approval step** — the *same flaw class* as our reference keystone, on code we
didn't write. Maximal credibility.

```powershell
$env:ANTHROPIC_API_KEY = "sk-..."
$env:PYTHONUTF8 = "1"

# 0. install the target into the venv (sandbox the creds — see the safety note)
pip install mcp-server-email     # or: pip install -e <clone>

# 1. scaffold a target.yaml from its live tool surface (NO LLM call, no attack, no --authorize)
mylonite scan --command "python" --arg "-m" --arg "mcp_email_server" --scaffold email.yaml

# 2. edit email.yaml: declare weakness_classes [W4], the consequential tool (send_email),
#    and an effect_probe that confirms a dispatch. Then prove the W4 confirmation control
#    is load-bearing (control-efficacy differential, model held constant):
mylonite validate --target-file email.yaml --authorize mcp-email --iterations 5
mylonite ablate   --target-file email.yaml --authorize mcp-email --controls W4

# 3. if KEPT, the emitted test is the keystone artifact. Commit it.
```

> **SAFETY — mandatory.** `send_email` really sends. Point it at a **sandboxed SMTP sink**
> (e.g. MailHog / a throwaway account with fake creds), never a live mailbox. This is the
> responsible-use default; the `--authorize` flag asserts you own the target.

Success = a **KEPT** differential: the raw server dispatches the send with no approval; the
control-shim guarded twin stages/blocks it; the gap holds 5/5; a validated regression test
is emitted. Because W4 is about the *app's dispatch behavior*, not the model falling for an
injection, this fires regardless of planner-model robustness.

### Secondary — W3 SSRF / unrestricted egress: official `server-fetch`

`@modelcontextprotocol/server-fetch` (`uvx mcp-server-fetch`). Per upstream issue **#2317**
it does not block internal/loopback IPs by default — a publicly-disclosed SSRF surface on
the *official* reference server (recognizable to the exact wedge).

```powershell
mylonite scan --command "uvx" --arg "mcp-server-fetch" --scaffold fetch.yaml
# edit fetch.yaml: weakness_classes [W3], egress tool = fetch, effect_probe = an internal
# URL the guarded (host-allowlist) twin must refuse. Then:
mylonite validate --target-file fetch.yaml --authorize mcp-fetch --iterations 5
```

### Defended-precision baseline (E2 — the 0-FP number)

Re-run against a server that **already** has the control (e.g. `server-fetch` once the
allowlist from #2317 lands, or any reputable server that gates the action) and show **0
findings** — the first external precision number. Record under
`verification/layer3_production/` (see `candidates.md`). A finding there is a Mylonite FP to
fix.

## Alternative — DVMCP CTF challenges (fallback)

DVMCP remains a valid fallback if a real OSS target can't be stood up, but it is a CTF, not
a realistic app, and Haiku resisted all 8 (recall 0/8), so it needs the weaker-planner
crutch below. Prefer the real OSS servers above.

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
