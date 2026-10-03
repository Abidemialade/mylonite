# 4. Find

Before this spends anything, Mylonite prints what it's about to do — the
model, the prompt it's using, and the tools it will drive — so you can check
the plan before paying for it:

```bash
mylonite scan --target-file app.yaml --authorize my-app
```

`--authorize` asserts you control the target: its value must match the
`scope` you scaffolded with, or the family name if you didn't set one — the
scaffold step prints the right value. See [Security](../security.md) for
why this is required and never optional.

This drives your tools with Mylonite's own planner — reading your system
prompt and tool descriptions, not your app's own agent or model — and runs
the [single-shot attack engine](../attack-modes.md). Findings land under
`.mylonite/scans/<timestamp>/`.

**Capping the spend.** `--max-llm-calls N` (default 50) is a per-scan
budget — a soft one, since each seed keeps a small floor. The global
`--max-llm-requests N` (before the command) or `MYLONITE_MAX_LLM_REQUESTS=N`
is the hard ceiling across this whole run: request N+1 is never sent, the
run stops and exits `3`. Both are described in full in the [CLI
reference](../cli-reference.md).

**Exit codes.** `scan` exits `0` whether or not it finds anything —
reporting a weakness is not a failure. `2` is a config or usage error
(including an empty scan), `3` is the budget or request ceiling above, and
`4` is a missing model choice or a provider/credential that refused the run
before the target was ever touched.

## Reading the output

A finding earns one of three **evidence tiers**, shown in the scan table and
printed as a summary line (`findings by evidence: 1 state, 2 trace, 1
judge-only`):

| Tier | What decided it |
|---|---|
| `state` | a probe read the target's own state and saw the damage. |
| `trace` | a deterministic check saw a consequential tool get called (or linked). |
| `judge-only` | only the LLM judge's read of the reply said so — nothing in the target's state or trace confirmed it. |

A `judge-only` result is a **candidate**, worth a look, not yet a finding to
act on: `validate` (the [next step](5-prove.md)) never keeps a test when
every firing run is judge-only. Anything that couldn't be decided reads
**NOT TESTED** with a reason code, never silently as clean — see [Reading
the results](../reading-results.md) for every field, [Which claim you
earned](../reading-results.md#which-claim-you-earned) for what a result does
and doesn't prove yet, and [Coverage by app shape](../index.md#coverage-by-app-shape)
if a class you expected reads NOT TESTED because of how your app is wired
rather than anything Mylonite tried.

Expect to find less here than on the [practice app](1-try.md) — often
nothing, on a well-built app and a capable model. That's the tool working,
not failing: a safeguard only earns proof by stopping a weakness that
actually lands.

## Next

[5. Prove](5-prove.md) — turn a candidate into a test, then confirm it's
real.
