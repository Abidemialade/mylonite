# Test your own app

The bundled [reference app](quarry.md) proves the machinery. The point of Mylonite is to run
it against **your** AI agent. If your app exposes its tools over MCP (or any
stdio MCP server), this is the end-to-end path: scaffold a target file, check it,
scan, and gate.

> **No MCP?** If your agent is a plain HTTP endpoint (a prompt in, a reply out),
> use the [`rest` transport](http-agent.md) — describe the request shape in the
> target file and change nothing in your app.

> **Authorisation.** Mylonite finds and reproduces working exploits, so every
> non-reference target requires an explicit `--authorize <you>` flag asserting you
> control the target. See [Security](security.md). Never point it at an app you don't own.

## 1. Scaffold a target file

`scan --scaffold` launches your MCP server, lists its tools (no LLM call, no attack),
infers the likely weakness classes and the plant/retrieve tools, and writes a commented
`target.yaml` starter (no `--authorize` needed — nothing is attacked):

```bash
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml --scope my-app
```

`--scope` is optional here (it labels the target and becomes the value `--authorize` must
match below — see [the `target.yaml` reference](target-file.md)); omit it and the
scaffolded `target.yaml` falls back to `family: custom`, so `--authorize custom` instead.

It suggests `weakness_classes` (W1/W2 baseline; W3 if it sees an egress tool; W4 if it
sees a consequential tool), pre-fills a `seed_arm` (how to plant poisoned content) and
an `effect_probe` (how to confirm damage), and lists your tools. Fill in the commented
sections — see the full [target.yaml reference](target-file.md).

A minimal target file is just:

```yaml
family: my-app
command: python
args: [my_server.py]
weakness_classes: [W2]
seed_arm:                    # how to plant untrusted content (required for W2)
  tool: save_note
  args_template: { body: "{payload}" }
```

> **Auto-wiring.** For a W2 target, if you omit `seed_arm`, `scan` will infer it from
> the live tool surface when a no-id recall path exists (so the planted payload is
> guaranteed to be surfaced back) — printing what it inferred. Otherwise it blocks
> loudly rather than silently skipping the W2 attack patterns and reading as clean.

## 2. Check it (free, no key)

`check` connects to the same target ONCE — no LLM call, no attack, no `--authorize`
needed — and reports structural exposure straight from the tool schemas: consequential
tools with no approval-shaped sibling, descriptions that steer the agent, tools taking an
apparent network destination, and unpinned tool descriptions (paste-ready digests for
`control_config.description_pins`):

```bash
mylonite check --target-file app.yaml
```

Every finding is a hint to confirm, never a verdict — the differential oracle (`scan`/
`gate`) is what proves an attack actually lands. Cheap enough to run on every push: add
`mylonite check --target-file app.yaml --enforce` to CI stage 1, next to lint, once the
surface is clean (`--enforce` exits `1` on any finding instead of reporting and exiting `0`).

## 3. Scan it

```bash
mylonite scan --target-file app.yaml --authorize my-app
```

This runs the [single-shot engine](attack-modes.md). Findings land under
`.mylonite/scans/`. Use the
[model roles](attack-modes.md#composing-the-model-roles) to point the
*planner* at a representatively exploitable model.

## 4. Gate it (the full pipeline)

`gate` runs the whole pipeline — scan → generate → validate → (optionally) open a PR —
and only a **kept** test makes it through:

```bash
mylonite gate --target-file app.yaml --authorize my-app            # writes test + CI workflows
mylonite gate --target-file app.yaml --authorize my-app --open-pr  # also opens the PR via gh
```

Because you have no in-repo guarded build, the validator synthesizes one at the adapter
boundary (the [control-efficacy check](validation.md#the-control-efficacy-check))
and proves the finding *differentially* by default — the emitted test gates on the
**control** being load-bearing, with the boundary-proxy caveat stated on the label. See
[CI gating](ci-gating.md) for the committed workflows and the PR anatomy.

## 5. Keep it honest over time

- **`mylonite ablate --target-file app.yaml --authorize my-app`** — score each safeguard:
  load-bearing, security theater, or (with `--redundancy`) redundant.

## Bundled targets

Three MCP servers ship as ready-to-scan targets (no target file needed) — useful for
trying Mylonite against real servers:

| Target | Scope | Exposes |
|--------|-------|---------|
| `mcp:filesystem:<abs/path>` | a sandbox dir | W1, W2, W4 (read/write files) |
| `mcp:fetch` | optional label | W3 (egress) |
| `mcp:github:<owner/repo>` | a repo | W1, W2, W4 (issues/comments) |

```bash
mylonite scan mcp:filesystem:/tmp/sandbox --authorize /tmp/sandbox
```

> These bundled families are **attack-only** today (they scan but don't yet route
> through the differential oracle); routing them through the on-ramp so they can emit a
> gating test is planned. For a CI-gating test against a real app, use `--target-file`.
