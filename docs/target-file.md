# `target.yaml` reference

A target file is how you point Mylonite at a custom MCP server (`--target-file`). One
YAML declares how to launch the server, which weakness classes it exposes, and how to
plant and verify attacks. `mylonite init-target` scaffolds one for you; this page is the
full field reference. Source: `mylonite.plugins._mcp.target_file.TargetFile`.

## Minimal

```yaml
family: my-app
command: python
args: [my_server.py]
weakness_classes: [W2]
seed_arm:
  tool: save_note
  args_template: { body: "{payload}" }
```

## Full, annotated

```yaml
# --- how to launch the server ---------------------------------------------
family: my-app                 # short name used in report ids (not a bundled name)
command: python                # the MCP server launch command
args: [my_server.py, --port, "0"]
env: { LOG_LEVEL: warning }    # extra env for the server process
scope: tenant-a                # optional label; must match --authorize / {scope}
requires_scope: false          # set true to require a non-empty scope

# --- the AI layer ----------------------------------------------------------
system_prompt: |               # the target's system prompt (inline)...
  You are a helpful assistant with access to the connected tools.
# system_prompt_file: prompts/system.txt   # ...or read it from a file (one or the other)
primary_tools: []              # optional: narrow seed selection to these tools
weakness_classes: [W1, W2, W3, W4]   # which classes to test

# --- how to plant poisoned content (required for indirect-injection W2) ----
seed_arm:
  tool: save_note              # the tool that stores attacker-controllable content
  args_template: { body: "{payload}" }   # {payload} is the bare natural-language plant
  id_key: id                   # JSON field in the result holding the new record's handle
  # id_pattern: 'note_(\d+)'   # ...or a regex to extract the id
  # id_from: first_int         # ...or "first integer in the result"

# --- how to confirm the damage materialised (recommended for custom targets) 
effect_probe:
  verify_tool: list_notes
  verify_args_template: {}
  expect_marker: "attacker@example.com"        # a string that proves the effect landed
  deferred_markers: ["queued for approval"]    # markers that mean DEFENDED, not fired

# --- which tools implement which controls (for the synthetic guarded twin) -
control_config:
  egress_tools: [web_fetch]            # W3: tools that reach the network
  egress_url_param: url                # the URL arg the allowlist guards
  fetch_allowlist: [example.com]       # hosts the egress control permits
  consequential_tools: [send_email]    # W4: high-impact actions to gate
  declared: [W2]                       # controls you've already implemented server-side
  synthetic: true                      # let Mylonite synthesize the missing guarded twin

# --- optional: a genuinely unguarded build + per-control server-layer toggles
vulnerable_launch:                     # how to launch a DELIBERATELY-unguarded variant
  command: python
  args: [my_server.py]
  env: { SECURITY_MODE: "off" }
control_env:                           # per-control env that disables ONE server guard
  W2: { SANITIZE_INPUT: "false" }
  W3: { ALLOWLIST: "disabled" }
```

## Field groups

- **Launch** (`family`, `command`, `args`, `env`, `scope`, `requires_scope`) — how the
  stdio MCP server is started and labelled.
- **AI layer** (`system_prompt` / `system_prompt_file`, `primary_tools`,
  `weakness_classes`) — what the agent is and what to test. Set at most one of the two
  prompt fields.
- **`seed_arm`** (`SeedArmSpec`) — how to plant untrusted content. `{payload}` must sit
  at a **bare string leaf** (e.g. `body: "{payload}"`), not nested inside serialized
  JSON. The `id_key`/`id_pattern`/`id_from` tell Mylonite how to capture the new
  record's handle so it can drive a read-back.
- **`effect_probe`** (`EffectProbeSpec`) — confirms the damage end-to-end, not just that
  a tool was called. `expect_marker` proves it fired; `deferred_markers` mean the action
  was *defended* (e.g. queued for approval), not a success.
- **`control_config`** (`ControlConfig`) — tells the synthetic guarded twin which tools
  carry egress (W3) and consequential actions (W4), the allowlist, which controls you've
  `declared`, and whether to `synthetic`-ally synthesize the rest.
- **Server-layer twin** (`vulnerable_launch`, `control_env`) — optional: drive the
  differential against *your own* unguarded build and per-control env toggles, instead of
  the adapter-boundary shim. Use these when you can launch genuinely (un)guarded variants
  of the server. See [Concepts](concepts.md) and [Security](security.md).

> **Windows SQLite footgun.** If `env` points at a SQLite DB by URL, note that
> `sqlite:////c/Users/...` (4 slashes) and `sqlite:///C:/Users/...` (3 slashes) open
> *different* databases on Windows — a silent way to scan an empty DB and wrongly
> conclude the agent is clean. Prefer an absolute path and verify it opened.
