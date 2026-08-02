# `target.yaml` reference

A target file is how you point Mylonite at a custom MCP server (`--target-file`). One
YAML declares how to launch the server, which weakness classes it exposes, and how to
plant and verify attacks. `mylonite scan --scaffold app.yaml` scaffolds one for you; this
page is the full field reference. Source: `mylonite.plugins._mcp.target_file.TargetFile`.

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
primary_tools: []              # optional: narrow attack pattern selection to these tools
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

# --- which tools implement which controls (for the synthetic guarded build) -
control_config:
  egress_tools: [web_fetch]            # W3: tools that reach the network
  egress_url_param: url                # the URL arg the allowlist guards
  fetch_allowlist: [example.com]       # hosts the egress control permits
  consequential_tools: [send_email]    # W4: high-impact actions to gate
  declared: [W2]                       # controls you've already implemented server-side
  synthetic: true                      # let Mylonite synthesize the missing guarded build

# --- optional: a genuinely unguarded build + per-control server-layer toggles
vulnerable_launch:                     # how to launch a DELIBERATELY-unguarded variant
  command: python
  args: [my_server.py]
  env: { SECURITY_MODE: "off" }
control_env:                           # per-control env that disables ONE server guard
  W2: { SANITIZE_INPUT: "false" }
  W3: { ALLOWLIST: "disabled" }
```

## Remote targets (SSE / HTTP)

By default a target is launched over **stdio** (`command`/`args` spawn a subprocess). To
scan a *remote* MCP server, set `transport` and `url` instead — `command` becomes optional:

```yaml
family: my-remote-app
transport: sse                 # stdio (default) | sse | http (streamable-HTTP)
url: https://app.example.com/mcp
headers:                       # optional; may carry auth
  Authorization: Bearer my-token
weakness_classes: [W2, W4]
seed_arm: { tool: save_note, args_template: { body: "{payload}" } }
```

- `url` is required for `sse`/`http` and rejected for `stdio`.
- `headers` are passed to the transport but **never logged and never shown** in the target
  descriptor (only the host appears). A target file keeps tokens out of shell history.
- `command`/`args`/`env` and the server-layer `vulnerable_launch`/`control_env` toggles do
  not apply to remote targets and are ignored.
- Everything else (`seed_arm`, `effect_probe`, `weakness_classes`, `control_config`) works
  exactly the same.

## Field groups

- **Launch** (`family`, `command`, `args`, `env`, `scope`, `requires_scope`) — how the
  stdio MCP server is started and labelled. For remote servers use
  `transport: sse|http` + `url` + optional `headers` instead of `command`/`args`.
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
- **`control_config`** (`ControlConfig`) — tells the synthetic guarded build which tools
  carry egress (W3) and consequential actions (W4), the allowlist, which controls you've
  `declared`, and whether to `synthetic`-ally synthesize the rest.
- **Server-layer build** (`vulnerable_launch`, `control_env`) — optional: drive the
  differential against *your own* unguarded build and per-control env toggles, instead of
  the adapter-boundary shim. Use these when you can launch genuinely (un)guarded variants
  of the server. See [Concepts](concepts.md) and [Security](security.md).

> **Windows SQLite footgun.** If `env` points at a SQLite DB by URL, note that
> `sqlite:////c/Users/...` (4 slashes) and `sqlite:///C:/Users/...` (3 slashes) open
> *different* databases on Windows — a silent way to scan an empty DB and wrongly
> conclude the agent is clean. Prefer an absolute path and verify it opened.

## The boundary controls fail closed

The four boundary controls the adapter-boundary shim synthesizes (W1 description
sanitizer, W2 untrusted-data envelope, W3 egress allowlist, W4 confirm-gate) each
answer one question about a tool call: *does this control apply to this tool?* For
W3 and W4, that answer is decided in this order:

1. An explicit list in `control_config` (`egress_tools` / `consequential_tools`) — you
   said so, and this is always the final word for that tool name.
2. Structural evidence: W3 only — a call with a URL, a bare hostname, or an IP-literal
   argument is treated as egress regardless of what the tool is called.
3. A name heuristic (substrings like `fetch`/`http`/`web` for egress, `send`/`delete`/
   `pay` for consequential actions) — a convenience, never the gate.
4. **Otherwise: guarded.** A tool that matches none of the above is still treated as
   in-scope for the control.

This means a W3/W4 tool your target exposes that doesn't match any hint, and isn't
declared, is now **refused** by default instead of silently passed through
unguarded — an egress call with no destination Mylonite can identify gets
`refused: ... no destination argument could be identified`, and an unhinted
consequential call gets `deferred: ... requires explicit confirmation`. The first
time this fires for a given tool name in a run, Mylonite logs a warning (once per
tool name) with the exact snippet to paste into `control_config` to classify it
precisely — either to confirm it as egress/consequential with the right argument
name, or (by omitting it from a *non-empty* declared list) to exempt it entirely.
W1 and W2 fail closed the same way but never refuse a call outright: W1 sanitizes
every tool description regardless of name, and W2 wraps every non-error result in
the `<untrusted>` envelope by default unless the tool is excluded via an explicit
declared list (not yet a `control_config` field — construct
`UntrustedEnvelopeControl` directly if you need to narrow it).

If your custom target has an egress or consequential tool with an unusual name
(e.g. `dispatch_widget`, `relay_message`), declare it up front so the run doesn't
spend a refusal cycle discovering it:

```yaml
control_config:
  egress_tools: [dispatch_widget]
  egress_url_param: destination
  consequential_tools: [relay_message]
```

## Path containment

`target.yaml` is a shareable, PR-editable document — a teammate can mail you one, or
a pull request can edit the one already in your repo. Two fields resolve to a real
filesystem path, and both are contained, not just shape-checked:

- **`system_prompt_file`** resolves relative to the directory the target YAML itself
  lives in (its `source_dir`), never the current working directory of whoever runs
  `mylonite`. A value like `../../../../etc/passwd` — or a symlink that points outside
  that directory — is refused before the file is ever opened; it cannot be used to read
  an arbitrary file off your disk. See `mylonite._paths.resolve_contained`.
- **`mcp:filesystem:<scope>`** (the sandbox path handed to
  `@modelcontextprotocol/server-filesystem`) must be a real, existing, non-root
  directory: `/`, `C:\`, your home directory, and any path containing `..` are all
  rejected outright, and the directory must actually exist. Set `MYLONITE_FS_SCOPE_ROOT`
  to an absolute directory to additionally require every filesystem scope stay inside
  that root — an opt-in hard ceiling for CI/shared-runner environments that launch
  scans against target files they didn't author.

Both checks fail loud (`PathEscapesBase` / `InvalidTargetScope`) rather than silently
reading or sandboxing the wrong thing. See `SECURITY.md` for what a `target.yaml` you
received from someone else can and cannot do.
