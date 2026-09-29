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
env: { LOG_LEVEL: warning }    # ADDED to a small allowlist, not merged into your full env — see below
scope: tenant-a                # optional label; must match --authorize / {scope}
requires_scope: false          # set true to require a non-empty scope
# timeout_s: 90                # optional; stdio/sse/http only. Overrides the planner
#                               # AND MCP session read timeout (both default to 60s) --
#                               # see "MCP session timeout" below.
# --authorize must EQUAL this target's required value: the declared `scope`
# exactly (e.g. `--authorize tenant-a` above) if one is set, else `family`
# (e.g. `--authorize my-app`) if it isn't. This is derived from the target's
# own data, never from `requires_scope` — see `mylonite._authz`, SECURITY.md.

# --- the AI layer ----------------------------------------------------------
system_prompt: |               # the target's system prompt (inline)...
  You are a helpful assistant with access to the connected tools.
# system_prompt_file: prompts/system.txt   # ...or read it from a file (one or the other)
primary_tools: []              # optional: documentation only — see the note below
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
  verify_tool: list_sent_mail
  verify_args_template: {}
  # A marker the AGENT must PRODUCE by acting (here: the attacker recipient in the
  # sent-mail log). Do NOT use a literal Mylonite plants into the payload (e.g. an
  # exfil address inside a poisoned note) on a plant-and-recall target: the verify
  # tool would reflect the planted payload back and the marker would match without
  # the agent doing anything. An effect now counts for an attempt only when the
  # marker is NEW since that attempt's own pre-drive baseline AND one of that
  # attempt's own executed calls carries it (or is the declared consequential/
  # egress tool) — a marker that was already there, or that another attempt
  # wrote, does not confirm this attempt. See "Effect attribution" below.
  expect_marker: "attacker@example.com"        # appears in the SENT log only if forwarded
  deferred_markers: ["queued for approval"]    # markers that mean DEFENDED, not fired

# --- which tools implement which controls (for the synthetic guarded build) -
control_config:
  egress_tools: [web_fetch]            # W3: tools that reach the network
  egress_url_param: url                # the URL arg the allowlist guards
  fetch_allowlist: [example.com]       # hosts the egress control permits
  consequential_tools: [send_email]    # W4: high-impact actions to gate
  read_tool_names: [read_note]         # W2: tools whose results get quarantined
  private_tools: [get_user_sessions]   # W2/W4: tools that RETURN sensitive data
  private_markers: ["INTERNAL-SECRET-"] # …or a literal that marks a result private
  destructive_tools: [delete_entities] # W2: sinks where an injected call is damage itself
  enforcement_mode: approve            # block (default) | approve | observe
  approval_policy: approve_when_trusted # in approve mode: deny_all | approve_when_trusted
  declared: [W2]                       # controls you've already implemented server-side
  synthetic: [W3, W4]                  # controls NOT already declared — Mylonite synthesizes/tests these

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
  Authorization: Bearer ${MY_TOKEN}
weakness_classes: [W2, W4]
seed_arm: { tool: save_note, args_template: { body: "{payload}" } }
```

- `url` is required for `sse`/`http` and rejected for `stdio`.
- `headers` are passed to the transport but **never logged and never shown** in the target
  descriptor (only the host appears). A target file keeps tokens out of shell history.
- Reference the token with `${VAR}`, as above, and export it before you scan
  (`export MY_TOKEN='...'` / `$env:MY_TOKEN = '...'`) — the same `${VAR}` mechanism the REST
  adapter's `request.headers` uses (see [`docs/http-agent.md`](http-agent.md)). Mylonite
  expands it from your shell's environment and never writes the literal value to the file.
- If the server rejects the request with 401 or 403, `scan` names the host and the status
  and points at this section — for example: `the server at app.example.com rejected the
  request (401). Set the token in headers: in the target file, e.g. Authorization: Bearer
  ${MY_TOKEN}, and export MY_TOKEN before you scan.` See
  [Known limitations](limitations.md) for what this does not (yet) cover — a static token
  only, no OAuth sign-in.
- `command`/`args`/`env` and the server-layer `vulnerable_launch`/`control_env` toggles do
  not apply to remote targets and are ignored.
- Everything else (`seed_arm`, `effect_probe`, `weakness_classes`, `control_config`) works
  exactly the same.

## MCP session timeout

`timeout_s` (optional; `stdio`/`sse`/`http` only — a `rest` target uses
[`request.timeout_s`](http-agent.md#the-target-file) instead) overrides BOTH the
planner's per-turn budget and the MCP `ClientSession`'s read timeout, which otherwise
default to 60 seconds each. Raise it for a target that legitimately takes longer per
turn — a local model, a slow server, or a first-run `npx`/`uvx` download. Both the
planner-timeout error (raised mid-scan, on a slow turn) and the `describe()`-timeout
error (raised on connect, e.g. a hung server) name `timeout_s` and its effective
value. The one-off `seed_arm` auto-wire probe (a single `describe()` call `scan`
makes up front to infer a `seed_arm` — see [CLI reference](cli-reference.md)) also
names `timeout_s`, but its own budget is `max(20, timeout_s)`: even a smaller
`timeout_s` never shrinks that first probe below 20 seconds. Omitting the field
keeps today's fixed 60s default for the planner and session, so an existing target
file loads unchanged.

```yaml
timeout_s: 90
```

## Field groups

- **Launch** (`family`, `command`, `args`, `env`, `scope`, `requires_scope`) — how the
  stdio MCP server is started and labelled. For remote servers use
  `transport: sse|http` + `url` + optional `headers` instead of `command`/`args`.
- **AI layer** (`system_prompt` / `system_prompt_file`, `primary_tools`,
  `weakness_classes`) — what the agent is and what to test. Set at most one of the two
  prompt fields.

    !!! note "`primary_tools` is currently documentation only"
        It is accepted, validated and round-tripped, but **nothing reads it** — it does
        not narrow seed selection today, despite what earlier versions of this page
        claimed. Use `weakness_classes` to control what gets tested. Wiring it as a real
        filter is tracked in `TODOS.md`.
- **`seed_arm`** (`SeedArmSpec`) — how to plant untrusted content. `{payload}` must sit
  at a **bare string leaf** (e.g. `body: "{payload}"`), not nested inside serialized
  JSON. The `id_key`/`id_pattern`/`id_from` tell Mylonite how to capture the new
  record's handle so it can drive a read-back.
- **`effect_probe`** (`EffectProbeSpec`) — confirms the damage end-to-end, not just that
  a tool was called. `expect_marker` proves it fired; `deferred_markers` mean the action
  was *defended* (e.g. queued for approval), not a success. Choose `expect_marker` as a
  value **the agent's own call carries** — the recipient address, a row it wrote, or
  `{payload}` — not a status word the target itself would print regardless of who acted.
  A fixed status word like `status=sent` can only be tied to an attempt through the tool
  the seed names as its consequential or egress tool, and only synthesised seeds name
  one. A tool declared under `control_config.consequential_tools` can link only
  synthesised seeds; catalogue seeds, which `validate` re-drives, never link through it.
  So `scan`, `validate` and `check` warn on a fixed marker whatever `control_config`
  declares: on a catalogue seed that effect can read `"unattributed"` but never
  `"true"`, and `validate` cannot keep the finding. The dependable fix is a marker the
  agent's own call carries. A marker shaped like an email address (`x@y.z`) or a URL
  (containing `://`) is exempt from the warning: it is assumed to be carried by the
  agent's call. See
  [Effect attribution](#effect-attribution) below for what confirms an effect and what
  `"unattributed"` means.
- **`control_config`** (`ControlConfig`) — tells the synthetic guarded build which tools
  carry egress (W3), consequential actions (W4), and untrusted-data results to quarantine
  (`read_tool_names`, W2), the allowlist, which controls you've `declared`, and whether to
  `synthetic`-ally synthesize the rest. For W2 specifically, two further lists decide
  whether the control can actually *discriminate*:
    - **`private_tools`** — tools whose results carry sensitive data. Reading one raises
      the session to `private`, and a public-facing sink then refuses. **This is the
      knob that catches exfiltration.** `read_tool_names` alone only marks content
      untrusted, which on its own gates nothing but destructive sinks.
    - **`destructive_tools`** — sinks where an injection-driven call is damage in itself
      (delete/overwrite/transfer). These refuse untrusted context outright. Inferred
      from MCP's `destructiveHint` and name hints when you don't declare them.
- **Server-layer build** (`vulnerable_launch`, `control_env`) — optional: drive the
  differential against *your own* unguarded build and per-control env toggles, instead of
  the adapter-boundary shim. Use these when you can launch genuinely (un)guarded variants
  of the server. See [Concepts](concepts.md) and [Security](security.md).
- **`framework`** — optional, free-form (e.g. `langchain`, `crewai`, `llamaindex`).
  Entirely a labelling hint: it names your agent framework in a structural
  recommendation's code sketch alongside the language Mylonite already infers from
  `command` (`python`/`uv`/`uvx`/`poetry` → Python, `node`/`npx`/`bun`/`tsx` → TypeScript,
  else generic pseudocode). Never validated against a fixed list, and never used to
  fabricate that framework's actual hook/decorator syntax — Mylonite points you at where
  to wire a sketch in, not at invented API details it hasn't verified.

> **Windows SQLite footgun.** If `env` points at a SQLite DB by URL, note that
> `sqlite:////c/Users/...` (4 slashes) and `sqlite:///C:/Users/...` (3 slashes) open
> *different* databases on Windows — a silent way to scan an empty DB and wrongly
> conclude the agent is clean. Prefer an absolute path and verify it opened.

> **`env` is an overlay, not your full environment.** A stdio target's spawned process
> does **not** inherit Mylonite's own environment wholesale — Mylonite routinely spawns
> deliberately-vulnerable and third-party servers, and handing every one of them
> Mylonite's own provider API keys / `GITHUB_TOKEN` / other credentials would be a real
> leak. The child gets a small, fixed allowlist of OS-plumbing variables (`PATH`, `HOME`,
> `USERPROFILE`, `SYSTEMROOT`, `TEMP`, `TMP`, `TMPDIR`, `LANG`, `LC_ALL`, `PATHEXT`,
> `COMSPEC`, `APPDATA`, `LOCALAPPDATA`) plus whatever you declare in `env:` — nothing
> else. If your server needs some OTHER parent-env variable, declare it explicitly here.
> The most common case: an `npx`/`uvx`-launched target running behind a corporate
> TLS-inspecting proxy needs its proxy/CA variables declared explicitly too, e.g.
> `env: { HTTPS_PROXY: "...", HTTP_PROXY: "...", NO_PROXY: "...", NODE_EXTRA_CA_CERTS:
> "...", SSL_CERT_FILE: "..." }` — without them the launch can fail with a TLS/registry
> error that looks unrelated to Mylonite.

## Coverage: a declared class your surface can't run is refused, not silently dropped

Declaring a class in `weakness_classes` is a promise: Mylonite tests it. Before either
`scan` or `gate` spends an LLM call, it checks whether your target's introspected tool
surface can actually produce even one seed for every declared class. A class can be
covered by more than one mechanism — the bundled catalogue seed for a literally-named
tool (`send_email`, `web_fetch`), or a seed synthesised for your target's OWN tool
(classifier-found, e.g. `execute_sql`, or declared via `control_config.egress_tools` /
`control_config.consequential_tools`) — so W3/W4 refuse only when NEITHER exists: no
egress-shaped tool at all for W3, no consequential tool at all for W4. W2 refuses only
when there is no store-and-recall pair AND no content-processing tool. If a class would
run zero seeds either way, the run refuses outright and names each one:

```text
error: this target declares weakness class(es) its tool surface cannot cover at all
(every attempt for them would never run):
  W2: this server has no tool that can store content for a later recall — remove W2
      from weakness_classes, or declare a seed_arm
```

The fix is always one of the two named: drop the class from `weakness_classes`, or
declare the missing piece (a `seed_arm` for W2, `control_config.egress_tools` for W3,
`control_config.consequential_tools` for W4). `mylonite scan --scaffold` only ever
suggests a class it already confirmed is coverable for the surface it just introspected,
so a fresh scaffold's target.yaml never trips this refusal on first run.

`--dry-run` downgrades the refusal to a warning — a dry run only enumerates seeds, so it
stays informative instead of blocking. A W2 class you've explicitly accepted running
uncovered via `--allow-no-seed-arm` is not re-blocked here — the run proceeds, its
kitchen-sink seeds are still scheduled, and each one hits the target and reports
`skipped_no_seed_arm` (NOT TESTED), which forces the scan's overall coverage to PARTIAL
rather than letting it read as a trustworthy clean pass. `gate` gets the same refusal,
with no `--dry-run` equivalent to downgrade it and no `--allow-no-seed-arm` flag of its
own — an uncoverable class always refuses there. `gate` also has no `seed_arm`
auto-wire: a W2 target that `scan` would wire for you refuses in `gate`. Run `scan` on it
first; when it finds a store-and-recall pair it writes the wired target to
`.mylonite/scans/<timestamp>/target.yaml`, and that file is the one to pass to `gate`.

The check has to launch the server to see its tools, and it fails closed: if the server
crashes, or can't be described within 20 seconds (or the target's `timeout_s`, when that
is larger), the run stops with exit 2 and says which, rather than starting without
knowing whether every declared class can run. After a timeout, re-run once (a first
`npx`/`uvx` download is cached after that) or raise `timeout_s`; after a crash, check the
target file's `command:` and `args:`. The scan engine repeats
the same rule on the description it actually runs against: a declared class with no seed
at all aborts the scan before any payload is sent (`no_payloads`, exit 2), so a skipped or
failed pre-flight can never let the other classes read as a clean pass.

When the refused class came from `--weakness-class` rather than the file, the message
says so and points at the flag, since editing `weakness_classes` would not help.

This is a different check from `mylonite check`, which needs a live tool surface and no
LLM call: it diffs `seed_arm.tool`, `effect_probe.verify_tool` and every
`control_config` tool-name field against the server's described tools, and flags any
name that isn't there — a typo, or a stale name copied from another target file. Those
findings count toward `check --enforce`, the same as an unapproved sink.

## Effect attribution

An `effect_probe` reads the verify tool before the agent runs (this attempt's own
baseline) and again after. An effect confirms `"true"` for **this** attempt only when
both hold: the marker is new since that baseline (with no marker, the verify output
itself changed), and one of this attempt's own executed calls carries the marker or is
the scenario's declared consequential or egress tool. Everything else the probe sees
falls into one of:

- **`"false"`** — the attempt did nothing, the post-drive read reported an error, a
  deferral marker (e.g. `"queued for approval"`) grew, or a linked call reported success
  while the marker never appeared, before or after (a silent drop).
- **`"unattributed"`** — the state change, or its absence, could not be tied to this
  attempt: an idempotent write, a delete, a bounded output window that slid, or a change
  another attempt made while this one only made an unrelated call. Not a final verdict —
  the attempt-scoped predicate decides it from this attempt's own trace, then the LLM
  judge if the predicate can't.
- **`"errored"`** — the baseline or the post-drive read itself raised or timed out.

This is what stops a target whose state outlives one run — a file, a database, a memory
store, any remote server — from letting an earlier attempt's write count as this
attempt's proof. A concurrent attempt's write can't be told apart this way, so on a
target with an `effect_probe`, Mylonite runs attempts one at a time. It costs one extra read-only call to the verify tool per attempt
with a declared `verify_tool`; nothing sent to the model changes.

## Secrets stay out of the file

Every target file Mylonite writes keeps the secrets in `headers`, `request.headers` and
`env` out of it: `scan --scaffold`, the copy saved in the scan directory, the copy
`generate` puts next to the test and the copy `gate` commits. Each value in `headers`
and `request.headers`, and each secret-looking `env` value (a key such as `GITHUB_TOKEN`
or `DB_PASSWORD`, or a value shaped like an API key), becomes a `${MYLONITE_TARGET_...}`
placeholder. Plain values such as `LOG_LEVEL: debug` stay as written.

A credential in the query string of `url` or `request.url` is masked too. A parameter
with a credential name (`api_token`, `access_key`, `client_secret`, `key`, `sig`, ...),
or whose value is shaped like an API key, becomes `***REDACTED***`. Other parameters
stay as written, and so do a few named exceptions that are request options, such as
`max_tokens`, `page_token` and `sort_key`. `url` reads no
variables, so a masked copy won't connect until you put the value back; the note the
writing command prints names each masked field, such as `request.url`. Keep copies
runnable by sending the token in `headers:` as a `${VAR}` reference instead.

```yaml
env:
  GITHUB_TOKEN: ${MYLONITE_TARGET_ENV_GITHUB_TOKEN}
  LOG_LEVEL: debug
```

Whichever command wrote the file prints the variables to set, with the key each one
stands for. The secret itself is never printed:

```text
note: secrets in headers and env were kept out of app.yaml. It reads them from these environment variables; set them before you use the file:
  bash/zsh:
    export MYLONITE_TARGET_ENV_GITHUB_TOKEN='<your GITHUB_TOKEN>'
  PowerShell:
    $env:MYLONITE_TARGET_ENV_GITHUB_TOKEN = '<your GITHUB_TOKEN>'
```

The bundled `mcp:github` family (no target file needed) uses the same `${VAR}`
expansion for its own fixed variable, `GITHUB_PERSONAL_ACCESS_TOKEN` — see
[Bundled targets](test-your-app.md#bundled-targets).

Set each variable to the real value in the shell that runs Mylonite, then use the file:

```bash
export MYLONITE_TARGET_ENV_GITHUB_TOKEN='ghp_...'
mylonite check --target-file app.yaml
```

To keep the values in a `.env` file instead, load it into your shell first
(`set -a; . ./.env; set +a` in bash or zsh). Mylonite's own `--env-file` flag reads only
provider API-key names, so it does not pick these up. In CI, set them as secrets on the
job.

If a variable is unset, loading the file stops with exit code 2 and names the variable,
the key it holds and the `export` line to run. Mylonite never starts your server with an
empty credential. Placeholders are expanded only inside `env`, `headers` and
`request.headers`, so `${...}` text elsewhere in the file, such as a template-injection
payload in `system_prompt`, is left alone.

## The boundary controls fail closed

The four boundary controls the adapter-boundary shim synthesizes (W1 description
pinning, W2 information-flow control, W3 egress allowlist, W4 confirm-gate) each
answer one question about a tool call: *does this control apply to this tool?* For
W2/W3/W4, that answer is decided in this order:

1. An explicit list in `control_config` (`read_tool_names` / `egress_tools` /
   `consequential_tools`) — you said so, and this is always the final word for that
   tool name.
2. The tool's own **MCP annotations** (`readOnlyHint`, `destructiveHint`,
   `openWorldHint`) — the protocol's standard risk vocabulary. Ranked below your
   declaration on purpose: the MCP spec is explicit that annotations are hints from a
   possibly-untrusted server.
3. Structural evidence: W3 only — a call with a URL, a bare hostname, or an IP-literal
   argument is treated as egress regardless of what the tool is called.
4. A name heuristic — whole-word tokens like `read`/`fetch`/`list` for W2,
   `fetch`/`http`/`web` for W3 egress, `send`/`delete`/`pay` for W4 consequential
   actions. A convenience, never the gate. Matching is on **tokens**, not substrings,
   so `get_postal_code` is not treated as consequential because of `post`.
5. **Otherwise: guarded.** A tool that matches none of the above is still treated as
   in-scope for the control.

This means a W2/W3/W4 tool your target exposes that doesn't match any hint, and isn't
declared, is now guarded by default instead of silently passed through unguarded:
- W3 — an egress call with no destination Mylonite can identify is **refused**:
  `refused: ... no destination argument could be identified`.
- W4 — an unconfirmed consequential call requires **out-of-band approval**. The
  decision is made by an `ApprovalPolicy` supplied by whoever runs the scan (or a
  human), *not* by the model: an earlier design refused the call and asked the model
  to re-supply a server-minted `confirm_token`, which no model completed in practice
  because the advertised tool schema never declared that argument.
- W2 — content read into the session carries **two independent labels**, following
  [FIDES](https://arxiv.org/abs/2505.23643):
    - `integrity` — a read tool's result is *untrusted*. Untrusted context is refused
      only at **destructive** sinks (delete/overwrite/transfer, or anything the server
      marks `destructiveHint`), where an injection-driven call is damage in itself.
    - `confidentiality` — *public* by default; *private* for a tool you list in
      `private_tools`. A public-facing sink refuses to run in a private context, which
      is what stops exfiltration.

  Labels combine most-restrictive-wins across the session. Crucially, ordinary
  read-then-act work is **not** blocked: reading a document and emailing a summary is
  allowed, while reading a *secret* and emailing it is refused. (An earlier
  single-axis version tainted the whole session on any read and refused every
  subsequent sink call, so "the guard resisted" was true by construction.)

The first time this fires for a given tool name in a run, Mylonite logs a warning
(once per tool name) with the exact `control_config` snippet to paste to classify it
precisely — either to confirm it with the right list/argument name, or (by omitting it
from a *non-empty* declared list) to exempt it entirely. W1 has no comparable warning:
it sanitizes every tool description unconditionally, regardless of name, so there is
nothing to classify or exempt.

If your custom target has a read/egress/consequential tool with an unusual name (e.g.
`materialise_record`, `dispatch_widget`, `relay_message`), declare it up front so the
run doesn't spend a cycle discovering it:

```yaml
control_config:
  read_tool_names: [materialise_record]
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
