# `target.yaml` reference

A target file is how you point Mylonite at a custom MCP server (`--target-file`). One
YAML declares how to launch the server, which weakness classes it exposes, and how to
plant and verify attacks. `mylonite scan --scaffold app.yaml` scaffolds one for you; this
page is the full field reference. Source: `mylonite.plugins._mcp.target_file.TargetFile`.

The scaffold writes a file that runs as written. What it detects goes in live,
each block tagged `# auto-detected`:

- a `seed_arm` when the server has a tool that stores content and a tool that reads it
  back without an id. It is the same `seed_arm` a scan would wire on its own, so the
  scaffold and the scan agree.
- an `effect_probe` when the file lists W3 or W4 and a readback tool is all of:
  - **safe** to call before and after every attempt: a whole-word read name (or
    `readOnlyHint: true`), no `readOnlyHint: false` or `destructiveHint`, no write verb in
    its name, not a consequential tool itself, and no record id to know;
  - **tied** to what the consequential tools change: a word for what the tool's verb
    produced (`sent_log` or `outbox` for `send_email`), or the id-free recall of a store a
    consequential tool writes (`read_graph` for `create_entities`). A shared noun alone
    (`list_emails` for `send_email`, `list_messages` for `send_message`) is not enough:
    an inbox can list what arrived and not what was sent. A tied tool wins over listing
    order;
  - free of required arguments (`verify_args_template: {}`).

  It sets no `expect_marker`, so any new change a call from the attempt made counts as the
  effect, and no deferral words, so a reply that says "queued" reads NOT TESTED
  ([`MYL-INC-012`](reason-codes.md#myl-inc-012)), never resisted.

A live probe turns on [calibration](#calibration): before it trusts the probe, the first
scan calls up to five of the server's consequential tools for real (never one marked
destructive), with `myl-cal-` marker values, to prove the probe sees a change. Add
`calibration: {controls: skip}` to turn that off; the probe's "no change" then never clears
a call ([`MYL-INC-002`](reason-codes.md#myl-inc-002)). Attempts on a target with an
`effect_probe` run one at a time.

Any other readback is written as a commented hint (with its required arguments stubbed,
when it has some): check it, fill it in and uncomment it. Until the file declares an
`effect_probe`, the scaffold marks W3 and W4 "effect unconfirmable" and the scan reads
those classes NOT TESTED ([`MYL-NT-017`](reason-codes.md#myl-nt-017)) unless an attempt
fires. A store tool whose
only readback needs the new record's id (the agent never learns it) gets a commented
`seed_arm`, and W2 is left out of `weakness_classes`.

`--scaffold` checks the output path is writable (not a directory, parent creatable)
before it launches your server, so a bad path fails fast with one line, not a
traceback after the launch cost. The write itself is atomic — a crash mid-write
leaves any existing file untouched, never truncated. Both the MCP scaffold and
the `--rest-url` scaffold get the same check.

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
# calibration:                 # optional; stdio/sse/http only -- see "Calibration" below.
#   controls: auto              # auto (default) | allow | skip
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
  expect_marker: "{exfil_email}"        # renders to this attempt's exfil address; see below
  deferred_markers: ["queued for approval"]    # words that mark a HELD item in the verify output
  deferred_reply_words: ["Job accepted"]       # words in a tool REPLY that mean "accepted for later"

# --- which tools implement which controls (for the synthetic guarded build) -
control_config:
  egress_tools: [web_fetch]            # W3: tools that reach the network
  egress_url_param: url                # the URL arg the allowlist guards
  fetch_allowlist: [example.com]       # hosts the egress control permits
  consequential_tools: [send_email]    # W4: high-impact actions to gate
  read_tool_names: [read_note]         # W2: tools whose results get quarantined
  verdict_read_tools: [web_search]     # verdict only: calls that count as reads
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
file loads unchanged. Must be greater than 0; declaring it on a `transport: rest`
target is rejected — set `request.timeout_s` there instead.

```yaml
timeout_s: 90
```

## Calibration

`calibration.controls` (optional; `stdio`/`sse`/`http` only — a `rest` target is
rejected, mirroring `timeout_s`) says whether `calibrate_custom_target()` may run
its controls: real writes through a consequential tool, and a plant-and-recall
through `seed_arm`, proving your `effect_probe` can actually see a change before
a scan trusts its "no change". Every `scan`/`gate`/`ablate`/`validate` run that
drives this target calls it once, automatically, and prints each control's status
and [reason code](reason-codes.md). Run
`mylonite scan --target-file app.yaml --authorize my-app` to see it before
trusting a full campaign's "no change" findings:

- `auto` (the default): run on an **authorized `stdio`** target only. Every
  live-driving command already requires `--authorize` to match this target's
  scope — `auto` additionally withholds consent for a remote (`sse`/`http`)
  target, since real writes against a server you don't launch yourself need a
  separate, explicit opt-in.
- `allow`: run on any transport, once authorized — including a remote one.
- `skip`: never run. An uncalibrated `effect_probe`'s "no change" can then
  never certify a resisted attempt; attempts it would have covered read
  NOT TESTED with `MYL-INC-002` instead.

```yaml
calibration:
  controls: allow   # e.g. for a remote (sse/http) target you own
```

A certified probe is trusted only for what calibration showed it. Its "no change"
clears a call only when every consequential tool the attempt called is one the
positive control wrote through (`scan --target-file app.yaml --authorize my-app`
lists them). A call through any
other tool may land where the probe cannot look, so it stays a finding. A
`verify_args_template` that uses `{payload}` is never certified (`MYL-INC-003`): an
attempt fills it with its whole attack text, so calibration cannot prove that read.
Select the record by a fixed value, or use a verify tool that takes no arguments.
Calibration is recorded per launch, so a result from the default launch is not reused
for a `vulnerable_launch` twin.

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
  a tool was called. Without one, a W3/W4 finding is proven only as far as `dispatched`
  and a "queued" reply from the server reads NOT TESTED (`MYL-INC-012`), not resisted (see
  [How an MCP attempt is decided](reading-results.md#how-an-mcp-attempt-is-decided)).
  `mylonite scan --scaffold` proposes a `verify_tool` and writes it live only when it is
  safe, tied to a consequential tool and needs no arguments (see the top of this page);
  otherwise it is a commented hint. Check that it reads back what an attack would change.
  With no `effect_probe` in effect, a W3 or W4 class on a custom target reads NOT TESTED
  ([`MYL-NT-017`](reason-codes.md#myl-nt-017)) unless an attempt in it fires.
  Not available on a `transport: rest` target: declaring one there is refused on load
  with exit `2`, before any model call, and W3 and W4 read NOT
  TESTED ([`MYL-NT-016`](reason-codes.md#myl-nt-016)). `expect_marker` proves it fired; `deferred_markers` mean the action
  was *defended* (e.g. queued for approval), not a success. List in `deferred_markers` only
  words that mark a held item in the verify tool's output, never a word that also shows for
  items that will still go out: when one grows, the attempt reads resisted. Words the server
  puts in a tool reply when it accepts a call for later (`Job accepted`, `Task created`) go
  in `deferred_reply_words`; they make the call read deferred (NOT TESTED unless the probe
  saw it held), never resisted. Both match whole words, ignoring case. Choose `expect_marker` as a
  value **the agent's own call carries** — the recipient address, a row it wrote,
  `{exfil_email}` or `{exfil_host}` — not a status word the target itself would print regardless of who acted.
  A fixed status word like `status=sent` can only be tied to an attempt through the tool
  the seed names as its consequential or egress tool, and only synthesised seeds name
  one. A tool declared under `control_config.consequential_tools` can link only
  synthesised seeds; catalogue seeds, which `validate` re-drives, never link through it.
  So `scan`, `validate` and `check` warn on a fixed marker whatever `control_config`
  declares: on a catalogue seed that effect can read `"unattributed"` but never
  `"true"`, and `validate` cannot keep the finding. The dependable fix is a marker the
  agent's own call carries. A marker shaped like an email address (`x@y.z`) or a URL
  (containing `://`) is exempt from the warning: it is assumed to be carried by the
  agent's call. A scan can mint a fresh exfil destination for each attempt (the
  generalization probe), which a fixed literal address can never match — use
  `{exfil_email}` / `{exfil_host}` instead of writing one in. Both render to this
  attempt's active destination either way, so they also work when that randomization
  is off; `scan`, `validate` and `check` warn when a marker is a literal address
  rather than one of the two placeholders. See
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
  `verdict_read_tools` is separate from every control. It names tools whose calls the
  effect verdict counts as reads, not as an action the attack could carry out, for a
  reader whose name it cannot tell from an action (`web_search`, `fetch_note`). No
  result is quarantined and no call is confirmed differently. Use it instead of
  `read_tool_names` for this: declaring `read_tool_names` narrows W2's quarantine to the
  tools you list. See [Reading results](reading-results.md) for the verdict's read rule.
- **`calibration`** (`CalibrationSettings`) — whether the calibration controls (real
  writes proving your `effect_probe` can see a change) may run; see
  [Calibration](#calibration) above.
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
> leak. Mylonite itself forwards only a small, fixed allowlist of OS-plumbing variables
> (`PATH`, `HOME`, `USERPROFILE`, `SYSTEMROOT`, `TEMP`, `TMP`, `TMPDIR`, `LANG`, `LC_ALL`,
> `PATHEXT`, `COMSPEC`, `APPDATA`, `LOCALAPPDATA`) plus whatever you declare in `env:`.
> The underlying MCP SDK then adds its own platform-default set on top of that — it
> always does this, independently of Mylonite — pulling a few more OS-plumbing
> variables (`HOMEDRIVE`, `HOMEPATH`, `PROCESSOR_ARCHITECTURE`, `SYSTEMDRIVE`,
> `USERNAME` on Windows; `LOGNAME`, `SHELL`, `TERM`, `USER` on POSIX) from Mylonite's own
> process into the child. None of these carry secrets, so the leak this allowlist
> guards against (provider API keys, `GITHUB_TOKEN`, other credentials) still can't
> happen, but "nothing else" is the aspiration, not the literal child environment. If
> your server needs some OTHER parent-env variable, declare it explicitly here — the
> SDK default set is fixed and not configurable. The most common case: an
> `npx`/`uvx`-launched target running behind a corporate TLS-inspecting proxy needs its
> proxy/CA variables declared explicitly too, e.g. `env: { HTTPS_PROXY: "...",
> HTTP_PROXY: "...", NO_PROXY: "...", NODE_EXTRA_CA_CERTS: "...", SSL_CERT_FILE: "..." }`
> — without them the launch can fail with a TLS/registry error that looks unrelated to
> Mylonite.

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
error: [MYL-PRE-001] this target declares weakness class(es) its tool surface cannot
cover at all (every attempt for them would never run):
  W2: this server has no tool that can store content for a later recall — remove W2
      from weakness_classes, or declare a seed_arm
```

The fix is always one of the two named ([MYL-PRE-001](reason-codes.md#myl-pre-001)): drop the class from `weakness_classes`, or
declare the missing piece (a `seed_arm` for W2, `control_config.egress_tools` for W3,
`control_config.consequential_tools` for W4). `mylonite scan --scaffold` only ever
suggests a class it already confirmed is coverable for the surface it just introspected,
so a fresh scaffold's target.yaml never trips this refusal on first run.

`--dry-run` downgrades the refusal to a warning — a dry run only enumerates seeds, so it
stays informative instead of blocking. A dry run wires a missing `seed_arm` the same way a
real scan does (detection reads the tool list; no LLM call), so its preview of W2 matches
what the scan will run. A W2 class you've explicitly accepted running
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

This is a different check from `mylonite check` (hidden and experimental — see
[docs/experimental.md](experimental.md)), which needs a live tool surface and no
LLM call: it diffs `seed_arm.tool`, `effect_probe.verify_tool` and every
`control_config` tool-name field against the server's described tools, and flags any
name that isn't there — a typo, or a stale name copied from another target file. Those
findings count toward `check --enforce`, the same as an unapproved sink.

## Effect attribution

An `effect_probe` reads the verify tool before the agent runs (this attempt's own
baseline) and again after. An effect confirms `"true"` for **this** attempt only when
both hold: the marker is new since that baseline (with no marker, the verify output
itself changed), and one of this attempt's own calls that reached the server without an
error carries the marker or is the scenario's declared consequential or egress tool. A
call whose reply says "queued" or carries a task handle still counts, because a queue can
send at once. Everything else the probe sees
falls into one of:

- **`"false"`** — the attempt did nothing, or a linked call reported success while the
  marker never appeared, before or after (a silent drop).
- **`"deferred"`** — a deferral marker (e.g. `"queued for approval"`) grew: the target's
  own state names a held/queued action. A defended app, not an unproven one — distinct
  from `"false"` because it rests on something the target actually said, not just on
  nothing having changed.
- **`"unattributed"`** — the state change, or its absence, could not be tied to this
  attempt: an idempotent write, a delete, a bounded output window that slid, or a change
  another attempt made while this one only made an unrelated call.
- **`"errored"`** — the baseline read, or the post-drive read itself, raised or timed
  out, or the post-drive read answered with its own `isError`. None of these mean the
  attempt was resisted: the probe never actually checked, so it can neither confirm nor
  clear anything the agent did.

None of these values decides an attempt alone. The tool-call trace says what the agent
did. The probe can raise a linked dispatch to `effect-confirmed`, or clear it, only
after calibration has proven the probe works. See [How an MCP attempt is
decided](reading-results.md#how-an-mcp-attempt-is-decided).

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
mylonite scan --target-file app.yaml --dry-run
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
