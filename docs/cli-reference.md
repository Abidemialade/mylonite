# CLI reference

Every command, its key options, and a worked example. Run `mylonite COMMAND --help` for
the authoritative, always-current list (the help strings and usage examples live in the
CLI itself). Global options `--api-key-file` and `--env-file` work before any command.
Beyond recognised provider credential/config names, `--env-file` also loads every
`MYLONITE_TARGET_...`-prefixed name and every name the run's own `--target-file` (if
any) references as `${NAME}` — see
[Secrets stay out of the file](target-file.md#secrets-stay-out-of-the-file). A
recognised value that is itself an unresolved `${VAR}`-shaped placeholder (never
substituted by a templating tool or secrets manager) is a config error naming the
variable and the file, not a silent load of that literal text as a credential.

**Hard spend limit.** The global option `--max-llm-requests N` (before the command), or
`MYLONITE_MAX_LLM_REQUESTS=N`, caps every LLM request the whole run sends, retries
included, across scan, validation and gate. It is the hard ceiling:
request N+1 is never sent. The run stops, exits `3`, prints one
[`MYL-ABT-001`](reason-codes.md#myl-abt-001) line naming the limit, and reads NOT
TESTED, never clean. The global option wins over the variable; with neither set
there is no ceiling. While a ceiling is set, Mylonite makes the provider retries itself
(`num_retries` from `mylonite.yaml` or `MYLONITE_NUM_RETRIES`) so each one is
counted. `--max-llm-calls` is a softer per-scan budget, described below.

**Extra LLM headers.** Some keys need a header on every request beyond the key itself:
an unscoped Anthropic key needs its workspace id, and some gateways route on a header.
Pass `--llm-header NAME=VALUE` before the command (repeat it for more than one), or set
`MYLONITE_LLM_HEADERS` to comma-separated `NAME=VALUE` pairs (a value can't contain a
comma there; use the flag for one that does); the flag wins over the variable for the
same name. `--env-file` loads `MYLONITE_LLM_HEADERS` too, so the header can sit next to
the key. Use the header name your provider's error names; for example:

```bash
mylonite --llm-header anthropic-workspace-id=<your-workspace-id> scan reference:vulnerable
```

Header values are treated as secrets. They go to the provider and nowhere else: the
console, artefacts, fixtures and replay cache keys never carry them, and Mylonite's
log filters mask them in log messages, tracebacks and extra fields (including LiteLLM's
own loggers).
Values shorter than 4 characters are not masked. A malformed entry exits `2`, and the
error names only the entry's position, never any part of it. LiteLLM's own debug
logging (`LITELLM_LOG=DEBUG`) prints request headers; leave it off when a header carries
a secret.

**Key check before the target starts.** `scan`, `validate`, `gate` and `ablate` send one
tiny request per distinct role model (a few tokens, no retries, counted against
`--max-llm-requests`) before they launch or touch the target. If the provider refuses
the key, the run stops with one line and exit `4`: an invalid or expired key (HTTP 401)
names the key variable, and a key that needs an extra header (HTTP 400, for example a
missing workspace id) names `--llm-header`, `MYLONITE_LLM_HEADERS` and the header the
provider's error names. Local providers
(Ollama, vLLM) are skipped. A timeout or rate limit on this request does not stop the
run; the later reachability check reports those. A key that is not set at all still
exits `2` before any request.

**Exit codes:** `0` ok (for `gate`: the scan ran and found nothing) · `1` structural findings present (the experimental `check
--enforce` — see [experimental.md](experimental.md)) · `2` config or usage error (incl. an
empty scan) · `3` LLM-call budget or the hard request ceiling exceeded · `4` no model
chosen, the provider refused the key or a required header, or the chosen provider
unreachable · `5` test rejected
(not kept), or `generate` refused an input whose validation did not keep it · `6`
`gate`: the test generator returned nothing (internal collaborator failure) · `7` `gate`: the validator returned nothing (internal collaborator failure) · `8`
`gate`: the git/gh step failed (your findings and validation report are still in `--out`) ·
`9` `gate`: at least one proven finding was kept and its gate test written · `10` `gate`:
nothing was kept, but at least one finding reproduced without proof (STABLE, NOT PROVEN); it
is listed as a candidate and no test is written.

`gate` writes a gate test only for a finding whose verdict is KEPT: a passing build and a
passing differential or effect leg. A finding that reproduced but proved nothing is a
candidate. `gate` prints it with the reason and how to get it proven, lists it in the PR
body when something else was kept, and keeps its evidence outside the gate directory.
`validate` on its own still exits `0` for a STABLE, NOT PROVEN test (see below).

Budget exhaustion always exits `3`, whichever layer of the run observes it first — and it
wins over a finding, not the other way round: a run that finds a real weakness and then
runs out of `--max-llm-calls` still exits `3`. On `gate`, the finding is still turned into
a test, validated, and gated (the PR is opened or printed) before that exit code is
returned — see [the gate page's precedence note](ci-gating.md#budget-exhaustion-and-findings).

**No model chosen at all?** There is no default provider or model. `scan`, `gate`,
`validate` and `ablate` each need one picked before touching a target — via
`--model`, `mylonite.yaml`'s `model:` key, or `MYLONITE_MODEL`. With all three
unset, the command prints one line naming every approved provider, an example
`--model` value and the environment variable it needs, then exits `4` — before
any adapter, subprocess or LLM call, `--dry-run` included. `check`, `scan
--scaffold` (introspection only — no LLM call either way) and `mylonite demo`'s
offline replay never need a model and keep working with nothing configured.

**Model chosen, no credential for it?** `scan`, `gate`, `validate` and `ablate`
all check every model they will call before doing any other work and exit `2`
naming the missing environment variable. The message also offers a way past it
that needs no key at all: `--model ollama_chat/llama3.2:3b` with [Ollama
running](self-hosted-models.md) locally, or, on `scan` only, `--dry-run` to
preview the run with no LLM calls (this credential check, unlike the one above,
is skipped under `--dry-run`). `validate`'s exit `4` (a credential IS set but
the provider can't be reached, on either the custom-target or the
reference-target path) points at the same local model and names the API-key
variable for the model's own provider. When the provider refused the check
with a rate limit (HTTP 429), could not be reached, or stalled, exit `4` says
that instead, names the provider and model, and says what to do; see
[When the provider rate-limits or drops the run](reading-results.md#when-the-provider-rate-limits-or-drops-the-run).

**Which variable does it check?** A provider in Mylonite's approved table (Anthropic,
Ollama, OpenAI, Gemini, Azure OpenAI, Vertex AI, Bedrock, vLLM/any OpenAI-compatible
endpoint, a LiteLLM proxy) is checked for that table's own variable(s) — a self-hosted
route like Ollama/vLLM needs none. A provider outside the table falls back to LiteLLM's
own `<PROVIDER>_API_KEY` naming convention and warns once, the first time. Either way,
this is a local name lookup: Mylonite never calls the provider to run the check.
Vertex AI authenticates via Application Default Credentials, not a key, so it's checked
for `VERTEXAI_PROJECT`/`VERTEXAI_LOCATION` instead. See [Choose a model](choose-a-model.md)
for the full provider table, how `--env-file`/`--api-key-file` and the ambient shell
environment stack up when more than one sets the same variable, and a per-command
needs-a-key table.

---

## `demo` — the reference-app playground

Zero-config, zero-key: shows one kept finding end to end, then the
vulnerable-vs-guarded scan behind it, on the bundled reference agent. This is the
fastest way to see what the tool actually does. Needs
`pip install "mylonite[demo]"` (the extra pulls the reference app).

```bash
mylonite demo            # offline replay, a few seconds, no API key
mylonite demo --live     # the scan makes real calls with the model you choose
```

What it prints, in order:

1. **The kept finding** (W4, an email sent with no approval step). The verdict is
   re-derived from a recorded run of the validator: fired without the safeguard,
   resisted with it, held under a deterministic rewording, and the generated test
   collects. Then come the severity, impact and suggested fix that `validate` and the
   gate PR print.
2. **Its regression test, red then green.** The generated test's check fails on the
   vulnerable build, and the test file itself passes on the guarded build, both
   replayed from recordings.
3. **The scan table** for W1 to W4 on both builds, the headline counts, a coverage
   note, and a legend for every mark.

The kept finding rests on one recorded run per build; a live `validate` repeats each
build several times. W1 does not land in the recording (see
[limitations](limitations.md#12-w1-does-not-land-on-the-reference-app)), and the
output says so instead of leaving a bare NO VERDICT cell.

Options: `--live`; `--provider`, `--model` (both `--live` only — replay is pinned to the
provider/model the fixtures were recorded against, and the command says so rather than
silently ignoring the flags).

**What the default mode is, precisely.** It replays LLM responses recorded against the
bundled targets, so it makes no network call and is byte-for-byte deterministic. The
scan, the adapters, the predicates and the differential are the real ones; only the model
responses are canned. The output labels itself `mode: replay (offline)` and carries the
model and date the fixtures were recorded — do not read a replayed number as a fresh
measurement of today's model. `--live` is the fresh measurement.

One deliberate difference from `scan`: the demo's scan table runs with the per-seed LLM
customiser and the LLM-judge fallback **off**, so it drives raw seed bodies judged by
deterministic predicates only. That is what makes the recording reproducible. A `--live`
`scan` exercises both of those stages and can legitimately reach a different result. The
kept finding is the exception: it replays the validator's own recorded run, customiser and
judge included, so `--live` changes the scan table and never the kept finding.

If fixtures are missing or stale the command **fails** with exit `2` and tells you to
re-record. It does not fall back to a live call, and it does not render a clean result —
a stale fixture would otherwise make the vulnerable side look guarded. See
[the reference app](quarry.md).

> **`check` is experimental.** A structural, no-LLM pre-check of a tool surface used to be
> documented here. It still exists, but it's hidden and needs `MYLONITE_EXPERIMENTAL=1` —
> see [experimental.md](experimental.md).

## `scan` — find weaknesses

Run the exploit-finding loop against a target.

**Target** (positional): `reference:vulnerable` / `reference:guarded` (the bundled
reference app builds), or `mcp:custom` with `--command`/`--arg`. Omit when using `--target-file`
(your own MCP app). Non-reference targets need `--authorize`.

Key options: `--target-file PATH` (a path that doesn't exist prints the exact
`--scaffold` command that creates one, and points at
[target.yaml](target-file.md)), `--authorize NAME` (must equal the target's `scope`,
or its family when it declares no scope; a missing value prints the one to pass, and a
bundled target that needs a scope, such as `mcp:filesystem`, prints the `mcp:filesystem:<scope>`
form), `--model` (any LiteLLM
provider via a `provider/model` prefix, e.g. `openai/gpt-4o`),
`--planner-model`, `--customiser-model`, `--judge-model`, `--max-llm-calls N`
(a budget, not a hard ceiling — every seed keeps a floor of it, so the worst
case is higher; see [Sizing --max-llm-calls](ci-gating.md); for a hard limit use
`--max-llm-requests` above),
`--max-concurrent N` (capped at 1 when the target declares an `effect_probe`, since a
concurrent attempt's change to shared state can't be told apart from this attempt's; see
[What the effect probe still cannot see](limitations.md#8-what-the-effect-probe-still-cannot-see)),
`--output-dir PATH`, `--config mylonite.yaml`, `--dry-run`,
`--allow-no-seed-arm`, `--purpose "…"` (a one-line description of what the app is for;
tailors the probes to its domain — overrides `purpose` in the target file, and is
persisted so `generate`/`validate` reuse it); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so a finding proves the target leaks to ANY
attacker destination, not one demo literal — **defaults ON for live custom-target
scans**, off for the reference/replay path; matches `generate`/`validate`/`gate`).
`--weakness-class W2` (repeatable; one meaning everywhere — only these classes run.
On `reference:*` and a bundled `mcp:<family>` it filters which seeds run. On a custom
target, `--target-file` or inline `mcp:custom` flags, it filters the target file's
declared `weakness_classes` the same way — it never widens past what the file
declares; naming only classes it doesn't declare matches nothing and refuses before
any spend, naming both the flag's values and the file's declared ones. With no
`weakness_classes` declared at all, the flag declares them instead — the same thing
the inline `mcp:custom` flags already do with nothing else to set them. Rejects an
unknown or lowercase value, e.g. `w4`, naming it). For a custom target: `--command`,
`--arg`, `--env`, `--scope`, `--system-prompt`/`--system-prompt-file`, `--primary-tool`.
`--command`/`--arg`/`--env` build an INLINE target from flags; combining any of them
with `--target-file` (which already fully describes the target) refuses with exit `2`
naming the flag(s) passed, except with `--scaffold`, which uses them to BUILD the file
in the first place.

If an attack module that would have run fails to import or construct, `scan` (and
`gate`) runs the rest and reports each weakness class that module covers as NOT TESTED
with [`MYL-NT-015`](reason-codes.md#myl-nt-015). An `attack modules:` line names the
module, and a scan with no finding exits `2`.

For a custom/`--target-file` target, `scan` (and `gate`) refuses before any LLM call if
a declared `weakness_classes` entry has zero seeds this surface could ever run — see
[Coverage](target-file.md#coverage-a-declared-class-your-surface-cant-run-is-refused-not-silently-dropped).
`--dry-run` downgrades the refusal to a warning; `--allow-no-seed-arm` exempts a
declared W2 with no `seed_arm` from the refusal and proceeds, with its seeds scheduled
and each one honestly reporting NOT TESTED. The refusal's own `describe()` call runs
after the provider key and model checks, so a missing key or a bad `--model` never
reaches it. Inferring `seed_arm` (auto-wire) is a separate, earlier probe: it runs
after the model check but before the key check, so a target with a declared W2 and no
`seed_arm` can still launch the server once with no key set. If either probe can't
describe the server in time, the run exits 2 with that reason instead of skipping the
check. Auto-wire's `describe()` call carries a budget of at least 20 seconds (more if
the target file's `timeout_s` is larger — see
[target-file.md](target-file.md#mcp-session-timeout)); a first-run `npx`/`uvx` server
download can genuinely take that long. A timeout there names `timeout_s` and says to
re-run (the download is cached after that) or raise `timeout_s`, and exits — never the
misleading "add a seed_arm" advice. `--dry-run` runs the auto-wire too (it reads the
tool list and makes no LLM call; the model check is skipped), so a dry run previews W2
the way the real scan will run it.

Every model `scan` resolves (`--model`/`--planner-model`/`--customiser-model`/
`--judge-model`) is checked against LiteLLM's own provider registry once, before any
seed runs (also true of `gate`/`validate`/`ablate`). A value LiteLLM can't route —
including one shaped like `provider/model` with an unknown provider, e.g.
`not-a-real/model` — exits 2 with one message naming the value and `--model`, instead
of a live call failing (and repeating) once per seed.

Before any live call, `scan` prints one line estimating how many LLM calls the
run will make, from the seed count after filters — a range, since a seed can
need anywhere from a couple of calls to several. It also names the hard
ceiling (`--max-llm-requests`/`MYLONITE_MAX_LLM_REQUESTS`) when one is set, and
says cost is unknown rather than guessing a price (no provider carries one
yet). `--dry-run` makes no call and skips this line.

Just before the estimate, `scan` prints a short run plan, ahead of calibration's control
writes and the first model call:

```text
Run plan (nothing has been sent yet):
  Model: openai/gpt-4o-mini (planner, customiser and judge)
  System prompt: declared in prompt.txt (system_prompt_file)
  Consequential tools this run may drive: send_email, create_ticket
  never_call (blocked before the server): wipe_account
Run against a test instance, never production.
```

The tools come from the target's tool list, minus anything under
[`control_config.never_call`](target-file.md#never_call-tools-mylonite-must-never-call),
which Mylonite blocks before the server. With no `system_prompt` or `system_prompt_file`
declared, the plan names Mylonite's generic default prompt and adds a warning that says how
to declare yours. `--dry-run` skips the plan too.

**Scaffold mode** — `--scaffold PATH` (with `--command`) introspects an MCP server
(one launch, **no LLM call, no attack**, so no `--authorize` needed) and writes a
`target.yaml` that runs as written: the `weakness_classes` the introspected surface can
cover, plus a `seed_arm` and an `effect_probe` written live, tagged `# auto-detected`,
when it finds them (see [target-file.md](target-file.md)). A candidate that still needs
a value from you stays commented. Add `--force` to overwrite. Review it, then scan with
`--target-file`.

The one launch `--scaffold` makes (and `check`'s, and the first connect a scan/gate
makes) gets a generous 120-second budget by default, since a first `npx -y <package>`
or `uvx <package>` run downloads the package before the server can answer at all. If it
still times out, the message names the budget and both fixes: run the server's launch
command once yourself first (or install the package), or raise the timeout — there is
no `--target-file` yet at this point to set `timeout_s` in, so set the
`MYLONITE_MCP_STARTUP_TIMEOUT_S` env var instead (ignored once a target file sets
`timeout_s`; see [target-file.md](target-file.md#mcp-session-timeout)).

The file also lists every tool in a comment block, the tool inventory: each tool's role
(consequential, egress, read, store, recall), where that role came from (`declared` in
the target file, the server's MCP `annotation`, a `schema` parameter, the tool's `name`,
or `unknown`), and whether the scan's confirm gate treats it as consequential. A tool
nothing recognises reads `unknown` and is treated as consequential, which is what the
scan already does with it. The scaffold names the unknown tools when it finishes. To
confirm them, list your consequential tools under `control_config.consequential_tools`;
every tool left off that list is then treated as not consequential. The block is
comments only, so the scan reads the same file either way.

To scaffold a REST/HTTP agent instead of an MCP server, pass `--rest-url URL` (no
`--command` needed) — add `--rest-body` for a request-body template other than the
default `{"prompt": "{prompt}"}`, and `--rest-response-path` for a dotted path into
the JSON reply (e.g. `choices.0.message.content`) when the agent's answer isn't the
whole body. See [the HTTP-agent walkthrough](http-agent.md).

```bash
mylonite scan --command python --arg my_server.py --scaffold app.yaml --scope my-app  # generate the target file
mylonite scan --target-file app.yaml --authorize my-app                                # then scan it
```

A secret passed with `--env` (for example `--env GITHUB_TOKEN=ghp_...`) is not written
to the file. The file gets a `${MYLONITE_TARGET_ENV_GITHUB_TOKEN}` placeholder, and
scaffold prints the variable to set, before its `next:` line, in both shell forms:

```text
note: secrets in headers and env were kept out of app.yaml. It reads them from these environment variables; set them before you use the file:
  bash/zsh:
    export MYLONITE_TARGET_ENV_GITHUB_TOKEN='<your GITHUB_TOKEN>'
  PowerShell:
    $env:MYLONITE_TARGET_ENV_GITHUB_TOKEN = '<your GITHUB_TOKEN>'
```

`args` has no key name to mask a value by, so a credential passed through `--arg`
instead (an `api-key=sk-...`-shaped flag, a URL with `?access_token=...`) is still
written in plain text — but now warns, naming the position and withholding the value:
`args[0] looks like it carries a credential (value withheld). Move it to env: ...`. See
[A credential in args is written in plain text](target-file.md#a-credential-in-args-is-written-in-plain-text-and-now-warns).

Set it before `check`, `scan` or `gate` loads the file; an unset one stops the load with
exit code 2 and the same `export` line. The scan-directory copy, `generate`'s copy and
`gate`'s copy print the same note. See
[Secrets stay out of the file](target-file.md#secrets-stay-out-of-the-file).

When a scan finds something, the summary table is followed by one block per finding,
most severe first: a `Severity` line, a one-sentence `Impact` line naming what an
attacker gets from that weakness class, and a suggested fix — the same facts the
[gate PR body](ci-gating.md) opens with, reused rather than re-derived, so the fix is
never exclusive to a committed test or a validated directory. It is always introduced
as a suggestion; `scan` proves and gates a weakness, it does not patch your code. The
`Next: mylonite generate …` hint follows the last block, with the scan directory's
path rendered with forward slashes on every platform (so it needs no quoting on its
own, and parses the same way in cmd, PowerShell or bash).

## `generate` — emit the regression test

Emit a pytest regression test from a confirmed exploit. Offline and deterministic — no
LLM call. Carries the compliance metadata.

Options: `scan_path` (an `exploit_*.json` or scan dir) or `--latest` (searches
`--scans-dir`, default the resolved scans dir, normally `.mylonite/scans` — an
input, where `--latest` looks for a scan to read, not where this command writes;
ignored when you pass `scan_path` directly); `--out PATH`;
`--target-file PATH` (custom targets — co-locates the YAML so the live test re-drives
your app; usually not needed, since this auto-resolves `target.yaml` from the scan
directory `scan_path` points at — pass it only when that file isn't there);
`--prove-control` (emit a control-efficacy test); `--unvalidated` (see below).

```bash
mylonite generate --latest --out .mylonite/generated/my-finding
```

A test written from a scan is a candidate until `validate` keeps it, so its first
line reads `# mylonite: unvalidated` and a short UNVALIDATED header follows. The
command prints an UNVALIDATED line with the `validate` command to run, literally —
for a custom target it carries the `--authorize` value that target's `scope` (or
family, if it declares none) requires, and every printed path renders with forward
slashes on every platform (quoted too, only if it still needs it — a space, say).
The "set your provider key" line next to it names that finding's
own provider's env var (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, ...), or "your
provider's API key" — naming no vendor — when the provider isn't known. When
`validate` returns **KEPT** it removes the header; a **STABLE, NOT PROVEN** or
**REJECTED** verdict adds it back, also to a test that was kept before or written
without one. The header always matches the latest verdict.

`generate` reads the `validation_report.json` next to the input exploit, if there
is one (`validate` and `gate` write it). If it is REJECTED, STABLE, NOT PROVEN or
unreadable, `generate` writes nothing and exits `5`. Pass `--unvalidated` to write
the test anyway, with the header. If it is KEPT, the test goes without the header
only when that report proved this exact test: the folder holds one exploit, the
exploit and the folder's `target.yaml` are no newer than the report, any
`--target-file` matches that `target.yaml`, `--prove-control` is off, and the test
the report names matches the one about to be written. Otherwise the test is stamped.

## `validate` — prove the test

Run the generated test through the [validation engine](validation.md), LIVE. On a real
`--target-file` app the [control-efficacy check](validation.md#the-control-efficacy-check)
holds the model constant and toggles only the safeguard; against the bundled reference app
it runs the two-build differential. A test is **kept** only when it discriminates reliably.

Options: `target` (the generated dir/file); `--iterations N` (default 5); `--model`
(any LiteLLM provider via a `provider/model` prefix); `--planner-model`,
`--customiser-model`, `--judge-model` (the three [model roles](attack-modes.md#composing-the-model-roles),
each defaulting to `--model`); `--config PATH`; `--target-file PATH` (re-drive
your REAL app instead of the reference build — usually not needed: for a custom
target this auto-resolves `target.yaml` co-located with the test, the same file
`generate` wrote; pass it explicitly only when that file isn't there);
`--authorize` (**required** when `--target-file` names a custom target — must equal the
target's declared `scope`, or its family name if no scope is declared; see
[target-file.md](target-file.md)); `--fast`
(skip the differential leg — faster, weaker); `--prove-input-control` (for a
black-box HTTP/`rest` target, run the input data-framing ("spotlighting")
differential to measure whether that input defence is load-bearing; a no-op once
`--fast` has already skipped the differential leg); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so the finding proves the target blocks ANY attacker
destination, not one demo literal — **defaults ON for live custom-target runs**, off for the
reference/replay path); `--iteration-timeout S` (default 120s — the wall-clock budget for each
differential run, on a custom target and on the bundled reference twins alike; a
stuck or slow run is cut off cleanly, is reported as reaching no verdict, never
counts as the guard resisting, and never hangs the job. The robustness re-drives
and the fixture recording have their own call budget instead).

Before any live call, `validate` also prints one line estimating how many LLM
calls the run will make — from `--iterations`, the twin count, and (on the
reference target) the metamorphic re-drive count — plus the hard ceiling
(`--max-llm-requests`/`MYLONITE_MAX_LLM_REQUESTS`) when one is set. It never
prices the run: no provider carries a price yet. The same run plan as `scan` comes
first; on a custom target its tool line names the declared consequential and egress
tools, or else the calls the recorded finding made.

Before any live run, `validate` prints a banner naming the model it resolved
(`--model`/`mylonite.yaml`/`MYLONITE_MODEL`) and checks that model — and the planner,
customiser and judge models when they differ — is reachable with one tiny completion
each, not a full scan, so a slow-but-working model (a local or self-hosted one in
particular) answers well inside `--iteration-timeout` instead of being misdiagnosed as
unreachable. The check honours a configured `api_base` (see
[Self-hosted models](self-hosted-models.md)).

The report's notes record the models the test was proved against
(`validated against model: <planner>`, plus the customiser and judge when they differ).
To re-prove a committed test after a model change, see
[Re-validate on a new model](model-upgrade.md).

A kept test exits `0`. A plain **KEPT** verdict is followed by the same severity,
impact and suggested-fix block `scan` shows under a finding, before the "Next: commit"
line — so the fix is shown here too, not only in the gate PR body. If its verdict
reads **STABLE, NOT PROVEN** (no differential or
effect proof, see [what the numbers mean](validation.md#what-the-numbers-mean)),
`validate` says the committed test would gate reproduction only, and points you at a
guarded side or an `effect_probe` — without the severity/impact/fix block, since
nothing was proven yet.

A run that cannot reach a verdict stops with one line and no traceback. It exits `3`
(`MYL-ABT-001`) when the LLM call budget runs out mid-run, and `2` (`MYL-ABT-006`)
when a custom target does not come up, so a run could not even describe it. If the
target went down after some runs finished, the line says how many and that their
results were discarded. Neither is reported as a rejected test. `gate` reports a
target that does not come up the same way, and says later findings were not
validated.

When it finishes, `validate` prints an `llm:` line with the calls it made (by role), the
tokens the provider reported, and the wall-clock time. The metamorphic stage runs under
its own call budget; if that budget is reached before every perturbation has run, the
stage does not pass.

```bash
mylonite validate .mylonite/generated/my-finding --target-file app.yaml --authorize my-app
```

## `gate` — scan → generate → validate → PR (the full pipeline)

The whole pipeline; only a kept test makes it through. The PR body always includes a
**Proven fix** (control-efficacy findings) or **Recommended fix** (otherwise) — an
evidence-anchored recommendation naming the actual tool and argument that landed the
exploit, as a fenced code sketch. See [Reading the
results](reading-results.md#the-gating-pr).

**`gate` does not modify your repository unless you ask it to.** By default it writes
only to `--out` (normally `.mylonite/gate/`) and prints the `git`/`gh` commands to
commit and open the PR yourself. `--open-pr` performs the branch/commit/push/PR;
`--workflows` scaffolds the two CI templates, but only once this run has kept at
least one finding — a run that keeps nothing writes no workflow file, and says so,
naming why. Both default to off — changed in 0.8.5,
where `--workflows` defaulted on and the branch and commit happened on every run.
Either flag resolves the repository root with `git rev-parse --show-toplevel` — so
`gate` works from any subdirectory — and fails fast, on exit code 8, outside a git
repository entirely.

`gate` generates, validates, and (for every KEPT one) gates **every** finding the
scan proves, not just the first — one branch, one PR, in deterministic pattern-id
order. See [Gating every finding](ci-gating.md#gating-every-finding) for the branch
naming, the multi-finding console output, and the budget-exhaustion-with-findings
exit code.

For a `--target-file` target, `gate` refuses before any LLM call if a declared
`weakness_classes` entry has zero seeds this surface could ever run — the same
pre-flight check `scan` runs; see
[Coverage](target-file.md#coverage-a-declared-class-your-surface-cant-run-is-refused-not-silently-dropped).
`gate` does not auto-wire a `seed_arm` the way `scan` does, so for a W2 target without
one, run `scan` first and pass the `target.yaml` it writes to `gate` — or pass
`--allow-no-seed-arm` to gate it as-is: those seeds report NOT TESTED instead of
blocking the whole run, the same meaning the flag has on `scan`.

`gate` runs its pre-flight checks in this order, all before any LLM call:

1. The repository checks, each exiting `8`: a `--base` that is empty, contains
   whitespace or starts with `-`; with `--open-pr` or `--workflows`, an output
   directory outside the repository; with `--open-pr`, a working tree with staged
   files or uncommitted changes to tracked files.
2. On Windows without long paths, the output path check, exiting `2` (see
   [Windows path length](ci-gating.md#windows-path-length)).
3. The target, `--authorize`, model, provider key and uncoverable-class checks, each
   exiting `2`. A bundled `mcp:<family>[:scope]` target combined with `--open-pr` or
   `--workflows` is refused here too, before the scan runs: that target has no
   `target.yaml` of its own for the gate to commit, so the scaffolded workflow could
   never launch it in CI. Run `mylonite scan --scaffold <path>` to write one, then
   gate with `--target-file <path>` instead. Dropping both flags still gates the
   bundled target and writes its artefacts locally, unchanged.

So when both kinds of problem are present, the exit-`8` error is the one you see first.

Options: `target` or `--target-file` (a custom target comes only through
`--target-file`; `gate` does not take inline `mcp:custom` flags); `--authorize` (the
target's `scope`, or its family when it declares no scope); `--open-pr` (create the branch,
commit, push, and open the PR via `gh`; refused on a tree with staged or uncommitted
changes, and a rollback never deletes a branch the run didn't create; after the commit it
returns you to the branch or detached commit you started on and keeps the gate branch,
naming it in the output); `--base BRANCH` (the branch the PR targets; defaults to the
repository's default branch: `origin/HEAD`, else the current branch's upstream, else
`main`; running from a feature branch, pass `--base`); `--config`; `--model` (any LiteLLM provider via
a `provider/model` prefix); `--planner-model`, `--customiser-model`, `--judge-model`
(the three [model roles](attack-modes.md#composing-the-model-roles), each defaulting
to `--model`, same split as `scan`); `--purpose "…"` (a one-line description of what
the app is for; tailors the probes to its domain — overrides `purpose` in the target
file); `--out PATH`; `--max-llm-calls` (a budget for the scan
phase, not a hard ceiling — see [Sizing --max-llm-calls](ci-gating.md); the
global `--max-llm-requests` caps scan and validation together);
`--iterations N` (validation-leg iterations, **default 3** — the kept verdict reflects
reproducibility across runs; pass `1` for the fastest, weakest gate); `--runs-on LABEL`
(GitHub runner; use a self-hosted label for in-perimeter MCP backends);
`--workflows/--no-workflows` (**default off**); `--llm-enrich` (append a labelled, unverified LLM fix
suggestion, rendered after the structural recommendation above); `--fast` (skip the
differential leg for a custom target: `gate` then keeps a finding only when an
`effect_probe` proves it, otherwise the finding is a candidate and `gate` exits `10`);
`--prove-input-control` (for a black-box HTTP/`rest` target, run the input
data-framing differential to measure whether that input defence is load-bearing;
opt-in, otherwise a `rest` target is validated by stability + effect + consensus;
`gate` lists a `rest` finding as a candidate and never commits it);
`--randomize-exfil/--no-randomize-exfil` (defaults ON for a live custom target);
`--allow-no-seed-arm` (gate a custom target that declares an indirect-injection class
like W2 with no `seed_arm` anyway; those seeds report NOT TESTED instead of blocking
the run — `gate` never auto-wires one the way `scan` does, so this is the only way to
gate such a target without running `scan` first).

Before the scan phase starts, `gate` prints one line estimating how many LLM
calls the scan will make (from the seed count after filters), plus about how
many more each finding kept and validated adds — the validation count depends
on how many findings the scan keeps, so it is a per-finding note, not a false
total. It also names the hard ceiling (`--max-llm-requests`/
`MYLONITE_MAX_LLM_REQUESTS`) when one is set; see
[Sizing --max-llm-calls](ci-gating.md) for the full formula. The same run plan as
`scan` comes first.

`gate` ends with a `gate llm:` line: the LLM calls made across every stage (by role), the
tokens the provider reported, and the wall-clock time.

```bash
mylonite gate --target-file app.yaml --authorize my-app --open-pr
```

## `report` — render findings

Render a saved scan or validation as a terminal trust panel — including the same
evidence-anchored recommendation the gating PR carries — offline. See [Reading the
results](reading-results.md).

Options: `target` (a scan dir, a `generate`-emitted dir **once `validate` has run**, or a
`*_report.json`); `--sarif PATH` (SARIF 2.1.0
for GitHub code scanning); `--json PATH` (machine-readable finding bundle). Both carry
the differential proof, the OWASP/ASI/ATLAS/NIST tags, and the same recommendation.
For a scan directory with a `verdicts.json`, `report` also prints the same per-class
summary and calibration status the scan printed (see [The per-class
summary](reading-results.md#the-per-class-summary)).

```bash
mylonite report .mylonite/scans/<dir> --sarif out.sarif --json finding.json
```

> **`ablate` is experimental.** Scoring each safeguard as load-bearing, security theater,
> redundant, no-attack or inconclusive used to be documented here. It still exists, but
> it's hidden and needs `MYLONITE_EXPERIMENTAL=1` — see [experimental.md](experimental.md).

> **Scaffolding moved.** The old `mylonite init-target` command is now `mylonite scan
> --scaffold PATH` (see [`scan`](#scan-find-weaknesses) above). See [Test your own
> app](test-your-app.md) and the [target.yaml reference](target-file.md).

## `version`

Print the installed version.

```bash
mylonite version
```

---

## `plugins`

List installed [extension plugins](plugin-authoring.md) across all five contract
groups, with each plugin's declared contract version. Discovery here also runs
the version-compatibility check, so a major-mismatched plugin is reported rather
than failing silently mid-run. Attack modules are the group that is also *run*
by `scan`/`gate`; the other four use the bundled reference implementation.

```bash
mylonite plugins
```

An adapter marked *"configured per target"* is not broken: the target-adapter
contract flows configuration through the target-file factory, so an adapter for
a named server family is built with that family rather than discovered
ready-made.

A plugin marked *"INCOMPATIBLE"* declares a contract major version this Mylonite
cannot load, and will be skipped at run time. The full listing still prints —
that is the point of the command — and the exit code is non-zero so a scripted
check still catches it.

A plugin marked *"FAILED TO LOAD (ImportError)"* raised when it was imported. An
attack module that raises when built with no arguments is marked the same way, with
its error type, because a scan can't run it either. Only the error type is shown, never
the message. A scan reports such a module's classes NOT TESTED with
[`MYL-NT-015`](reason-codes.md#myl-nt-015).

---

### Run config (`mylonite.yaml`)

`scan`, `gate`, `validate`, `ablate` and `check` accept `--config mylonite.yaml` (auto-discovered from `./mylonite.yaml`)
to declare `target_file` / `authorize` / `provider` / `model` / budget once. An explicit
flag always wins.

Most keys also have a flat `MYLONITE_*` env var, the lowest-precedence source of the
three: an explicit flag wins over `mylonite.yaml`, which wins over the env var, which
wins over the command's own built-in default.

| `mylonite.yaml` key | Env var | What it sets |
|---|---|---|
| `target_file` | — | the custom-target YAML (`--target-file`) |
| `authorize` | — | the ownership assertion (`--authorize`) |
| `provider` | `MYLONITE_PROVIDER` | the LiteLLM provider id — deprecated, prefix `model` instead |
| `model` | `MYLONITE_MODEL` | the model LiteLLM calls |
| `planner_model` | `MYLONITE_PLANNER_MODEL` | the model driving the agent under test; defaults to `model` |
| `customiser_model` | `MYLONITE_CUSTOMISER_MODEL` | the model crafting attack payloads; defaults to `model` |
| `judge_model` | `MYLONITE_JUDGE_MODEL` | the model deciding the LLM-judge fallback verdict; defaults to `model` |
| `max_llm_calls` | — | the process-wide LLM call budget for a scan (`--max-llm-calls`) |
| `api_base` | `MYLONITE_API_BASE` | a self-hosted or proxy LiteLLM endpoint |
| `max_tokens` | `MYLONITE_MAX_TOKENS` | the per-call `max_tokens` |
| `temperature` | `MYLONITE_TEMPERATURE` | the per-call temperature |
| `timeout` | `MYLONITE_TIMEOUT` | the per-call socket timeout, in seconds |
| `num_retries` | `MYLONITE_NUM_RETRIES` | the per-call LiteLLM retry count |
| `root` | `MYLONITE_ROOT` | overrides the artefact root every command's output nests under |

`target_file`, `authorize` and `max_llm_calls` have no flat env var — set them with
`--target-file`/`--authorize`/`--max-llm-calls`, or in `mylonite.yaml`.
