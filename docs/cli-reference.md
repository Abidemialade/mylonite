# CLI reference

Every command, its key options, and a worked example. Run `mylonite COMMAND --help` for
the authoritative, always-current list (the help strings and usage examples live in the
CLI itself). Global options `--api-key-file` and `--env-file` work before any command.

**Hard spend limit.** The global option `--max-llm-requests N` (before the command), or
`MYLONITE_MAX_LLM_REQUESTS=N`, caps every LLM request the whole run sends, retries
included, across scan, validation and gate. It is the hard ceiling:
request N+1 is never sent. The run stops, exits `3`, prints one
[`MYL-ABT-001`](reason-codes.md#myl-abt-001) line naming the limit, and reads NOT
TESTED, never clean. The global option wins over the variable; with neither set
there is no ceiling. While a ceiling is set, Mylonite makes the provider retries itself
(`num_retries` from `mylonite.yaml` or `MYLONITE_NUM_RETRIES`) so each one is
counted. `--max-llm-calls` is a softer per-scan budget, described below.

**Exit codes:** `0` ok/kept · `1` structural findings present (the experimental `check
--enforce` — see [experimental.md](experimental.md)) · `2` config or usage error (incl. an
empty scan) · `3` LLM-call budget or the hard request ceiling exceeded · `4` provider unreachable · `5` test rejected
(not kept) · `6` `gate`: the test generator returned nothing (internal collaborator
failure) · `7` `gate`: the validator returned nothing (internal collaborator failure) · `8`
`gate`: the git/gh step failed (your findings and validation report are still in `--out`).

Budget exhaustion always exits `3`, whichever layer of the run observes it first — and it
wins over a finding, not the other way round: a run that finds a real weakness and then
runs out of `--max-llm-calls` still exits `3`. On `gate`, the finding is still turned into
a test, validated, and gated (the PR is opened or printed) before that exit code is
returned — see [the gate page's precedence note](ci-gating.md#budget-exhaustion-and-findings).

**No LLM credential configured?** `scan`, `gate`, `validate` and `ablate` all check
every model they will call before doing any work and exit `2` naming the missing
environment variable. The message also offers a way past it that needs no key at
all: `--model ollama_chat/llama3.2:3b` with [Ollama running](self-hosted-models.md)
locally, or, on `scan` only, `--dry-run` to preview the run with no LLM calls.
`validate`'s exit `4` (a credential IS set but the provider can't be reached, on
either the custom-target or the reference-target path) points at the same
local model and names the API-key variable for the model's own provider. When the
provider refused the check with a rate limit (HTTP 429), could not be reached, or
stalled, exit `4` says that instead, names the provider and model, and says what to
do; see
[When the provider rate-limits or drops the run](reading-results.md#when-the-provider-rate-limits-or-drops-the-run).

**Which variable does it check?** A provider in Mylonite's approved table (Anthropic,
Ollama, OpenAI, Gemini, Azure OpenAI, Vertex AI, Bedrock, vLLM/any OpenAI-compatible
endpoint, a LiteLLM proxy) is checked for that table's own variable(s) — a self-hosted
route like Ollama/vLLM needs none. A provider outside the table falls back to LiteLLM's
own `<PROVIDER>_API_KEY` naming convention and warns once, the first time. Either way,
this is a local name lookup: Mylonite never calls the provider to run the check.
Vertex AI authenticates via Application Default Credentials, not a key, so it's checked
for `VERTEXAI_PROJECT`/`VERTEXAI_LOCATION` instead. See "The approved-provider registry"
in [self-hosted models](self-hosted-models.md#the-approved-provider-registry) for the
full table — its own page is a later addition.

---

## `demo` — the reference-app playground

Zero-config, zero-key: runs the vulnerable-vs-guarded differential on the bundled
reference agent. This is the fastest way to see what the tool actually does. Needs
`pip install "mylonite[demo]"` (the extra pulls the reference app).

```bash
mylonite demo            # offline replay, instant, no API key
mylonite demo --live     # real calls; needs the recorded model served locally
```

Options: `--live`; `--provider`, `--model` (both `--live` only — replay is pinned to the
provider/model the fixtures were recorded against, and the command says so rather than
silently ignoring the flags).

**What the default mode is, precisely.** It replays LLM responses recorded against the
bundled targets, so it makes no network call and is byte-for-byte deterministic. The
scan, the adapters, the predicates and the differential are the real ones; only the model
responses are canned. The output labels itself `mode: replay (offline)` and carries the
model and date the fixtures were recorded — do not read a replayed number as a fresh
measurement of today's model. `--live` is the fresh measurement.

One deliberate difference from `scan`: the demo runs with the per-seed LLM customiser and
the LLM-judge fallback **off**, so it drives raw seed bodies judged by deterministic
predicates only. That is what makes the recording reproducible. A `--live` `scan` exercises
both of those stages and can legitimately reach a different result.

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
`--weakness-class W2` (repeatable; on `reference:*` and a bundled `mcp:<family>` this
filters which seeds run — on a custom target, `--target-file` or inline `mcp:custom`
flags, it adds to the target file's declared `weakness_classes` instead. Unifying the
two is a deliberate follow-up, not this release. Rejects an unknown or lowercase value,
e.g. `w4`, naming it). For a custom target: `--command`, `--arg`,
`--env`, `--scope`, `--system-prompt`/`--system-prompt-file`, `--primary-tool`.

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
misleading "add a seed_arm" advice.

Every model `scan` resolves (`--model`/`--planner-model`/`--customiser-model`/
`--judge-model`) is checked against LiteLLM's own provider registry once, before any
seed runs (also true of `gate`/`validate`/`ablate`). A value LiteLLM can't route —
including one shaped like `provider/model` with an unknown provider, e.g.
`not-a-real/model` — exits 2 with one message naming the value and `--model`, instead
of a live call failing (and repeating) once per seed.

**Scaffold mode** — `--scaffold PATH` (with `--command`) introspects an MCP server
(one launch, **no LLM call, no attack**, so no `--authorize` needed) and writes a
commented starter `target.yaml` with suggested `weakness_classes` and auto-detected
`seed_arm`/`effect_probe` candidates — only classes the introspected surface can
actually cover are suggested. Add `--force` to overwrite. Edit it, then scan
with `--target-file`.

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

Set it before `check`, `scan` or `gate` loads the file; an unset one stops the load with
exit code 2 and the same `export` line. The scan-directory copy, `generate`'s copy and
`gate`'s copy print the same note. See
[Secrets stay out of the file](target-file.md#secrets-stay-out-of-the-file).

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
`--prove-control` (emit a control-efficacy test).

```bash
mylonite generate --latest --out .mylonite/generated/my-finding
```

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
validation run, on a custom target and on the bundled reference twins alike; a
stuck or slow run is cut off cleanly, counts as no verdict, and never hangs
the job).

The report's notes record the models the test was proved against
(`validated against model: <planner>`, plus the customiser and judge when they differ).
To re-prove a committed test after a model change, see
[Re-validate on a new model](model-upgrade.md).

A kept test exits `0`. If its verdict reads **STABLE, NOT PROVEN** (no differential or
effect proof, see [what the numbers mean](validation.md#what-the-numbers-mean)),
`validate` says the committed test would gate reproduction only, and points you at a
guarded side or an `effect_probe`.

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
`--workflows` scaffolds the two CI templates. Both default to off — changed in 0.8.5,
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
one, run `scan` first and pass the `target.yaml` it writes to `gate`.

`gate` runs its pre-flight checks in this order, all before any LLM call:

1. The repository checks, each exiting `8`: a `--base` that is empty, contains
   whitespace or starts with `-`; with `--open-pr` or `--workflows`, an output
   directory outside the repository; with `--open-pr`, a working tree with staged
   files or uncommitted changes to tracked files.
2. The target, `--authorize`, model, provider key and uncoverable-class checks, each
   exiting `2`.

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
suggestion, rendered after the structural recommendation above); `--fast`;
`--prove-input-control` (for a black-box HTTP/`rest` target, run the input
data-framing differential to measure whether that input defence is load-bearing;
opt-in, otherwise a `rest` target is gated by stability + effect + consensus);
`--randomize-exfil/--no-randomize-exfil` (defaults ON for a live custom target).

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
