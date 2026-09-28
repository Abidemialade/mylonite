# CLI reference

Every command, its key options, and a worked example. Run `mylonite COMMAND --help` for
the authoritative, always-current list (the help strings and usage examples live in the
CLI itself). Global options `--api-key-file` and `--env-file` work before any command.

**Exit codes:** `0` ok/kept · `1` `check --enforce`: structural findings present · `2`
config or usage error (incl. an empty scan) · `3` LLM-call budget exceeded · `4` provider
unreachable · `5` test rejected (not kept) · `6` `gate`: the test generator returned
nothing (internal collaborator failure) · `7` `gate`: the validator returned nothing
(internal collaborator failure) · `8` `gate`: the git/gh step failed (your findings and
validation report are still in `--out`).

Budget exhaustion always exits `3`, whichever layer of the run observes it first.

**No LLM credential configured?** `scan`, `gate`, `validate` and `ablate` all check
every model they will call before doing any work and exit `2` naming the missing
environment variable. The message also offers a way past it that needs no key at
all: `--model ollama_chat/llama3.2:3b` with [Ollama running](self-hosted-models.md)
locally, or, on `scan` only, `--dry-run` to preview the run with no LLM calls.
`validate`'s exit `4` (a credential IS set but the provider can't be reached, on
either the custom-target or the reference-target path) points at the same
local model.

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

## `check` — static structural pre-check

Zero-key, zero-spend on-ramp: connects to a target ONCE (`describe()` — no LLM call, no
attack) and reports structural exposure from the tool schemas alone. Belongs in CI stage
1, next to lint — cheap enough to run on every push.

Options: `--target-file PATH` (required — or set `target_file:` in `mylonite.yaml`);
`--enforce` (exit `1` on the substantive W1–W4 structural findings instead of reporting and
exiting `0` — the report-then-enforce adoption ramp). The "unpinned descriptions" advisory
is **shown but does not gate**: it fires on every tool of every server on first contact, so
gating on it would make `--enforce` red for everyone and unusable as a CI stage.
`--config mylonite.yaml` (auto-discovered from `./mylonite.yaml` when present).

```bash
mylonite check --target-file app.yaml
mylonite check --target-file app.yaml --enforce   # CI gate once the surface is clean
```

Reports: consequential tools with no approval-shaped sibling tool, descriptions that
steer the agent, tools taking an apparent network destination, content-processing tools
that could carry an indirect-injection payload, unpinned tool descriptions (paste-ready
digests for `control_config.description_pins`), a target-file wiring name
(`seed_arm.tool`, `effect_probe.verify_tool`, or any `control_config` tool-name field)
that isn't among the server's described tools — a typo or a name copied from another
target file — and which weakness classes the surface suggests. Every finding except the
unpinned-descriptions advisory counts toward `--enforce`, including the wiring-name one:
a name that names no real tool means the plant or the effect probe silently never fires.
Every finding is a hint to confirm, never a verdict — `scan`/`gate` are what prove an
attack actually lands.

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
case is higher; see [Sizing --max-llm-calls](ci-gating.md)),
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
filters which seeds run — on a custom target it adds to the target file's declared
`weakness_classes`). For a custom target: `--command`, `--arg`,
`--env`, `--scope`, `--system-prompt[-file]`, `--primary-tool`.

For a custom/`--target-file` target, `scan` (and `gate`) refuses before any LLM call if
a declared `weakness_classes` entry has zero seeds this surface could ever run — see
[Coverage](target-file.md#coverage-a-declared-class-your-surface-cant-run-is-refused-not-silently-dropped).
`--dry-run` downgrades the refusal to a warning; `--allow-no-seed-arm` exempts a
declared W2 with no `seed_arm` from the refusal and proceeds, with its seeds scheduled
and each one honestly reporting NOT TESTED. The check launches the server, so it runs
after the provider key and model checks: a missing key never spawns the target. If the
server can't be described in time, the run exits 2 with that reason instead of skipping
the check. Inferring that `seed_arm` (auto-wire) makes
one `describe()` call to the target with a 20-second budget; a first-run `npx`/`uvx`
server download can genuinely take that long, so a timeout there says so and exits,
rather than the misleading "add a seed_arm" advice.

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

Options: `scan_path` (an `exploit_*.json` or scan dir) or `--latest`; `--out PATH`;
`--target-file PATH` (custom targets — co-locates the YAML so the live test re-drives
your app); `--prove-control` (emit a control-efficacy test).

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
your REAL app instead of the reference build);
`--authorize` (**required** when `--target-file` names a custom target — must equal the
target's declared `scope`, or its family name if no scope is declared; see
[target-file.md](target-file.md)); `--fast`
(skip the differential leg — faster, weaker); `--randomize-exfil/--no-randomize-exfil`
(mint a unique exfil address per run so the finding proves the target blocks ANY attacker
destination, not one demo literal — **defaults ON for live custom-target runs**, off for the
reference/replay path); `--iteration-timeout S`.

The report's notes record the models the test was proved against
(`validated against model: <planner>`, plus the customiser and judge when they differ).
To re-prove a committed test after a model change, see
[Re-validate on a new model](model-upgrade.md).

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

For a `--target-file` target, `gate` refuses before any LLM call if a declared
`weakness_classes` entry has zero seeds this surface could ever run — the same
pre-flight check `scan` runs; see
[Coverage](target-file.md#coverage-a-declared-class-your-surface-cant-run-is-refused-not-silently-dropped).
`gate` does not auto-wire a `seed_arm` the way `scan` does, so for a W2 target without
one, run `scan` first and pass the `target.yaml` it writes to `gate`.

Options: `target` or `--target-file` (a custom target comes only through
`--target-file`; `gate` does not take inline `mcp:custom` flags); `--authorize` (the
target's `scope`, or its family when it declares no scope); `--open-pr` (create the branch,
commit, push, and open the PR via `gh`); `--config`; `--model` (any LiteLLM provider via
a `provider/model` prefix); `--out PATH`; `--max-llm-calls` (a budget for the scan
phase, not a hard ceiling — see [Sizing --max-llm-calls](ci-gating.md));
`--iterations N` (validation-leg iterations, **default 3** — the kept verdict reflects
reproducibility across runs; pass `1` for the fastest, weakest gate); `--runs-on LABEL`
(GitHub runner; use a self-hosted label for in-perimeter MCP backends);
`--workflows/--no-workflows` (**default off**); `--llm-enrich` (append a labelled, unverified LLM fix
suggestion, rendered after the structural recommendation above); `--fast`;
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

```bash
mylonite report .mylonite/scans/<dir> --sarif out.sarif --json finding.json
```

## `ablate` — score the safeguards

Toggle each AI safeguard and report which are **load-bearing**, **security theater**,
**redundant**, **no-attack** (the attack itself never reproduced, so there's nothing to
attribute), or **inconclusive** (a leg of the comparison never produced a trustworthy
result — a crash, a provider outage, a target that failed to launch). See
[the control-efficacy check](validation.md#the-control-efficacy-check).
Under the matrix, `guarded side:` names what played the guarded side — your own
server-layer control (via `control_env`) or Mylonite's boundary control — together with
the claim a load-bearing row earns (see
[Which claim you earned](reading-results.md#which-claim-you-earned)).

Options: `--target-file PATH` (**required** — there is no positional target form, and the
bundled `reference:*` targets are not accepted); `--authorize` (the target's `scope`, or
its family when it declares no scope); `--controls W2,W3,W4`;
`--iterations N`; `--redundancy` (all-minus-one, to tell redundant from theater);
`--max-seeds N`; `--model` (any LiteLLM provider via a `provider/model` prefix).

On a target that declares an `effect_probe`, the raw and guarded legs of each
comparison run one after the other instead of at the same time, so slower is the
cost of a correct read on a target whose evidence lives in state the two legs
would otherwise share (a file, a database, a remote server). A target with no
`effect_probe` keeps running its legs at the same time.

```bash
mylonite ablate --target-file app.yaml --authorize my-app --controls W2,W4 --redundancy
```

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

---

### Run config (`mylonite.yaml`)

`scan`, `gate`, `validate`, `ablate` and `check` accept `--config mylonite.yaml` (auto-discovered from `./mylonite.yaml`)
to declare `target_file` / `authorize` / `provider` / `model` / budget once. An explicit
flag always wins.
