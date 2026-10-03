# Upgrading from 0.10.x / 0.11.x

0.12 changes several things an automated caller or a committed CI workflow can
trip on: there is no default model, `gate`'s exit codes now separate "kept" from
"clean", an unproven finding is never committed, a few commands trade a
traceback for a clean exit code, several reason codes are new or now mean
something more specific, the files `gate` writes are shaped differently on
disk, and credential handling around target files is stricter —
`--env`/`--arg` with `--target-file`, a credential-shaped `--arg` value, and
an unresolved `--env-file` placeholder each now get a named error or warning
instead of silence. Everything here is already in [`CHANGELOG.md`](https://github.com/Abidemialade/mylonite/blob/main/CHANGELOG.md)
under `[Unreleased]`; this page is the upgrade checklist, not a second copy of
that detail.

If you only run `mylonite` by hand against your own app, read
[No default model](#no-default-model) and
[Gate: 9 and 10 replace a bare 0](#gate-9-and-10-replace-a-bare-0), then skip to
whichever other section names something you use. If you have a committed gate
workflow or call `gate-action`, read all of it.

## No default model

**What changed.** `scan`, `generate`'s validation-aware read path, `validate`,
`gate` and `ablate` have never picked a model for you by accident — but a
version you ran against before this release may have had `MYLONITE_MODEL` set
in your shell or CI job from an earlier experiment, and that still worked. It
still works today, too: nothing here removes a model you already configure.
What changed is the message when none is configured at all.

**What you'll see.** With no `--model`, no `model:` in `mylonite.yaml` and no
`MYLONITE_MODEL`, the command exits `4` with one line naming every approved
provider, an example `--model` value and the environment variable it needs —
before it launches your target or makes a call.

**What to do.** Pick a model once, per [Choose a model](choose-a-model.md), and
set it in your shell profile or CI job's env block. No key at all works too:
`--model ollama_chat/llama3.2:3b` with [Ollama running](self-hosted-models.md)
locally.

## Gate: 9 and 10 replace a bare 0

**What changed.** `gate` used to exit `0` both when a scan found nothing and
when it kept a finding. It now reserves `0` for "the scan ran and found
nothing," and reports a kept finding or an unproven candidate as their own exit
codes.

**What you'll see.** `gate` exits `9` when at least one finding was proven and
committed as a gate test, and `10` when nothing was kept but a candidate
remains (see [Never-keep-unproven](#never-keep-unproven) below). `0` now means
only that nothing was found at all.

**What to do.** If a script or CI step treats `gate`'s exit code as a pass/fail
signal, update it: a plain `if [ $? -ne 0 ]` check now fails on `9` and `10`,
which is probably not what you want on a nightly discovery run that is
supposed to keep finding the same unfixed issue. The scaffolded discovery
workflow and `gate-action` already map `0`/`9`/`10` to a green step and fail
only on `1`–`8` — re-run `mylonite gate --workflows` to pick up that mapping if
your workflow predates it (see
[Re-run the scaffold or bump the pin](#re-run-the-scaffold-or-bump-the-pin)).
`gate-action` also gained an `exit-code` output, a `result` output
(`clean`/`kept`/`candidates`), and an opt-in `fail-on` input for a caller that
wants a red check on a specific result.

## Never-keep-unproven

**What changed.** A finding whose validation passed without a passing
differential or effect leg — STABLE, NOT PROVEN — used to be committed as a
gate test anyway. It no longer is.

**What you'll see.** Such a finding is now a candidate: nothing is written to
the gate directory or committed for it. The console explains why and how to
prove it (declare `control_env` and drop `--fast`, or declare an
`effect_probe`), and a multi-finding PR body lists it under "Candidates (not
proven, not committed)." A gate run that keeps nothing but produces a candidate
exits `10`, not `9` or `0`.

**What to do.** If your gate run has been relying on a STABLE, NOT PROVEN test
that was committed under an earlier release, it stays as it was — this change
affects only what a *new* `gate` run writes. Prove the candidate (the console
message says how) to get it committed as a real gate test going forward.

## `validate`: exit 3 for budget, exit 2 for a target that won't launch

**What changed.** `validate` and `gate` used to print a traceback and exit `1`
when the LLM call budget ran out mid-run, and would run every remaining
iteration against a custom target that had already gone down, then report the
attack as not reproduced.

**What you'll see.** A spent call budget now stops with one line and exits `3`
(`MYL-ABT-001`). A custom target that does not come up exits `2`
(`MYL-ABT-006`) at the first failed run; if it went down after some runs
finished, the line says how many ran and that their results were discarded.
Under `gate`, the same line says later findings were not validated.

**What to do.** If a script checked for exit `1` to detect a budget problem,
check for `3` instead. Raise `--max-llm-calls` or `--max-llm-requests` if the
run is genuinely running out of budget rather than hitting a real limit.

## Reason codes: three are new, two now mean something narrower

**What changed.** Coverage gaps that used to read `⚠ N/A (no such capability)`
or disappear from the class summary entirely now read `⚠ NOT TESTED` with a
reason code, so a tool reading `scan_report.json` can always tell *why* a class
reports nothing rather than inferring it from a missing row.

**What you'll see:**

- **`MYL-NT-017`** — a W3 or W4 class ran with no `effect_probe` declared, so
  nothing read the target's state back; the class reads NOT TESTED rather than
  RESISTED. A scan whose only gap is this code now exits `2` where it used to
  exit `0`.
- **`MYL-NT-018`** — a custom target had more candidate tools in a class than
  `seed_tool_ceiling` (see below) allowed probing; each tool past the ceiling
  gets its own NOT TESTED row instead of only a log line.
- **`MYL-NT-019`** — the call budget, provider check or wall-clock limit cut a
  scan off before a seed finished; that seed is now NOT TESTED instead of
  silently dropping out of the class summary.
- **`MYL-INC-012`** — a calibrated `effect_probe` reply that says "queued" (or
  another deferral word) now always reads NOT TESTED instead of RESISTED, on
  every class that declares an `effect_probe`, not only the ones it previously
  covered.
- **`MYL-PRE-006`** — new; see [`--weakness-class` always narrows](#-weakness-class-always-narrows).

**What to do.** Add an `effect_probe` to a target file that declares W3/W4
(`mylonite scan --scaffold` proposes one) to clear `MYL-NT-017`. Raise
`seed_tool_ceiling` in the target file to clear `MYL-NT-018` if you want every
candidate tool probed rather than the first 8. The rest are read-only signal —
no action needed unless you want the class to read RESISTED or FOUND instead
of NOT TESTED. Full wording for every code: [Reason codes](reason-codes.md).

## `--weakness-class` always narrows

**What changed.** `--weakness-class` used to filter a `reference:*` or bundled
`mcp:<family>` target's seeds, but *add to* a custom target's declared
`weakness_classes` — the same flag widening one kind of scan and narrowing
another.

**What you'll see.** `--weakness-class` now filters a custom target's declared
classes the same way it filters a bundled one: naming a class the target also
declares narrows to the overlap. Naming only classes the target does not
declare matches nothing and refuses with one line, `MYL-PRE-006`, before any
LLM call.

**What to do.** If your target file declares `weakness_classes` and you pass
`--weakness-class` for a class outside that list, check the list first — that
scan now runs a narrower set than before, not a wider one. A target file with
no `weakness_classes` declared at all is unaffected.

## `generate` stamps a test unvalidated and can refuse to write one

**What changed.** A test `generate` writes straight from a scan — without a
prior KEPT `validate` run proving that exact test — now says so in the file
itself, and `generate` can refuse to write one at all when the input looks
already rejected.

**What you'll see.** Such a test's first line is `# mylonite: unvalidated`,
followed by a short header, and the command prints the `validate` command to
run next. When the exploit's neighboring `validation_report.json` says
REJECTED, STABLE NOT PROVEN, or fails to parse, `generate` now writes nothing
and exits `5`. Pass `--unvalidated` to write it anyway, with the header.

**What to do.** If a script expects `generate` to always write a file, check
its exit code and handle `5`, or pass `--unvalidated` when you deliberately
want a test from an unproven exploit. `gate`'s own flow is unaffected.

## Gate directories moved to a short, hashed layout

**What changed.** A gate run on the reference target with two or more findings
used to write every finding's replay fixtures into one shared `fixtures/`
folder at the gate root, so later findings overwrote earlier ones' recordings.
Gate directories are now named by weakness class plus a short hash, and each
finding's fixtures live in its own folder, which also keeps the deepest path
under Windows' 260-character limit without long paths turned on.

**What you'll see.** A finding's folder is now something like
`.mylonite/gate/w2-1a2b3c/`, holding `test_w2-1a2b3c.py` and
`exploit_w2-1a2b3c.json`; the full pattern id stays in the test's docstring and
the exploit JSON. A rejected finding's evidence moves to
`.mylonite/gate-rej/<id>/` (was `gate-rejected/<pattern>/`). Replay recordings
are now named by the first 12 hex characters of their key (was the full key),
with the full key stored inside the file.

**What to do.**

- Gate directories committed under an earlier release keep replaying
  unchanged — nothing here breaks a test you already have.
- Before committing tests from a *new* `gate` run against an existing project,
  see [Re-run the scaffold or bump the pin](#re-run-the-scaffold-or-bump-the-pin):
  an older `mylonite==` pin in your committed workflow cannot replay the new,
  shorter recording names, so a freshly gated test would fail in CI on its
  first run. `gate` prints a warning naming the workflow file when it finds an
  older pin.
- A new run into the same `--out` writes the new layout beside any old
  folders rather than deleting them; `pytest` then collects both until you
  remove the old ones by hand.

## Re-run the scaffold or bump the pin

Three changes in this release — the short gate layout, the provider-aware
credential templates, and the `gate --base`/`--open-pr` fixes — all land in
the *files* `mylonite gate --workflows` writes, not just in the CLI's own
behaviour. A workflow or `gate-action` call committed from an earlier release
keeps working, but won't pick any of this up until you do one of:

- **Re-run the scaffold:** `mylonite gate --workflows` over your existing
  project, then review and commit the diff.
- **Bump the pin by hand:** change the `mylonite==` version your committed
  workflow installs, and `gate-action`'s pinned tag if you call it directly.

Two parts of this need a positive action, not just a version bump:

**The emitted workflow and `gate-action` now read your actual provider's
credential, not always Anthropic's.** They used to always render
`ANTHROPIC_API_KEY: ${{ secrets.MYLONITE_API_KEY }}`, so an OpenAI, Gemini or
other non-Anthropic model's gate job failed in CI with no useful message. Both
now read the credential variable for the model's own provider from the
approved-provider registry, and a provider needing more than a bare key
(Azure's endpoint and API version) gets those emitted too, as repository
variables.

If you call `gate-action` directly (not through the scaffolded workflow), add
its new required `api-key:` input when you bump the tag, pointing it at the
secret you already export:

```yaml
- uses: Abidemialade/mylonite/gate-action@<new-tag>
  with:
    model: ${{ vars.MYLONITE_MODEL }}
    api-key: ${{ secrets.MYLONITE_API_KEY }}
```

An older pinned tag keeps working unchanged — it just keeps assuming
Anthropic's key variable. A local model (Ollama, vLLM) or a provider needing
more than one credential variable (Bedrock's keypair, or Vertex with no bare
key at all) makes `gate --workflows` refuse outright before it spends
anything, since a single `MYLONITE_API_KEY` secret cannot express either.

## A black-box `rest` target can't declare `effect_probe`

**What changed.** A `transport: rest` target that declared an `effect_probe`
used to have the field silently dropped, so the probe never ran and `validate`
would suggest adding one that could never work.

**What you'll see.** Every command that loads such a file — `scan`, `generate`,
`validate`, `gate`, and the experimental `check` — now exits `2` before it
connects or calls a model, naming the reason: Mylonite sees only the agent's
HTTP reply over `rest`, so there is no state to read back. A `target.yaml`
saved by an earlier scan with this block also now stops `generate` and
`validate` the same way.

**What to do.** Delete the `effect_probe` block from the target file and
re-run. To confirm a side effect on an agent reachable only over HTTP, point
Mylonite at its MCP server directly instead, where one exists.

## `seed_tool_ceiling`

**What changed.** A custom target with more than 8 candidate tools in one
weakness class used to probe only the first 8 and name the rest in a log
warning you could easily miss.

**What you'll see.** The cap is unchanged at 8 by default, but every tool past
it is now its own `⚠ NOT TESTED` row with reason code `MYL-NT-018` (see
[Reason codes](#reason-codes-three-are-new-two-now-mean-something-narrower)
above), so it shows up in the report, not just the log.

**What to do.** If you want every candidate tool probed, add
`seed_tool_ceiling: <n>` to the target file (3 to 50; the default stays 8).
Each extra probe costs LLM calls. See [`target.yaml`](target-file.md).

## A JSON request now gets a JSON content type

**What changed.** The `rest` transport sent its request body with no
`Content-Type` header, so an agent server that requires one — FastAPI, for
example — rejected every attack with a 422 before it reached the agent, and
the class read NOT TESTED.

**What you'll see.** When the body is JSON and the target file sets no
`Content-Type` itself, Mylonite now sends `application/json`. If your target
file already sets one, that value still wins.

**What to do.** Nothing, unless a `rest` target's class was reading NOT TESTED
for this reason — re-run the scan and it should now reach the agent.

## `--env`/`--arg` with `--target-file` now refuses

**What changed.** `scan` accepts `--target-file` alongside the `mcp:custom`
flags (`--command`, `--arg`, `--env`) that build an inline target spec. Once
`--target-file` was also given, those three flags had no effect at all — the
file's own `command`/`args`/`env` always won — with nothing printed to say so.

**What you'll see.** Passing any of `--command`, `--arg` or `--env` together
with `--target-file` now exits `2`, naming the flag(s) you passed. A script
that relied on them being silently dropped needs updating.

**What to do.** Put the launch override in the target file's `env:` block
instead, or drop `--target-file` and build the target from the flags alone.

## A credential-shaped `--arg` value now warns

**What changed.** `scan --scaffold` keeps a secret out of the written
`target.yaml` when it arrives via `--env` or a header — but a credential
passed through `--arg` (`--api-key=sk-...`, a URL with `?access_token=...`)
has no key name to mask by, and was written in plain text with no warning
that it had been.

**What you'll see.** `scan --scaffold`, and every later command that loads the
file, now warns on a credential-shaped `args` entry — naming its position,
never the value — and points at the fix. The value is still written in plain
text; the warning is what's new.

**What to do.** Move a credential out of `args` into `env:` (most subprocess
CLIs also accept it from an environment variable) or a remote target's
`headers:`, as `${VAR}`.

## `--env-file` loads more, and refuses an unresolved `${VAR}` placeholder

**What changed.** `--env-file` only ever recognised provider-key/config
names, dropping a `MYLONITE_TARGET_...` placeholder or a hand-written
`${NAME}` reference in a target file with a warning — you had to `set -a; .
./.env; set +a` instead. It also set a recognised variable to whatever text
followed `=`, even when that text was itself an unresolved `${VAR}`-shaped
reference left behind by a templating tool or secrets manager that never
ran — sending the literal placeholder text to the provider as if it were
the key.

**What you'll see.** `--env-file` now additionally loads every
`MYLONITE_TARGET_...`-prefixed name and every name the run's own
`--target-file` references as `${NAME}` (pass both flags together, or let
`mylonite.yaml`'s `target_file:` supply the path). It also exits `2` and
names the variable and the file when a loaded value is exactly
`${SOME_NAME}`, instead of loading it.

**What to do.** Nothing, unless a script relied on one of those names being
silently dropped (unlikely) or on the raw-placeholder value loading
(should never have worked). Resolve a `${VAR}` reference before Mylonite
reads the file — run the templating step first, or set the real value
directly.
