# CI gating

`mylonite gate` runs the whole flow — find an exploit, write a regression test,
validate it against the differential oracle, and (opt-in) open a PR that gates
CI on it.

## The end-to-end flow (local)

Against your own app this drives a real agent and makes real model calls, so budget
minutes and API spend rather than seconds.

!!! tip "Sizing `--max-llm-calls`"

    Every seed is guaranteed a floor of the budget before the rest is shared, so a
    large tool surface cannot let the first few seeds drain the pool and leave the
    others untried. Probes that chain two tools cost two or three calls each, so a
    server with many egress or action tools wants a larger budget than the default
    of 50. If the budget still runs out, the whole scan aborts (exit code 3) and a
    log line **names the seeds that never started** — they proved nothing, but they
    are not reported as NOT TESTED rows; the report records only that the scan was
    cut short by its budget. An attack module that fails to load is different: its
    classes DO read NOT TESTED with [`MYL-NT-015`](reason-codes.md#myl-nt-015), so
    the gate does not pass on a scan that never ran them.

    **`--max-llm-calls` is therefore a floor-adjusted budget, not a hard ceiling.**
    Worst case is `cap + (seeds - 1) × max(2, cap ÷ seeds)` — with `--max-llm-calls
    50` against a surface that synthesises 100 seeds, up to roughly 250 calls. That
    is deliberate: the alternative is that the seeds which happen to start last
    make no call at all, and a probe that never ran is indistinguishable from a
    target that resisted. Size CI spend against the worst case, not the flag value.

    **The budget bounds only `gate`'s scan phase.** `--help` already says so ("LLM
    call budget for the scan phase"). Validation — re-driving each kept finding
    against both twins, `--iterations` times, plus a metamorphic robustness pass —
    happens *after* the scan and has no call budget of its own; on most runs it
    makes the majority of the calls.

    The formula depends on which kind of target is being gated:

    - **The bundled reference agent** — `iterations` full differential drives
      (raw twin + guarded twin, so `× 2`), plus 7 built-in metamorphic
      re-paraphrasings of the same attack — each *also* driven against both
      twins (another `× 2`) to check the finding survives rewording, not just
      the literal payload. So one finding costs roughly `(iterations + 7) × 2`
      re-drives, each itself several LLM calls (customiser, planner, judge).
      At the default `--iterations 3` that's `(3 + 7) × 2 = 20` re-drives for
      ONE finding — a two-finding scan is roughly 40, not one.
    - **Your own target** — there is no in-repo guarded twin and no
      metamorphic pass, so the cost is flatter: `iterations` re-drives of the
      real target, plus another `iterations` re-drives of a boundary-guarded
      twin *only when* a guard adapter is configured (the default unless
      `--fast`). At the default `--iterations 3` that's 3 re-drives per
      finding with no guard configured, or 6 with one.

    Either way, every finding a scan proves is gated now, not just the first,
    so this cost scales with findings, not just `--iterations`. Size CI
    spend against the whole `gate` run — scan plus validation — not against
    `--max-llm-calls` alone.

    **For a hard limit, set `MYLONITE_MAX_LLM_REQUESTS`** (or pass the global
    `--max-llm-requests N` option before `gate`). It counts every request the
    whole `gate` run sends — scan, validation and retries — and never sends one
    past the limit. Hitting it stops the run with exit `3` and a NOT TESTED
    result: no test is generated or validated past that point, and the run
    never reads as a pass. Size it from a run's `llm:` lines plus headroom for
    retries.

```bash
# against the bundled reference agent
mylonite gate reference:vulnerable

# against your own MCP app
mylonite scan --command "python" --arg "-m" --arg "your.server" --scaffold target.yaml
mylonite gate --target-file target.yaml --authorize custom --open-pr
```

`gate` does not auto-wire a `seed_arm`. `scan` does: for a target that declares W2
without one, `scan` looks for a store-and-recall pair on the live server and uses it.
`gate` refuses the same target instead, because W2 has nothing to plant with. For such a
target, run `mylonite scan --target-file target.yaml --authorize <family>` first. When it
wires a `seed_arm`, it writes the wired target to `.mylonite/scans/<timestamp>/target.yaml`;
pass that file to `gate --target-file`.

### Gating every finding

A scan often turns up more than one weakness. `gate` generates and validates
**every** finding the scan proves, in deterministic order (sorted by pattern id),
and commits every KEPT one's test to a single branch behind a single PR:

```text
2 findings: validating each (about 2x the single-finding validation cost)
1 kept, 1 rejected
```

`gate` never commits an unproven finding. A finding whose validation passed
but had no passing differential or effect leg (or a black-box keep that rests on
the LLM judge alone) reads **STABLE, NOT PROVEN**. `gate` treats it as a
candidate:

- no test, exploit or report for it is written to the gate directory or
  committed; its evidence goes to the `-rej` folder next to `--out`, with its
  validation report;
- the console prints one line per candidate, with the reason and how to get it
  proven: declare `control_env` and drop `--fast`, or declare an `effect_probe`,
  then re-run `gate`. A finding on a black-box `rest` target can't be proven
  this way, so `gate` never commits one;
- when another finding was kept, `PR_BODY.md` lists the candidates under
  "Candidates (not proven, not committed)";
- an earlier kept test, exploit and fixtures with the same id stay in place,
  byte for byte;
- with nothing kept, no PR is opened and `gate` exits `10`.

```text
3 findings: validating each (about 3x the single-finding validation cost)
1 kept, 1 not proven (candidates, not committed), 1 rejected
```

### Exit codes

`gate`'s exit code tells a CI script what the run produced:

| Code | Meaning |
|------|---------|
| `0` | The scan ran and found nothing to gate. |
| `9` | At least one proven finding was kept; its gate test is written (and committed with `--open-pr`). |
| `10` | Nothing was kept, but at least one finding is a STABLE, NOT PROVEN candidate. No test was written. |
| `5` | Every finding that reached a verdict was rejected. |

An aborted scan still wins over all of these (see
[Budget exhaustion and findings](#budget-exhaustion-and-findings)). The full table
is in [Reading the results](reading-results.md#exit-codes-for-ci).

**Upgrading:** `gate` used to exit `0` both for a kept finding and for a clean
run. A kept finding now exits `9`. A CI script that treated `0` as "gated" needs
to check for `9`; one that treats any non-zero exit as a failure now fails when
`gate` keeps a finding, which is the point of a gate. The scaffolded discovery
workflow and the gate action run `gate --open-pr` as their last step and don't
yet read these codes, so for now a night that keeps a finding (`9`) or finds only
candidates (`10`) shows as a failed run.

A finding that was generated and validated but not kept is still named in
`PR_BODY.md`, with the reason, under "Other findings (not gated)" — it isn't
silently dropped the way it used to be. If a generator or validator failure hits
one finding specifically, the rest are still gated; only a run where *every*
finding fails the same way falls back to the old single-finding exit codes (`6`
generate failed, `7` validate failed).

The branch name reflects how many findings it carries: gating exactly one kept
finding keeps the historical `mylonite/gate-<pattern_id>`; gating several uses
`mylonite/gate-<hash>`, a short stable hash of the kept pattern ids. Both keep the
`mylonite/gate-` prefix, so anything that matches on it (a branch-protection rule,
a script) keeps working either way.

### A finding you haven't fixed yet

`gate` commits the test for a finding that still works on your app as a
**pending fix**, so the gate PR doesn't turn CI red the day it merges. The test
carries one extra line, `@testkit.pending_fix(...)`, and moves through three
states:

1. **Not fixed yet.** The attack still lands, so the test is an expected
   failure (`xfail`) and the check stays green. `pytest -ra` lists it as
   `XFAIL ... pending fix: ...`.
2. **Fixed.** The attack stops on every re-drive attempt (3 by default), the
   test passes, and the check fails on purpose with: *The attack did not land
   on any re-drive attempt this run. If your fix has landed, remove the
   `@testkit.pending_fix(...)` line above this test.* An attack that lands
   rarely can still resist three attempts, so if you haven't shipped a fix,
   re-run the check first.
3. **Marker removed.** The test is a regular gate. It passes while the fix
   holds and fails the check if the attack works again.

This applies to findings on your own target that the gate re-drives with
`testkit.assert_target_resists`. A control-efficacy test
(`assert_control_holds`) and a test against the bundled reference agent
already pass on your current build, so they are committed without the marker.
`pytest -m mylonite_pending_fix` lists every test still waiting on a fix. A
check that never reached a verdict (a missing fixture, an unresolved model, a
target that didn't start) still fails; only the attack landing counts as "not
fixed yet". The `PR_BODY.md` "How this is gated" section says which tests are
pending.

### Budget exhaustion and findings

`--max-llm-calls` bounds the *scan* phase (see the sizing box above). If the
budget runs out mid-scan but the scan already proved a real finding, `gate` still
generates, validates, and opens or prints the PR for that finding — nothing is
thrown away. The run's exit code is still the scan's own: **`3`**, not `0` or `9` — the
same "abort always wins" rule `scan` follows on its own (see
[Reading the results](reading-results.md#exit-codes-for-ci)). Treat exit `3` from
`gate` as "check `PR_BODY.md` before you decide this was just an infrastructure
failure", not as a reason to discard the run.

The error line carries reason code `[MYL-ABT-001]`. The other abort and
incomplete-coverage errors `gate` prints carry codes the same way; look each one
up in [Reason codes](reason-codes.md).

If a custom target does not come up while `gate` is validating a finding, `gate`
stops with one `[MYL-ABT-006]` line and exit `2`. The line says how many runs had
finished, that later findings were not validated, and where the scan results are.

### W3 or W4 with no `effect_probe`

On a custom target that declares W3 or W4 and no `effect_probe`, nothing reads the
target's own state, so each of those classes reads NOT TESTED
([`MYL-NT-017`](reason-codes.md#myl-nt-017)) unless an attempt fires. A gate that finds
nothing there exits **`2`** ("Coverage was incomplete"), not `0` ("nothing to gate").
**Upgrading:** a gate you committed against such a target before this change turns red.
Add an `effect_probe` to the target file (re-run `mylonite scan --scaffold` to get a
proposed one), or remove W3/W4 from `weakness_classes`.

### Pre-flight order

`gate` runs its pre-flight checks in this order, all before any LLM call:

1. The repository checks, each exiting `8`: a `--base` that is empty, contains
   whitespace or starts with `-`; with `--open-pr` or `--workflows`, an output
   directory outside the repository; with `--open-pr`, a working tree with staged
   files or uncommitted changes to tracked files.
2. On Windows without long paths, the output path check, exiting `2` (see
   [Windows path length](#windows-path-length)).
3. The target, `--authorize`, model, provider key and uncoverable-class checks, each
   exiting `2`.

So when both kinds of problem are present, the exit-`8` error is the one you see first.

For a custom (`--target-file`) target, `gate` then calibrates the declared
`effect_probe` — real writes proving it can see a change — once, before its scan
phase runs. This is the same calibration `scan`/`validate`/`ablate` each run on
their own path; see [Calibration](target-file.md#calibration) for what
`calibration.controls` permits and [Reason codes](reason-codes.md) for what an
uncalibrated probe reads as.

### What `gate` touches

**By default, nothing outside its own output directory.** `gate` writes
`.mylonite/gate/` — the generated test, the exploit JSON, the validation report,
your `target.yaml` and `PR_BODY.md` — and then prints the exact `git` and `gh`
commands to commit and open the PR yourself. With neither flag below, your
repository is not modified: no branch, no commit, no workflow files.

Each finding gets a short, stable id: its weakness class and six hex digits
of a hash of its pattern id, for example `w2-1a2b3c`. Its test is
`test_w2-1a2b3c.py` and the exploit it loads is `exploit_w2-1a2b3c.json`. The
full pattern id is in the test's docstring and the exploit JSON, `gate` prints
which pattern each test gates, and a multi-finding PR body has a table mapping
each pattern id to its test.

One finding is written straight into `.mylonite/gate/`, and on the reference
target its replay recordings sit beside it in `.mylonite/gate/fixtures/`. With
two or more, each kept finding gets its own folder, `.mylonite/gate/<id>/`,
holding its test, exploit JSON, validation report and, on the reference target,
the `fixtures/` its test replays. With `--target-file`, each finding folder also
gets its own redacted `target.yaml`, because the test loads the file from its
own folder. `pytest .mylonite/gate/` runs every kept test; on the reference
target it runs offline, with no provider key. A rejected finding's files,
recordings included, move to `.mylonite/gate-rej/<id>/` and are never
committed.

Gate dirs written by earlier versions, with folders and tests named after the
full pattern id, keep replaying unchanged. When you upgrade, re-run `gate` with
`--workflows`, or change the `mylonite==` pin in your committed gate workflows
to the new version, before committing new tests: an older pin cannot replay
the new recordings, so those tests would fail in CI on their first run. `gate`
prints a warning naming the workflow file when it finds an older pin. A new
run into the same `--out` writes the short-id layout beside the old folders
and leaves them alone, so `pytest .mylonite/gate/` then runs both; delete the
old folders once the new tests are committed.

### Windows path length

**`gate` refuses an output directory Windows cannot hold before it calls a model
or starts your target.** Without long paths enabled, Windows caps a file path at
259 characters. `gate` works out the longest path it could write under `--out`
(a folder per finding, rejected findings included) and, if that is over the
limit, prints one line naming the path, its length and how many characters to
cut from `--out`, then exits `2`. After the scan it checks again with the real
findings, before any validation. Linux, macOS and Windows with long paths on
skip the check.

With the default `.mylonite/gate`, a project path of up to 200 characters fits:
the deepest file, `.mylonite/gate-rej/<id>/fixtures/<recording>.json`, uses 58
of the 259. CI runs a two-finding gate from a 200-character project root with
long paths off. To go deeper, pass a shorter `--out` or enable long paths
(`LongPathsEnabled` in the registry, plus `git config core.longpaths true` for
teammates who clone the gate). Replay recordings are named by the first 12 hex
digits of their key (17 characters); recordings made by earlier versions keep
their 64-digit names and still replay.

`gate` redacts secret-shaped values in the exploit JSON, the validation report
and `PR_BODY.md` (its evidence lines and the optional LLM suggestion) before it
writes them. A key the target echoed into its reply, a tool result or a
validator error shows up there as `***REDACTED***`. The recorded replay files
under `fixtures/` are not redacted; review them before you commit.

Two flags opt in to the rest, independently:

- **`--open-pr`** creates the branch, commits the gate directory, pushes, and
  opens the PR via `gh`. If `gh` is missing or unauthenticated it still commits
  and prints the remaining two commands. Once the commit exists, `gate` checks
  out the branch you started on (or, on a detached HEAD, the same commit),
  whether the PR opened or the push or `gh` step failed. The gate branch is
  kept, and the output names it: "The gate branch 'mylonite/gate-…' is kept
  with the committed gate output; you are back on 'main'." The committed gate
  output now lives on that branch, so it leaves your working tree; run
  `git checkout <gate branch>` to look at it.
- **`--workflows`** scaffolds the two `.github/workflows/` templates described
  below — this writes to disk whether or not `--open-pr` is also set. Pass
  `--workflows` alone and the printed summary lists the workflow file(s) it
  wrote, rather than claiming nothing outside the output directory changed.

Both are off by default. Writing into someone's repository is an action you ask
for, not one you opt out of.

> **Changed in 0.8.5.** `gate` previously created a branch and a commit on every
> run, and scaffolded the workflow templates unless you passed `--no-workflows`.
> If you relied on that, add `--open-pr` and `--workflows` explicitly.

The PR body is itself a result surface (see [Reading the results](reading-results.md#the-gating-pr)).
It states the guarded-twin claim only for a `KEPT` validation; any other verdict is named
with its reason. It carries:

- **The differential proof** — the fires/resists numbers and the `kept` formula, so a
  reviewer sees *why the test is trustworthy*, not just that it exists.
- **Located at** — the exact locus to fix (which tool description / returned content /
  action handler / system-prompt line).
- **The proven fix** — an evidence-anchored recommendation naming the actual tool and
  argument that landed the exploit (your own tool for a `--target-file` app; the
  reference app's tool for the bundled `reference:*` targets), as a fenced code sketch
  (never a diff — Mylonite doesn't assert it knows your file layout) tiered
  deterministic/probabilistic/detective.
- **Compliance** — the OWASP-LLM/ASI · MITRE ATLAS · NIST tags.
- **Inline annotations** — a best-effort GitHub check-run annotation on the offending
  prompt line, when the AI layer is a committed file.
- **Which repository secrets to add** — when the target file has secret-shaped
  fields (headers, `env:`), the committed `target.yaml` replaces them with
  `${MYLONITE_TARGET_...}` placeholders; the PR body and the console both name
  the repository secrets those placeholders need before the scaffolded gate
  workflow (or your own) can load the file in CI.

The recommendation's confidence is degraded, not silently kept at full strength, when the
effect probe didn't settle the finding on its own: `unprobed` (no `effect_probe`
declared), `errored`, `deferred` or `false` (the probe confirmed nothing on a finding the
tool-call trace decided), and `unattributed` (the state change, or its absence, could not
be tied to that attempt — see [Effect attribution](target-file.md#effect-attribution))
each lower it one step, so a PR body never reads a weaker signal as a fully-confirmed one.

For a custom target the gate proves the finding **differentially by default** (the
control-efficacy check). `--fast` skips that leg, so `gate` keeps a finding only when
an `effect_probe` proves it; otherwise the finding is a candidate, no test is written,
and `gate` exits `10`.

## Adopting it in GitHub CI

Add one secret — `MYLONITE_API_KEY` (your provider key) — and the two
scaffolded workflows. Both map that one secret to the credential variable
your chosen model's provider actually needs (`ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, …), computed when `gate --workflows` wrote them — see
[Provider keys](#provider-keys) below for what that means if you later
switch providers. If your target file has secret-shaped fields (a header,
an `env:` entry), add one repository secret per `${MYLONITE_TARGET_...}`
placeholder too — `gate` names the exact variables in its console output and
`PR_BODY.md` the first time it writes a redacted `target.yaml`. The
scaffolded workflows already map each one to `${{ secrets.<NAME> }}` in the
step that runs the gate. GitHub renders a secret you haven't added as an empty
string, and an empty value counts as set when the target file is expanded, so
on its own a missing secret would launch your server with an empty credential
and the gate test could pass for the wrong reason. To stop that, each workflow
runs a "Check the target secrets are set" step first, which fails the job on
the first empty one with `secret <NAME> is empty - add it under repository
secrets`.
Outside these workflows (a local run, another CI system), an empty
`MYLONITE_TARGET_*` variable is used as given, so export real values.

- **`mylonite-gate.yml`** runs on every PR. It re-drives your agent (bounded:
  deterministic effect-probe, small model, 1 iteration) and fails the check on
  a regression. It sets `MYLONITE_LIVE_TARGET=1` for you (see
  [The validation engine](validation.md)) — without that variable the committed
  test for a custom target is *skipped*, not run. It also sets
  `MYLONITE_REQUIRE_GATE_RUN=1`, which makes the job fail if a Mylonite gate test
  was skipped or none was collected, so the check can only go green by running
  the gate. `pytest -ra` prints the reason if it does. A pending-fix test that
  ran and failed as expected counts as a run, not a skip. A
  `@pytest.mark.xfail` you add by hand does not: it can hide a check that never
  reached a verdict, so it still fails the job.

    The re-drive carries a **hard call budget and a wall-clock timeout**. It is
    scoped to the single already-known pattern, so a healthy run is a customiser
    call, a few planner turns and a judge call; overrunning the bound means
    something is wrong — a hung MCP server, a stalled provider — not that the
    work was large. Without those bounds the only backstop is your CI platform's
    job cap, which on GitHub-hosted runners is **six hours**.

    Two things worth knowing before you make this a required check. It calls a
    live model, so it is **not bit-for-bit deterministic** the way a unit test
    is — budget for the occasional re-run rather than treating a single red as
    proof of regression. And it is the one path in the product that spends money
    on every PR; the nightly discovery job is where the expensive work belongs.
- **`mylonite-discovery.yml`** runs nightly or on demand. It does the expensive
  full discovery and opens a fresh gating PR when it finds a new exploit. It
  also needs a repository **variable** — `vars.MYLONITE_AUTHORIZE` — set to
  the same value your own `--authorize` would need (the target's declared
  `scope`, or its `family` if no scope is declared; see
  [target.yaml](target-file.md)); the workflow passes it to
  `mylonite gate --authorize` through an environment variable, so a value
  holding a quote or `;` stays one argument.

**Both workflows are hardened the same way every workflow in this
repository is.** Every action is pinned by commit SHA, with the tag as a
comment (a moved tag would run new code in your CI the next time the job
fires). Each job sets `concurrency:` — the per-PR gate cancels a
superseded run on the same ref, the nightly discovery job serializes
instead so one run never races a PR it is in the middle of opening — and a
`timeout-minutes:` so a hung provider or MCP server fails the job instead of
riding your CI platform's much larger default cap. Each job also sets
`MYLONITE_REDRIVE_ATTEMPTS` explicitly rather than leaving it to the
default: `1` on `mylonite-gate.yml` (the per-PR job already explained
above spends real money on every PR, so it takes the cheaper, less
conclusive bound) and `3` on `mylonite-discovery.yml` (the nightly job,
where the fuller signal is worth the extra re-drives). See [What a live
gate costs](#what-a-live-gate-costs) for the trade-off either number makes.

**If your target launches with `npx`/`node` or `uvx`/`uv`,** the scaffolded
workflow adds a Node or `uv` setup step automatically — read from the
target file's own `command:` at the time `gate --workflows` ran. A hosted
runner has neither preinstalled the way it has Python, so without this the
job would fail to launch your target with no clearer message than "command
not found".

**A bundled MCP target (`mcp:<family>[:scope]`, no `--target-file`) refuses
`--open-pr`/`--workflows` outright.** It has no `target.yaml` of its own, so
the committed test's `target.yaml` load would fail every time CI re-drives
it. Run `mylonite scan --scaffold` first to write one, then gate with
`--target-file <path>` instead.

**No default model, so both workflows pin the one `gate --workflows` used —
but what that controls is NOT the same in each.** There is no default
provider or model — a live command stops rather than guessing one (see "No
model chosen at all?" in [the CLI reference](cli-reference.md)). Both
workflows set `MYLONITE_MODEL: ${{ vars.MYLONITE_MODEL || '<model>' }}`,
where `<model>` is the exact value the run that scaffolded them resolved,
but only **`mylonite-discovery.yml`** actually reads that variable:
its `mylonite gate --target-file ... --open-pr` step is a LIVE invocation,
and `MYLONITE_MODEL` is exactly what chooses its model (the same env var
`--model`/`mylonite.yaml` would otherwise need to win over). Add a
repository **variable** named `MYLONITE_MODEL` to change the model the
*discovery* workflow drives, without editing the file; leave it unset and
the baked-in literal keeps that job working exactly as scaffolded.

**`mylonite-gate.yml`'s per-PR job does NOT read `MYLONITE_MODEL` at all.**
It runs `pytest` against the already-committed test, which re-drives the
finding against the model recorded with it at `gate`/`generate` time (the
exploit's own execution-context metadata, or a sibling `scan_report.json`)
— never an environment variable. The variable is still set in that
workflow's `env:` block (for consistency, and in case a future committed
test ever needs it as a fallback), but today it is inert there. Re-run
`gate --workflows` after choosing a different `--model` to re-bake the
discovery workflow's literal; a per-PR test's model only changes when the
finding itself is re-proven against a different one (`mylonite validate
--model ...`, then re-committing).

Both workflows install the Mylonite release that wrote them:
`pip install "mylonite==X.Y.Z"`, where `X.Y.Z` is the version that ran
`gate --workflows`. A new Mylonite release never changes what your CI runs until
you change that line, or re-run `gate --workflows` with the new version.

### Prerequisites `gate --open-pr` assumes

`mylonite gate --open-pr` shells out to `git`/`gh` directly (no GitHub API
client), so it inherits a few real preconditions the scaffolded workflows
satisfy automatically but a local or non-GitHub run must provide itself:

- **A git repository.** `gate --open-pr` (and `--workflows`) resolves the repo
  root with `git rev-parse --show-toplevel`, so it works from any subdirectory —
  the gate output and the scaffolded workflows land at the repo root either way,
  not wherever you happened to run it from. Outside a git repository entirely,
  it fails fast with a named error, before any scan/LLM spend.
- **A clean working tree.** `--open-pr` switches branch and runs `git commit`,
  which commits everything staged. So `gate` refuses, before any LLM call, when
  files are staged or tracked files have uncommitted changes; commit, stash or
  unstage them first. Untracked files are fine: `gate` stages only the files it
  wrote.
- **The right PR base.** The PR targets your repository's default branch:
  `origin/HEAD`, else the branch your current branch tracks, else `main`. Pass
  `--base <branch>` to target another branch. The printed `gh pr create`
  command uses the same base. Running from a feature branch? Pass `--base`:
  the gate branch is cut from the commit you have checked out, so against the
  default branch the PR also carries your feature branch's unmerged commits.
- **A fresh gate branch.** If the gate branch (`mylonite/gate-…`) already
  exists from an earlier run, `git checkout -b` fails and `gate` stops on exit
  code `8`. It leaves that branch and its commits alone; it deletes a branch
  on rollback only when this run created it. Push or delete the old branch,
  then re-run.
- **`.mylonite/gate/` (or your configured `--out`) must actually be
  committed.** `gate` writes the test, the exploit, and your `target.yaml`
  there, then commits and pushes them as part of the PR — but if *your* repo's
  own `.gitignore` has a blanket `.mylonite/` rule (a natural pattern to add,
  and what Mylonite's own repo uses for its dev artefacts), `git add` refuses
  the explicitly-named ignored path and `gate --open-pr` fails loudly with a
  git error (rolling back the half-created branch) rather than opening an
  empty PR — verified against `gate.pr.open_or_print_pr` directly.
  Confusing either way: make sure your `.gitignore` does **not** ignore the
  gate output directory.

A failure in any of these is reported as a named error on **exit code 8**, not
a traceback, and the findings, the generated test and the validation report are
all written to `--out` *before* any git command runs — so a git failure costs
you no evidence. If the failure comes after the commit (the push or `gh`
step), the evidence is on the kept gate branch the error names, and you are
back on your original branch. Re-run the printed `git`/`gh` commands by hand
once the precondition is fixed.

### The reusable Action

```yaml
- uses: Abidemialade/mylonite/gate-action@v0.11.0
  with:
    target-file: .mylonite/gate/target.yaml
    authorize: ${{ vars.MYLONITE_AUTHORIZE }}   # your target's scope, or family if no scope
    model: anthropic/claude-haiku-4-5           # no default -- pick one: see "Choose a model"
    api-key: ${{ secrets.MYLONITE_API_KEY }}    # mapped automatically to the model's provider
    open-pr: "true"
    # llm-headers: ${{ secrets.MYLONITE_LLM_HEADERS }}   # optional
```

The action also configures a git identity before it calls `mylonite gate
--open-pr` (a hosted runner has none by default, so the commit would
otherwise fail), and sets up Node or installs `uv` on its own when your
target file's `command:` needs one.

**The tag is the release.** The action lives in this repository
(`gate-action/action.yml`), so every Mylonite release tag `vX.Y.Z` is also an
action tag, and `gate-action@vX.Y.Z` installs exactly `mylonite==X.Y.Z`. Tags
before v0.10.2 predate the pin and install the latest release. To upgrade,
change the tag. `scripts/prepare_release.py` bumps the action's pin and
the tag on this page with the version, and the release job refuses a tag whose
pin does not match.

**`mode` and `runs-on` are deprecated.** `mode` was never read; `runs-on` fed
`--runs-on`, but the action never passes `--workflows`, so it had nothing to
scaffold a runner label into. Both inputs still exist for backward
compatibility — the action does not write workflow files in CI — but a
non-default value now logs a `::warning::` in the job log instead of being
silently accepted and silently ignored.

## Other CI systems (Jenkins, GitLab, …)

The committed gate is a plain `pytest` file with no GitHub dependency, so it should run
anywhere that meets the preconditions below. **GitHub Actions is the only configuration we
test**, so treat other systems as supported-but-unverified.

```bash
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate
```

**The environment variable is required.** Without it the live test is skipped and `pytest`
exits **0**. `mylonite generate` prints this exact command for that reason. To make the job
fail rather than pass when the gate test did not run, also set
`MYLONITE_REQUIRE_GATE_RUN=1` in the CI job — the same check the scaffolded GitHub workflow
enables:

```bash
MYLONITE_LIVE_TARGET=1 MYLONITE_REQUIRE_GATE_RUN=1 pytest .mylonite/gate -ra
```

With it set, the session fails if any `mylonite_security` test was skipped or if none was
collected; tests without that marker are never inspected. Leave it unset for local runs,
where a keyless skip is the intended default. You also need:

- `mylonite` and `pytest` installed
- the scan artefacts (the exploit JSON and `target.yaml`) co-located with the test:
  `exploit_<id>.json` in a gate dir, `exploit_<pattern_id>.json` from `generate`
- a provider key
- network egress to both the model provider and your MCP server

Only the bundled reference/replay test runs offline unconditionally; a gate against your
own app always re-drives the real target.

### What a live gate costs

A live gate test re-drives your app up to 3 times. It fails on the first attempt the
attack lands on, errors at the first inconclusive one, and passes only when every attempt
resisted, so a passing check is the expensive case:

| Test | Attack lands on attempt 1 | Every attempt resists |
|---|---|---|
| `assert_target_resists` | 1 re-drive | 3 re-drives |
| `assert_control_holds` | 1 raw + 1 guarded | 1 raw + 3 guarded |

Each re-drive is one seed: about a customiser call, a few agent turns and a judge call,
capped at 12 model calls and 180 seconds. To spend less on every pull request and keep the
full check on a schedule, set the number of attempts per job:

```bash
# every pull request: one attempt
MYLONITE_LIVE_TARGET=1 MYLONITE_REDRIVE_ATTEMPTS=1 pytest .mylonite/gate
# nightly: the default 3
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate
```

The scaffolded `mylonite-gate.yml`/`mylonite-discovery.yml` already set this
for you — `1` on the per-PR job, `3` on the nightly one — so you only need
the commands above on another CI system or a local override.

One attempt proves less: an attack that lands 40% of the time resists a single re-drive
60% of the time. A test that passes `attempts=` itself keeps that number whatever the
variable says.

What does *not* port: opening the gating PR, inline check-run annotations, and Security-tab
SARIF upload all use the `gh` CLI and GitHub APIs. On other CI, run the test as the gate and
surface results through your own reporting — `mylonite report --sarif` still emits standard
SARIF 2.1.0 if your platform ingests it.

### Provider keys

There is no default provider. The scaffolded workflows map the one
`MYLONITE_API_KEY` secret to the credential variable the model `gate
--workflows` resolved actually needs — `ANTHROPIC_API_KEY` for an
Anthropic model, `OPENAI_API_KEY` for an OpenAI one, and so on, read from
the approved-provider registry at the time the workflow was written, never
hardcoded to one provider.

**That mapping is baked in, not re-computed at CI time.** Setting a
repository `MYLONITE_MODEL` variable to a model from a *different*
provider (see above) changes which model the *discovery* workflow drives,
but **not** which credential variable it exports — the workflow still only
ever sets the one baked in when it was scaffolded. Switching providers
needs a fresh `gate --workflows` run (with the new model) to re-bake both
the model fallback and the key mapping together; a repository variable
alone is enough only for staying on the same provider's other models.

A model whose provider needs more than one credential variable (Bedrock's
access-key pair) or none that Mylonite's registry knows about makes `gate
--workflows` refuse to scaffold at all, naming why — a single
`MYLONITE_API_KEY` secret can't express either case. Write that workflow by
hand instead. The same holds for a **local** model (Ollama, vLLM): there is
no key to map, and a hosted GitHub runner can't reach it regardless, so
scaffolding would only produce CI that can never pass.

### Supply-chain pinning

Both the scaffolded workflows and `gate-action` cap and pin their LiteLLM
install: `pyproject.toml` bounds the floor-only range Mylonite itself
depends on, and a `mylonite-constraints.txt` (vendored next to the
templates and the action) pins the exact tested release the install step
applies with `pip install -c mylonite-constraints.txt`. This is an exact
pin, not a hash lock (`--require-hashes` needs a network resolve across
every package in the tree) — raise the pin alongside `pyproject.toml`'s own
floor when you upgrade deliberately, not by letting the range drift.

### Optional: extra LLM request headers

Set a `MYLONITE_LLM_HEADERS` repository secret (`NAME=VALUE` pairs,
comma- or newline-separated — e.g. a provider workspace id your account
needs on every request) and both scaffolded workflows, and the reusable
Action's `llm-headers` input, pass it straight through as an environment
variable, never through a command-line flag. Leave it unset if you don't
need one.

### Surfacing findings in the Security tab

Emit SARIF from a scan or validation and upload it so AI-layer findings land in the
GitHub **Security tab** alongside every other code-scanning result:

```yaml
- run: mylonite report .mylonite/generated/<dir> --sarif mylonite.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mylonite.sarif }
```

Behind a corporate network? See
[Enterprise & air-gapped networking](enterprise-networking.md).

## Where to go next

- [Quickstart](quickstart.md) — install, the commands that work today, and the
  scan → generate → validate flow.
- [The validation engine](validation.md) — why a validated test is worth
  committing, and why the CI gate runs offline.
- [Enterprise & air-gapped networking](enterprise-networking.md) — self-hosted
  runners, internal model gateways, and TLS-inspecting proxies.
