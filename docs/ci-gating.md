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
    of 50. If the budget runs out, the summary **names the seeds that never
    started** — those proved nothing and are reported as NOT TESTED, never as
    clean.

    **`--max-llm-calls` is therefore a floor-adjusted budget, not a hard ceiling.**
    Worst case is `cap + (seeds - 1) × max(2, cap ÷ seeds)` — with `--max-llm-calls
    50` against a surface that synthesises 100 seeds, up to roughly 250 calls. That
    is deliberate: the alternative is that the seeds which happen to start last
    make no call at all, and a probe that never ran is indistinguishable from a
    target that resisted. Size CI spend against the worst case, not the flag value.

```bash
# against the bundled reference agent
mylonite gate reference:vulnerable

# against your own MCP app
mylonite scan --command "python" --arg "-m" --arg "your.server" --scaffold target.yaml
mylonite gate --target-file target.yaml --authorize custom --open-pr
```

### What `gate` touches

**By default, nothing outside its own output directory.** `gate` writes
`.mylonite/gate/` — the generated test, the exploit JSON, the validation report,
your `target.yaml` and `PR_BODY.md` — and then prints the exact `git` and `gh`
commands to commit and open the PR yourself. Your repository is not modified:
no branch, no commit, no workflow files.

Two flags opt in to the rest:

- **`--open-pr`** creates the branch, commits the gate directory, pushes, and
  opens the PR via `gh`. If `gh` is missing or unauthenticated it still commits
  and prints the remaining two commands.
- **`--workflows`** additionally scaffolds the two `.github/workflows/`
  templates described below.

Both are off by default. Writing into someone's repository is an action you ask
for, not one you opt out of.

> **Changed in 0.8.5.** `gate` previously created a branch and a commit on every
> run, and scaffolded the workflow templates unless you passed `--no-workflows`.
> If you relied on that, add `--open-pr` and `--workflows` explicitly.

The PR body is itself a result surface (see [Reading the results](reading-results.md#the-gating-pr)):

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

For a custom target the gate proves the finding **differentially by default** (the
control-efficacy check); `--fast` skips that leg for a faster, cheaper check that no
longer proves the safeguard carries the security — a deliberate trade-off, not the
recommended default.

## Adopting it in GitHub CI

Add one secret — `MYLONITE_API_KEY` (your provider key) — and the two
scaffolded workflows:

- **`mylonite-gate.yml`** runs on every PR. It re-drives your agent (bounded:
  deterministic effect-probe, small model, 1 iteration) and fails the check on
  a regression. It sets `MYLONITE_LIVE_TARGET=1` for you (see
  [The validation engine](validation.md)) — without that variable the committed
  test for a custom target is *skipped*, not run. It also sets
  `MYLONITE_REQUIRE_GATE_RUN=1`, which makes the job fail if a Mylonite gate test
  was skipped or none was collected, so the check can only go green by running
  the gate. `pytest -ra` prints the reason if it does.

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

Both workflows install the Mylonite release that wrote them:
`pip install "mylonite==X.Y.Z"`, where `X.Y.Z` is the version that ran
`gate --workflows`. A new Mylonite release never changes what your CI runs until
you change that line, or re-run `gate --workflows` with the new version.

### Prerequisites `gate --open-pr` assumes

`mylonite gate --open-pr` shells out to `git`/`gh` directly (no GitHub API
client), so it inherits a few real preconditions the scaffolded workflows
satisfy automatically but a local or non-GitHub run must provide itself:

- **A git repository, and `gate` run from its root.** `gate` resolves the repo
  root as the current working directory (`Path.cwd()`) — it does not search
  upward for a `.git` — so `cd` into the repo root before running it.
- **A `main` branch as the PR base.** The branch/commit/PR flow targets `main`
  by default; if your default branch is named differently, open the PR
  yourself with the printed `git push` + `gh pr create --base <branch>`
  command instead of `--open-pr`.
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
you no evidence. Re-run the printed `git`/`gh` commands by hand once the
precondition is fixed.

### The reusable Action

```yaml
- uses: Abidemialade/mylonite/gate-action@v0.10.2
  with:
    target-file: .mylonite/gate/target.yaml
    authorize: ${{ vars.MYLONITE_AUTHORIZE }}   # your target's scope, or family if no scope
    open-pr: "true"
```

**The tag is the release.** The action lives in this repository
(`gate-action/action.yml`), so every Mylonite release tag `vX.Y.Z` is also an
action tag, and `gate-action@vX.Y.Z` installs exactly `mylonite==X.Y.Z`. Tags
before v0.10.2 predate the pin and install the latest release. To upgrade,
change the tag. `scripts/prepare_release.py` bumps the action's pin and
the tag on this page with the version, and the release job refuses a tag whose
pin does not match.

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
- the scan artefacts (`exploit_<pattern_id>.json`, `target.yaml`) co-located with the test
- a provider key
- network egress to both the model provider and your MCP server

Only the bundled reference/replay test runs offline unconditionally; a gate against your
own app always re-drives the real target.

What does *not* port: opening the gating PR, inline check-run annotations, and Security-tab
SARIF upload all use the `gh` CLI and GitHub APIs. On other CI, run the test as the gate and
surface results through your own reporting — `mylonite report --sarif` still emits standard
SARIF 2.1.0 if your platform ingests it.

### Provider keys

The scaffolded workflows map the `MYLONITE_API_KEY` secret to
`ANTHROPIC_API_KEY` (Anthropic is the default provider). If you run a different
provider, set that provider's key env var in the workflow instead (e.g.
`OPENAI_API_KEY`) and pass `--model` with a `provider/model` prefix (e.g.
`--model openai/gpt-4o`) — Mylonite routes through LiteLLM.

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
