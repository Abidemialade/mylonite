# CI gating

`mylonite gate` runs the whole flow — find an exploit, write a regression test,
validate it against the differential oracle, and (opt-in) open a PR that gates
CI on it.

## The end-to-end flow (local)

Against your own app this drives a real agent and makes real model calls, so budget
minutes and API spend rather than seconds.

```bash
# against the bundled reference agent
mylonite gate reference:vulnerable

# against your own MCP app
mylonite scan --command "python" --arg "-m" --arg "your.server" --scaffold target.yaml
mylonite gate --target-file target.yaml --authorize custom --open-pr
```

Without `--open-pr`, `gate` writes `.mylonite/gate/` (the test, the exploit,
your `target.yaml`) and the `.github/workflows/` templates, commits them to a
branch, and prints the exact `gh pr create` command. With `--open-pr` it opens
the PR via `gh`.

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
  a regression. Cheap — a few cents per PR. It sets `MYLONITE_LIVE_TARGET=1`
  for you (see [The validation engine](validation.md)) — without that
  variable the committed test for a custom target is *skipped*, not run, and
  `pytest` still exits `0`.
- **`mylonite-discovery.yml`** runs nightly or on demand. It does the expensive
  full discovery and opens a fresh gating PR when it finds a new exploit. It
  also needs a repository **variable** — `vars.MYLONITE_AUTHORIZE` — set to
  the same value your own `--authorize` would need (the target's declared
  `scope`, or its `family` if no scope is declared; see
  [target.yaml](target-file.md)); the workflow passes it straight through to
  `mylonite gate --authorize`.

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
  and what Mylonite's own repo uses for its dev artefacts), that commit is a
  silent no-op: the PR opens with no test in it, and the per-PR gate workflow
  then has nothing to run. Make sure your `.gitignore` does **not** ignore the
  gate output directory.

### The reusable Action

```yaml
- uses: Abidemialade/mylonite/gate-action@main
  with:
    target-file: .mylonite/gate/target.yaml
    authorize: ${{ vars.MYLONITE_AUTHORIZE }}   # your target's scope, or family if no scope
    open-pr: "true"
```

**Not yet pinned to a stable release.** `gate-action` (`gate-action/action.yml`
in this repo) has no tagged release yet — `@main` tracks the tip of the
default branch. For a reproducible pin, reference a specific commit SHA
instead of `@main` until a versioned tag exists.

## Other CI systems (Jenkins, GitLab, …)

The committed gate is a plain `pytest` file with no GitHub dependency, so it should run
anywhere that meets the preconditions below. **GitHub Actions is the only configuration we
test**, so treat other systems as supported-but-unverified.

```bash
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate
```

**The environment variable is required.** Without it the live test is skipped and `pytest`
exits **0** — your pipeline goes green having tested nothing. `mylonite generate` prints
this exact command for that reason. You also need:

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
