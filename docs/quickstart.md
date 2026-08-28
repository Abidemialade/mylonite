# Quickstart

## Install

Requires **Python 3.11–3.13** — `litellm` (the model-agnostic LLM layer) has no 3.14
wheels yet, so create your virtualenv with a 3.11–3.13 interpreter. The `mylonite` CLI is
on PyPI:

```bash
pip install mylonite                 # the CLI that scans your app
pip install "mylonite[demo]"         # + the reference app, for `mylonite demo`
```

Then, with no API key and nothing to configure:

```bash
mylonite demo
```

That replays a recorded scan against the bundled reference app's vulnerable and guarded
builds and prints the differential — weaknesses on one side, clean on the other. It is
the fastest way to see what the tool does. See [`demo`](cli-reference.md) for exactly
what "replay" means and how it differs from a live `scan`.

The `[demo]` extra adds the reference target (`mcp-kitchen-sink`), which is a separate
package: a plain `pip install mylonite` never pulls the deliberately-vulnerable reference
agent. The extra pins it exactly, because the demo's recorded fixtures are keyed on that
package's tool schemas.

To hack on Mylonite or the reference target, use a development checkout with **two**
editable installs (the `mylonite` package, then the reference target):

On Linux / macOS (bash):

```bash
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
```

On Windows (PowerShell):

```powershell
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
```

Contributors should also run `pre-commit install` after installing.

## Commands that work today

```bash
mylonite version
mylonite check --target-file app.yaml              # free, no API key, no attack
mylonite scan reference:vulnerable
mylonite scan mcp:fetch --authorize fetch
mylonite gate reference:vulnerable                 # scan -> test -> validate, the full pipeline
mylonite report .mylonite/scans/<dir> --sarif out.sarif --json finding.json
```

- `mylonite check --target-file app.yaml` — static structural pre-check: no LLM
  call, no API key, no spend. Reports consequential tools with no approval
  step, steering descriptions, destination-taking tools, and unpinned
  descriptions from the tool schemas alone. `--enforce` turns it into a CI
  gate once the surface is clean. See the [CLI reference](cli-reference.md).
- `mylonite scan <target>` — run the live exploit-finding loop. Needs an LLM
  API key: `ANTHROPIC_API_KEY` for the default provider, or another LiteLLM
  provider via `--model` with a `provider/model` prefix (e.g.
  `--model openai/gpt-4o`) plus that provider's own key env var.
  Targets: `reference:vulnerable` / `reference:guarded`
  (the in-process reference app builds), and the bundled MCP (Model Context
  Protocol) stdio families
  `mcp:filesystem:<sandbox>`, `mcp:fetch`, `mcp:github:<owner/repo>` — these
  require `--authorize` (see the
  [responsible-use policy](security.md)) plus the family's runtime: `uv` for
  `mcp:fetch` (spawns via `uvx`), Node.js for `mcp:filesystem` /
  `mcp:github` (spawn via `npx`). Add `--dry-run` to enumerate seeds
  without an API key.
- `mylonite gate <target>` — the whole pipeline (scan → generate → validate → optional
  PR) in one command; only a kept test makes it through. See [CI gating](ci-gating.md).
- `mylonite report <dir>` — render a scan/validation as a terminal panel,
  `--sarif` (GitHub code scanning), or `--json` bundle. See
  [Reading the results](reading-results.md).

## The full flow: scan → generate → validate

The end-to-end pipeline works today. Scan a target for a weakness,
emit a regression test from the finding, then validate that the test is
*meaningful* through the differential oracle.

On Linux / macOS (bash):

```bash
mylonite scan reference:vulnerable
mylonite generate --latest
mylonite validate .mylonite/generated/indirect-injection-note-body-direct
```

On Windows (PowerShell):

```powershell
mylonite scan reference:vulnerable
mylonite generate --latest
mylonite validate .mylonite\generated\indirect-injection-note-body-direct
```

- `mylonite scan reference:vulnerable` — runs the live exploit-finding loop
  against the in-process vulnerable build and writes `exploit_*.json` artefacts
  under `.mylonite/scans/<ts>/`. Live — needs an API key (see below).
- `mylonite generate --latest` — **offline and deterministic** (no LLM call).
  Reads the newest scan's exploit, emits a testkit-based pytest regression
  test, and prints the exact `mylonite validate <dir>` command to run next.
  `--latest` picks the newest scan; pass an explicit `exploit_*.json` or scan
  dir instead if you prefer.
- `mylonite validate <dir>` — runs the `DifferentialValidator` (the
  [validation engine](validation.md)). **Live** — it makes real LLM calls
  (Haiku by default — `claude-haiku-4-5`), so it needs an API key and discloses cost/latency up
  front. It runs the full attack scan against *both* reference builds across a
  5-run flakiness filter and reports `kept` plus the mutation score. Exits `0`
  when the test is kept and `5` when it is cleanly rejected.

`generate` is the only offline command here; `scan` and `validate` both make
live LLM calls. Whether the committed regression test that `generate` emits
replays offline at the CI gate depends on the target: for the bundled
`reference:*` builds it replays **offline** (no API key needed there); for a
real, custom target (`--target-file`) there is no recorded twin to replay, so
the emitted test re-drives your actual app **live**, gated behind
`MYLONITE_LIVE_TARGET=1` (the CI workflow sets it for you) — see
[The validation engine](validation.md) and [CI gating](ci-gating.md).

## Gate it (CI) and read the results

Turn a finding into a committed regression test and a gating PR with one command, then
render it in whatever format your pipeline consumes:

```bash
mylonite gate --target-file app.yaml --authorize my-app --open-pr   # against YOUR app
mylonite report .mylonite/generated/<dir> --sarif out.sarif     # GitHub code scanning
mylonite report .mylonite/generated/<dir> --json finding.json   # dashboards / SIEM / bots
```

## Where to go next

- [Test your own app](test-your-app.md) — the custom MCP on-ramp (`scan --scaffold` → scan → gate).
- [Try it — the reference app](quarry.md) — the deliberately vulnerable playground (W1–W4 walkthrough).
- [Attack modes](attack-modes.md) — the single-shot W1–W4 attack engine.
- [The validation engine](validation.md) — why a generated test means what it claims.
- [Reading the results](reading-results.md) · [CLI reference](cli-reference.md).
