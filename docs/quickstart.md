# Quickstart

## Install

Requires Python 3.11 or newer. The `mylonite` CLI is on PyPI:

```bash
pip install mylonite
```

The demo and the differential oracle also use the Quarry (`mcp-kitchen-sink`)
reference target, which is **not** published yet — so to run them you need a
clone-first install with **two** editable installs (the `mylonite` package, then
the reference target):

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
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
```

Contributors should also run `pre-commit install` after installing.

## Commands that work today

```bash
mylonite version
mylonite taxonomy list --framework owasp-llm
mylonite demo
mylonite scan reference:vulnerable
mylonite scan mcp:fetch --authorize fetch
mylonite scan reference:vulnerable --adaptive      # strategist refines until it lands
mylonite scan reference:vulnerable --synthesize    # chain 2+ tools to a sink
mylonite scan reference:vulnerable --memory        # cross-turn memory poisoning
mylonite gate reference:vulnerable                 # scan -> test -> validate, the magic moment
mylonite report .mylonite/scans/<dir> --sarif out.sarif --json finding.json
```

- `mylonite demo` — the 60-second offline showcase: replays recorded scans
  against the Quarry's vulnerable and guarded twins and prints the
  differential. **No API key needed.** See [The Quarry](quarry.md).
- `mylonite taxonomy list` — browse the bundled threat taxonomy
  (`owasp-llm`, `owasp-asi`, `atlas`, `nist`).
- `mylonite scan <target>` — run the live exploit-finding loop. Needs an LLM
  API key: `ANTHROPIC_API_KEY` for the default provider, or another LiteLLM
  provider via `--provider`/`--model` plus that provider's own key env var.
  Targets: `reference:vulnerable` / `reference:guarded`
  (the in-process Quarry twins), and the bundled MCP stdio families
  `mcp:filesystem:<sandbox>`, `mcp:fetch`, `mcp:github:<owner/repo>` — these
  require `--authorize` (see the
  [responsible-use policy](security.md)) plus the family's runtime: `uv` for
  `mcp:fetch` (spawns via `uvx`), Node.js for `mcp:filesystem` /
  `mcp:github` (spawn via `npx`). Add `--dry-run` to enumerate seeds
  without an API key.
- `mylonite scan <target> --adaptive` — opt-in adaptive loop: when an
  indirect-injection attempt doesn't fire, an LLM strategist re-crafts the
  injection and retries within a budget (needs a session-capable target, e.g.
  `reference:*`). Off by default.
- `mylonite scan <target> --synthesize` / `--memory` — opt-in tool-chaining
  synthesis and stateful cross-turn memory poisoning. See [Attack modes](attack-modes.md).
- `mylonite gate <target>` — the whole pipeline (scan → generate → validate → optional
  PR) in one command; only a kept test makes it through. See [CI gating](ci-gating.md).
- `mylonite report <dir>` — render a scan/validation as a terminal panel, HTML
  dashboard, `--sarif` (GitHub code scanning), or `--json` bundle. See
  [Reading the results](reading-results.md).

## The full flow: scan → generate → validate

The end-to-end "magic moment" works today. Scan a target for a weakness,
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
  against the in-process vulnerable twin and writes `exploit_*.json` artefacts
  under `.mylonite/scans/<ts>/`. Live — needs an API key (see below).
- `mylonite generate --latest` — **offline and deterministic** (no LLM call).
  Reads the newest scan's exploit, emits a testkit-based pytest regression
  test, and prints the exact `mylonite validate <dir>` command to run next.
  `--latest` picks the newest scan; pass an explicit `exploit_*.json` or scan
  dir instead if you prefer.
- `mylonite validate <dir>` — runs the `DifferentialValidator` (the
  [validation engine](validation.md)). **Live** — it makes real LLM calls
  (Haiku by default), so it needs an API key and discloses cost/latency up
  front. It runs the full attack scan against *both* reference twins across a
  5-run flakiness filter and reports `kept` plus the mutation score. Exits `0`
  when the test is kept and `5` when it is cleanly rejected.

`generate` is the only offline command here; `scan` and `validate` both make
live LLM calls. The committed regression test that `generate` emits, however,
replays **offline** at the CI gate (no API key needed there) — see
[The validation engine](validation.md).

## Gate it (CI) and read the results

Turn a finding into a committed regression test and a gating PR with one command, then
render it in whatever format your pipeline consumes:

```bash
mylonite gate --target-file app.yaml --authorize me --open-pr   # against YOUR app
mylonite report .mylonite/validated/<dir> --sarif out.sarif     # GitHub code scanning
mylonite validate <dir> --models claude-haiku-4-5,claude-sonnet-4-6   # durable across upgrades?
```

## Where to go next

- [Test your own app](test-your-app.md) — the custom MCP on-ramp (`init-target` → scan → gate).
- [Try it — the Quarry](quarry.md) — the deliberately vulnerable playground (W1–W4 walkthrough).
- [Attack modes](attack-modes.md) — single-shot, adaptive, tool-chaining, memory poisoning.
- [The validation engine](validation.md) — why a generated test means what it claims.
- [Reading the results](reading-results.md) · [CLI reference](cli-reference.md).
