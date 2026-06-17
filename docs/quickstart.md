# Quickstart

## Install

Requires Python 3.11 or newer. Mylonite is not on PyPI yet — install from
source. The flow is clone-first with **two** editable installs: the
`mylonite` package, then the Quarry (`mcp-kitchen-sink`) reference target
used by the demo and the differential oracle.

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
mylonite scan reference:vulnerable --adaptive
mylonite scan reference:vulnerable --synthesize
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
- `mylonite scan <target> --synthesize` — opt-in tool-chaining synthesis:
  synthesize an app-specific multi-tool exploit chain from the tool surface and
  differentially validate it against the twins (reference-twin targets for now).
  See [Concepts](concepts.md#adaptive-attacks-and-tool-chaining-synthesis).

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

## Commands still to come

```bash
mylonite init         # scaffold a config (Phase 3)
```

This exists as a stub that exits non-zero with a pointer to
[`ROADMAP.md`](https://github.com/Abidemialade/mylonite/blob/main/ROADMAP.md).

## Where to go next

- [The Quarry](quarry.md) — the deliberately vulnerable playground: run the
  demo, walk the W1–W4 weakness catalogue, then point the scanner at a real
  MCP server.
- [The validation engine](validation.md) — why a generated test means what
  it claims, and why the CI gate runs offline.
- [Concepts](concepts.md) — scope and the differential-oracle moat.
