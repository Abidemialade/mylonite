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

## Commands still to come

```bash
mylonite generate     # emit a regression test from a finding (Phase 2)
mylonite validate     # run the test through the differential oracle (Phase 2)
mylonite init         # scaffold a config (Phase 3)
```

These exist as stubs that exit non-zero with a pointer to
[`ROADMAP.md`](https://github.com/Abidemialade/mylonite/blob/main/ROADMAP.md).

## Where to go next

- [The Quarry](quarry.md) — the deliberately vulnerable playground: run the
  demo, walk the W1–W4 weakness catalogue, then point the scanner at a real
  MCP server.
- [Concepts](concepts.md) — scope and the differential-oracle moat.
