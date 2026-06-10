# Mylonite

> Point it at your AI agent; it finds a real weakness and writes the
> regression test that closes it forever — in your repo, gating your CI.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — the system prompt, tools,
RAG pipeline, agent planner — and emits **validated regression tests** that
gate CI. It deliberately does *not* test the surrounding traditional code;
that work belongs to SAST/DAST tools.

The full product thesis, market positioning, and phased build plan live in
[ROADMAP.md](./ROADMAP.md).

> **Status:** v0.3.0 — `mylonite scan` and the zero-config `mylonite demo`
> playground work today against the bundled reference agent and real
> open-source MCP servers. The differential validation engine and test
> emission (Phase 2 — the moat) are next. See [CHANGELOG.md](./CHANGELOG.md)
> and the [issue tracker](https://github.com/Abidemialade/mylonite/issues)
> for what is and isn't implemented today.

## Try it in 60 seconds

*(Once installed.)* The real zero-second funnel is the GIF — watch Mylonite
find four exploits against a deliberately vulnerable agent, offline, with no
API key:

![Mylonite demo](docs/assets/quarry-demo.gif)

*The `mylonite demo` playground running against the Quarry and its guarded
twin. ([How this GIF is recorded.](docs/assets/recording-script.md))*

Neither `mylonite` nor `mcp-kitchen-sink` is published to PyPI yet, so the
install is **clone-first** with two editable installs. Requires Python 3.11+.

```bash
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
mylonite demo
```

```powershell
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink
mylonite demo
```

**No API key needed** — the demo replays recorded model behavior; add
`--live` to re-run for real.

The demo runs the real scan twice — once against the deliberately vulnerable
reference agent ("the Quarry") and once against its guarded twin — and prints
a safety banner, a weakness table, and the headline result:

```text
  SAFETY: in-process, loopback-only, no network egress.

  W1  Tool-description smuggling   OWASP LLM01 · ASI01 · AML.T...
  W2  Poisoned-note → action       OWASP LLM01 · ASI02 · AML.T...
  W3  Unrestricted web_fetch       OWASP LLM06 · ASI02 · AML.T...
  W4  Unconfirmed send_email       OWASP LLM06 · ASI05 · AML.T...

  4 exploits on vulnerable, 0 on guarded
  mode: replay (offline)
```

The Quarry runs entirely in-process and never binds to a network. Full
walkthrough: [docs/quarry.md](./docs/quarry.md).

Once you've seen it, point `scan` at a real target:

```bash
mylonite scan mcp:fetch --authorize fetch
```

*(needs an LLM API key + [`uv`](https://docs.astral.sh/uv/) installed)*

## What works today (v0.3.0)

- **`mylonite scan <target>`** — the async exploit-finding loop. Targets:
  `reference:vulnerable` / `reference:guarded` (the bundled Quarry twins),
  plus real open-source MCP servers — `mcp:filesystem:<sandbox>`,
  `mcp:fetch`, and `mcp:github:<owner/repo>` (these need an LLM API key,
  `uv`/`uvx`, and an explicit `--authorize`).
- **`mylonite demo`** — zero-config, offline, deterministic playground that
  replays committed LLM fixtures to find four exploits on the Quarry and
  none on its guarded twin. `--live` re-runs for real (needs a key).
- **`mylonite taxonomy list`** — the bundled threat taxonomy: OWASP LLM Top
  10 (2025), OWASP Agentic Security Initiative (2026), MITRE ATLAS, and
  NIST AI RMF, all as data files with provenance.
- **Versioned extension contracts + plugins** — five Python Protocols
  (attack modules, target adapters, test generators, validators, compliance
  mappers) with reference implementations and entry-point-based plugin
  loading.

## Documentation

- [docs/quarry.md](./docs/quarry.md) — the Quarry playground walkthrough.
- [ROADMAP.md](./ROADMAP.md) — phased build plan, architecture, and engineering standards.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — dev setup, how to author a plugin.
- [GOVERNANCE.md](./GOVERNANCE.md) — decision-making, registry acceptance.
- [SECURITY.md](./SECURITY.md) — responsible-disclosure + dual-use policy.
- Docs site (mkdocs-material): `mkdocs serve` from a checkout. Hosted docs
  land with the Phase 4 launch.

## Responsible use

Mylonite reproduces working weaknesses in AI agents. **Use it only against
targets you control or are contractually authorized to test.** The `scan`
command refuses to run against real targets without an explicit `--authorize`
flag naming the target. The bundled vulnerable reference agent runs
in-process and binds to nothing.

Full policy: [SECURITY.md](./SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
