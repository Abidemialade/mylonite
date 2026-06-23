# Mylonite

> Point it at your AI agent; when it finds a real weakness, it writes the
> **validated** regression test that closes it — in your repo, gating your CI.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — the system prompt, tools,
RAG pipeline, agent planner — and emits **validated regression tests** that
gate CI. It deliberately does *not* test the surrounding traditional code;
that work belongs to SAST/DAST tools.

See [ROADMAP.md](./ROADMAP.md) for the architecture, scope, and direction, and the
[documentation site](https://abidemialade.github.io/mylonite/) for guides and reference.

> **Status:** the full `scan → generate → validate → gate` pipeline works end to end,
> against the bundled Quarry twins and your own MCP app (`--target-file`). v0.6.0
> shipped the `scan → gating PR` flow (`mylonite gate` + a reusable GitHub Action);
> v0.7.0–0.7.2 added the *control-efficacy oracle* (which safeguard is load-bearing),
> differential-by-default on real targets, gating metamorphic robustness, SARIF /
> GitHub code scanning, and proven-fix diffs in the PR. **v0.7.3** adds stateful
> **memory-poisoning** (`scan --memory`), **cross-model durability**
> (`validate --models`), and a machine-readable JSON bundle (`report --json`). See
> [CHANGELOG.md](./CHANGELOG.md). `pip install mylonite` installs the CLI from PyPI; the
> offline Quarry demo target is an opt-in extra — `pip install "mylonite[demo]"`.

## Try it in 60 seconds

*(Once installed.)* The real zero-second funnel is the GIF — watch Mylonite
find four exploits against a deliberately vulnerable agent, offline, with no
API key:

![Mylonite demo](docs/assets/quarry-demo.gif)

*The `mylonite demo` playground running against the Quarry and its guarded
twin. ([How this GIF is recorded.](docs/assets/recording-script.md))*

**Install the CLI and run the demo** — `mylonite` is on PyPI. The base install is just
the tool that scans your app; the offline Quarry demo target is an opt-in extra (a
deliberately-vulnerable mock agent, never pulled by a plain install). Requires
**Python 3.11–3.13** — `litellm` (the model-agnostic LLM layer) has no 3.14 wheels yet,
so create your virtualenv with a 3.11–3.13 interpreter. The CLI prints a clear note if
it detects 3.14+.

```bash
pip install "mylonite[demo]"   # the [demo] extra adds the offline Quarry target
mylonite demo                  # no clone, no API key
```

For a development checkout (to hack on Mylonite or the reference target):

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

## From scan to a gating PR

`mylonite gate` runs the whole magic moment — find an exploit, write a regression
test, validate it against the differential oracle, and (opt-in) open a PR that
gates CI on it:

```bash
mylonite gate reference:vulnerable          # find -> test -> validate -> print the PR command
mylonite gate --target-file target.yaml --authorize your-scope --open-pr   # ...and open it
```

`gate` writes a validated regression test under `.mylonite/gate/` plus two CI
workflows (a cheap per-PR gate + nightly discovery), then prints (or, with
`--open-pr`, opens) a PR carrying the finding, its OWASP/ASI/ATLAS/NIST tags, the
validation evidence, and a human-applied suggested fix. Full guide:
[docs/ci-gating.md](./docs/ci-gating.md). Behind a corporate network, see
[docs/enterprise-networking.md](./docs/enterprise-networking.md).

## What works today (v0.7.3)

- **`mylonite gate <target>`** — the end-to-end magic moment: scan → generate
  → validate → optionally open a gating PR. Writes the regression test and
  two CI workflow templates under `.mylonite/gate/`. Add `--open-pr` to push
  a branch and open the PR via `gh`. Use `--target-file target.yaml` for a
  custom MCP app.
- **`mylonite scan <target>`** — the async exploit-finding loop. Targets:
  `reference:vulnerable` / `reference:guarded` (the bundled Quarry twins),
  plus real open-source MCP servers — `mcp:filesystem:<sandbox>`,
  `mcp:fetch`, and `mcp:github:<owner/repo>` (these need an LLM API key,
  `uv`/`uvx`, and an explicit `--authorize`). Custom MCP apps: pass
  `--target-file target.yaml --authorize <scope>`. Depth modes: `--adaptive`
  (a strategist refines the injection until it lands), `--synthesize`
  (tool-chaining to a sink; works on `--target-file` too), and `--memory`
  (stateful cross-turn memory poisoning — the "zombie agent" shape).
- **`mylonite generate [SCAN_PATH]`** — emit a `pytest` regression test from
  a confirmed exploit (offline, no LLM). Pass `--latest` to auto-pick the
  newest scan, or `--target-file` when the scan was against a custom target.
  Emitted tests carry OWASP/ASI/ATLAS/NIST tags (NIST auto-derived) and the
  attack tier.
- **`mylonite validate <generated-dir>`** — run the differential-oracle
  validator live (real LLM, Haiku) to prove the test is meaningful: it must
  fail on the vulnerable twin and pass on the guarded one across a flakiness
  filter *and* survive the gating metamorphic rewrites. Pass `--target-file`
  for custom targets (re-drives the real app); `--fast` skips the differential
  leg for a faster, weaker gate. The **control-efficacy oracle** runs **by
  default** on a real target — it holds the model constant and proves the
  *control*, not the model, carries the security (a synthetic guarded twin);
  add `--adaptive` to grade whether it holds under an adaptive attacker.
- **`mylonite validate --models a,b,c`** — **cross-model durability**: re-prove
  the differential across model versions and flag any where the weakness
  re-emerges, so a fix doesn't silently break on a model upgrade.
- **`mylonite ablate <target>`** — the control-ablation matrix: scores each
  safeguard's marginal contribution (load-bearing vs. security-theater), with
  `--redundancy` to find controls another control already covers and
  `--max-seeds` to probe multiple seeds per weakness.
- **`mylonite report <dir>`** — render a scan/validation as a terminal trust
  panel, a self-contained **HTML** dashboard (`--html`), **SARIF 2.1.0** for
  GitHub code scanning (`--sarif`), or a machine-readable **JSON** bundle
  (`--json`) for dashboards/SIEM — all carrying the differential proof and the
  OWASP/ASI/ATLAS/NIST tags.
- **`mylonite demo`** — zero-config, offline, deterministic playground that
  replays committed LLM fixtures to find four exploits on the Quarry and
  none on its guarded twin. `--live` re-runs for real (needs a key).
- **`mylonite doctor`** — diagnose provider connectivity before a live scan;
  classifies failures as auth / TLS / network / rate-limit with a concrete
  remedy.
- **`mylonite init-target`** — scaffold a `target.yaml` for a custom MCP app
  by launching it once (no LLM call), listing its tools, and writing a
  commented starter with suggested `weakness_classes`, `seed_arm`, and
  `effect_probe` template.
- **`mylonite taxonomy list`** — the bundled threat taxonomy: OWASP LLM Top
  10 (2025), OWASP Agentic Security Initiative (2026), MITRE ATLAS, and
  NIST AI RMF, all as data files with provenance.
- **Custom MCP targets via `--target-file`** — declare your MCP server's
  `command`, `weakness_classes`, `seed_arm`, and `effect_probe` in a YAML
  file; Mylonite drives indirect injection and validates effect end-to-end.
- **Versioned extension contracts + plugins** — five Python Protocols
  (attack modules, target adapters, test generators, validators, compliance
  mappers) with reference implementations and entry-point-based plugin
  loading.

## Documentation

**Full docs site:** [abidemialade.github.io/mylonite](https://abidemialade.github.io/mylonite/)
(or `mkdocs serve` from a checkout). Highlights:

- [Quickstart](./docs/quickstart.md) · [Test your own app](./docs/test-your-app.md) — install and point it at your MCP server.
- [Weakness classes](./docs/weakness-classes.md) · [Attack modes](./docs/attack-modes.md) — what's tested and how attacks work.
- [The validation engine](./docs/validation.md) — the differential oracle (the moat).
- [Reading the results](./docs/reading-results.md) · [CLI reference](./docs/cli-reference.md) · [target.yaml](./docs/target-file.md).
- [CI gating](./docs/ci-gating.md) · [Architecture](./docs/architecture.md) · [Plugin authoring](./docs/plugin-authoring.md).
- [ROADMAP.md](./ROADMAP.md) · [CONTRIBUTING.md](./CONTRIBUTING.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [SECURITY.md](./SECURITY.md).

## Responsible use

Mylonite reproduces working weaknesses in AI agents. **Use it only against
targets you control or are contractually authorized to test.** The `scan`
command refuses to run against real targets without an explicit `--authorize`
flag naming the target. The bundled vulnerable reference agent runs
in-process and binds to nothing.

Full policy: [SECURITY.md](./SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
