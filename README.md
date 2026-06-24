# Mylonite

> **Model robustness ≠ app security.** A frontier model can resist every generic
> prompt-injection you throw at it and still hand an attacker a win — because the hole
> is in *your app's design*, not the model's alignment. Mylonite proves whether your
> **app-layer controls** (not the model's current good behavior) are what's stopping the
> attack, writes a **validated regression test** for each weakness it finds, and gates
> CI so a model upgrade can't silently strip the protection away.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Point Mylonite at your MCP agent. It attacks the AI/agentic layer — the system prompt,
tool/function schemas, RAG pipeline, and agent memory — finds app-specific weaknesses,
and for each one emits a **validated, CI-gating `pytest` regression test**. The
validation is the moat: a **differential oracle** keeps a finding only when the attack
*fires* on the unguarded app and is *resisted* once the control is applied, across a
flakiness filter — proving the **control**, not the model's mood, carries the security.
Every headline claim is backed by an independent [verification
harness](./docs/verification.md) that scores Mylonite against external ground truth it
did not author.

It deliberately does *not* test the surrounding traditional code; that work belongs to
SAST/DAST tools.

**The keystone result.** Run the *same* model against two versions of the bundled
reference app: against the deliberately-vulnerable twin Mylonite catches a `send_email`
dispatched with **no approval step** (a pure app-design flaw no amount of model alignment
fixes); against the guarded twin it finds nothing. Same model — the app's design decides.
This is the difference between "your chatbot behaved today" and "your app is secure." See
the full [independent scorecard](./docs/verification.md), negatives included.

See [ROADMAP.md](./ROADMAP.md) for the architecture, scope, and direction, and the
[documentation site](https://abidemialade.github.io/mylonite/) for guides and reference.

> **Status:** the full `scan → generate → validate → gate` pipeline works end to end,
> against the bundled Quarry twins and your own MCP app (`--target-file`). The
> **control-efficacy oracle** proves which safeguard is load-bearing; `mylonite ablate`
> scores the whole control set (load-bearing vs. theater). A third-party
> [verification harness](./docs/verification.md) checks every claim against external
> ground truth. The command surface is deliberately narrow — deeper attack tactics
> (`--adaptive`, `--synthesize`, `--memory`, cross-model `--models`) and the remote
> SSE/HTTP adapter ship as **experimental** until they're proven on third-party targets.
> See [CHANGELOG.md](./CHANGELOG.md). `pip install mylonite` installs the CLI from PyPI;
> the offline Quarry demo target is an opt-in extra — `pip install "mylonite[demo]"`.

## Try it in 60 seconds

*(Once installed.)* `mylonite demo` runs the real scan offline against a deliberately
vulnerable agent and its guarded twin — no API key, deterministic.

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
a safety banner, a weakness table, and the headline differential:

```text
  DEMO ONLY — the Quarry is a deliberately vulnerable in-process agent.

  tool-description-instruction-smuggling   LLM01 / ASI02 / AML.T0051     ✓
  indirect-injection-via-note-body         LLM01, LLM05 / ASI01, ASI06   ✓
  unrestricted-web-fetch                   LLM06 / ASI02, ASI05          ✗
  unconfirmed-email-send                   LLM06 / ASI02                 ✗

  the Quarry: 2 exploits on vulnerable, 0 on guarded
  mode: replay (offline)
```

That **vulnerable-vs-guarded differential is the oracle** that validates every generated
regression test. (Which seeds land depends on the planner model — a robust model resists
some; what stays constant is that whatever fires on the vulnerable twin is resisted on the
guarded one.) The Quarry runs entirely in-process and never binds to a network. Full
walkthrough: [docs/quarry.md](./docs/quarry.md).

Once you've seen it, point `scan` at your own MCP app:

```bash
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml   # write a target.yaml
mylonite scan --target-file app.yaml --authorize my-app                     # then scan it
```

*(scanning needs an LLM API key; scaffolding does not)*

## From scan to a gating PR

`mylonite gate` runs the whole magic moment — find an exploit, write a regression
test, validate it against the differential oracle, and (opt-in) open a PR that
gates CI on it:

```bash
mylonite gate reference:vulnerable          # find -> test -> validate -> print the PR command
mylonite gate --target-file app.yaml --authorize your-scope --open-pr   # ...and open it
```

`gate` writes a validated regression test under `.mylonite/gate/` plus two CI
workflows (a cheap per-PR gate + nightly discovery), then prints (or, with
`--open-pr`, opens) a PR carrying the finding, its OWASP/ASI/ATLAS/NIST tags, the
validation evidence, and a human-applied suggested fix. Full guide:
[docs/ci-gating.md](./docs/ci-gating.md). Behind a corporate network, see
[docs/enterprise-networking.md](./docs/enterprise-networking.md).

## What works today

The proven core — every command here has a backing
[verification](./docs/verification.md) number or a committed differential proof:

- **`mylonite gate <target>`** — the end-to-end magic moment: scan → generate
  → validate → optionally open a gating PR. Writes the regression test and
  two CI workflow templates under `.mylonite/gate/`. Add `--open-pr` to push
  a branch and open the PR via `gh`. Use `--target-file target.yaml` for a
  custom MCP app.
- **`mylonite scan <target>`** — the async exploit-finding loop. Targets:
  `reference:vulnerable` / `reference:guarded` (the bundled Quarry twins), or
  your own MCP app via `--target-file target.yaml --authorize <scope>`. Pass
  `--command '…' --scaffold app.yaml` to introspect a server and write a starter
  target.yaml (no LLM call, no attack, no `--authorize` needed).
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
  *control*, not the model, carries the security (a synthetic guarded twin).
- **`mylonite ablate <target>`** — the control-ablation matrix: scores each
  safeguard's marginal contribution (**load-bearing vs. security-theater**), with
  `--redundancy` to find controls another control already covers and
  `--max-seeds` to probe multiple seeds per weakness. This is the "which control
  is actually carrying your security" readout.
- **`mylonite report <dir>`** — render a scan/validation as a terminal trust
  panel, **SARIF 2.1.0** for GitHub code scanning (`--sarif`), or a
  machine-readable **JSON** bundle (`--json`) for dashboards/SIEM — both carrying
  the differential proof and the OWASP/ASI/ATLAS/NIST tags.
- **`mylonite demo`** — zero-config, offline, deterministic playground that
  replays committed LLM fixtures to find exploits on the Quarry and none on its
  guarded twin. `--live` re-runs for real (needs a key).
- **`mylonite doctor`** — diagnose provider connectivity before a live scan;
  classifies failures as auth / TLS / network / rate-limit with a concrete
  remedy.
- **`mylonite taxonomy list`** — the bundled threat taxonomy: OWASP LLM Top
  10 (2025), OWASP Agentic Security Initiative (2026), MITRE ATLAS, and
  NIST AI RMF, all as data files with provenance.
- **Independent verification harness (`verification/`)** — scores Mylonite
  against external ground truth it did not author (DVMCP, InjecAgent, AgentDojo),
  with an honest scorecard including the negatives. See
  [docs/verification.md](./docs/verification.md).
- **Versioned extension contracts + plugins** — five Python Protocols
  (attack modules, target adapters, test generators, validators, compliance
  mappers) with reference implementations and entry-point-based plugin
  loading.

**Experimental** (in the tree, runnable when passed explicitly, hidden from `--help`
until proven on third-party ground truth): deeper attack tactics `scan --adaptive`
(a strategist refines the injection until it lands), `scan --synthesize` (tool-chaining
to a sink), `scan --memory` (stateful cross-turn memory poisoning), cross-model
durability `validate --models`, the bundled `mcp:filesystem|fetch|github` shorthands,
and the remote SSE/HTTP transport. See [attack modes](./docs/attack-modes.md).

## Documentation

**Full docs site:** [abidemialade.github.io/mylonite](https://abidemialade.github.io/mylonite/)
(or `mkdocs serve` from a checkout). Highlights:

- [Quickstart](./docs/quickstart.md) · [Test your own app](./docs/test-your-app.md) — install and point it at your MCP server.
- [Weakness classes](./docs/weakness-classes.md) · [Attack modes](./docs/attack-modes.md) — what's tested and how attacks work.
- [The validation engine](./docs/validation.md) — the differential oracle (the moat).
- [Independent verification](./docs/verification.md) — the honest scorecard against ground truth Mylonite didn't author.
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
