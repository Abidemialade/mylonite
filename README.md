# Mylonite

> **A safe model is not the same thing as a safe app.** A top-tier model can shrug off
> every generic prompt-injection you throw at it and still hand an attacker a win — because
> the weakness is in how your app is *wired*, not in how the model behaves. Mylonite checks
> whether your app's own safeguards are what stop an attack, writes a test for every
> weakness it finds, and wires that test into CI so a future model upgrade cannot quietly
> remove the protection.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mylonite.svg)](https://pypi.org/project/mylonite/)
[![GitHub release](https://img.shields.io/github/v/release/Abidemialade/mylonite)](https://github.com/Abidemialade/mylonite/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**For teams shipping MCP or agentic apps who want CI-enforced regression coverage on the AI
layer.**

Point Mylonite at any MCP (Model Context Protocol) app, whatever model or framework sits
behind it. It attacks the part an ordinary code scanner cannot see — the system prompt and
the tool descriptions your agent reads — finds weaknesses specific to your app, and turns
each one into a **`pytest` test that gates your CI**.

Mylonite deliberately does *not* review your ordinary application code. That is what
SAST/DAST tools are for.

## How it works

The idea is simple: **run the same attack twice.**

1. Once against your app as it is.
2. Once with the safeguard in place.

A weakness is only reported if the attack **succeeds** the first time and is **stopped** the
second — repeated several times over, so that a model having a good or bad day cannot
decide the outcome. (In the codebase and the docs this is the *differential*, or
control-efficacy check.)

That answers a question a one-off scan cannot: **is your safeguard doing the work, or is
the model's current good behaviour doing it?** Only one of those survives a model upgrade.

### Two levels of proof

Mylonite always tells you which one you got.

| What plays the "safeguard" role | What a kept finding tells you | How to get it |
|---|---|---|
| **Your own safeguard**, switched off and on | Your implementation is doing the work. The stronger result. | Declare `control_env` in your `target.yaml` |
| **A standard safeguard** Mylonite applies at the boundary | The attack is real, and this kind of safeguard closes it — but what stopped it was Mylonite's stand-in, not your code | The default; works on any app, no setup |

The second is genuinely useful, and it is what runs against most real apps. It is a weaker
statement than the first, and no Mylonite output will dress it up as the stronger one.

## How it has been tested

Mylonite ships an [independent verification harness](./docs/verification.md) that scores it
against material it did not write — runnable third-party MCP servers and published academic
benchmarks. The harness is in this repository and you can run it yourself.

### Results against third-party targets

- **A kept finding on a third-party MCP email server.** The attack succeeded **5 times out
  of 5** against the server as shipped, and **0 times out of 5** with the safeguard in
  place. Scope of that run: the server needed two fixes before it would start at all (a
  launch wrapper, and a one-line bug in its own `send_email`), the weakness only appears
  when the app's system prompt tells the agent to send without asking, and the safeguard
  was Mylonite's boundary stand-in rather than a second build of the server. Full detail in
  [the capability matrix](./verification/CAPABILITY_MATRIX.md).
- **No false alarms** on a third-party server with nothing wrong with it (Enkrypt's
  `echo_mcp`). Running the same comparison against a *hardened* third-party server is still
  outstanding — see
  [verification](./docs/verification.md#layer-3--precision-false-positives-on-known-good-targets).
- **A real weakness found in a published vulnerable-MCP corpus** (MCPSecBench). When that
  finding was re-run to confirm it, it failed to reproduce (0 of 3 runs), so Mylonite
  discarded it instead of shipping a flaky test.
- **The judge checked against real third-party examples** — AgentDojo transcripts from
  models that genuinely fell for attacks, not examples we wrote ourselves.
- **The safety rails hold under test.** A check that could not be run is never reported as
  a pass; a score with nothing to measure is labelled as such; work outside the tool's
  scope is marked rather than graded.

### Results that came back negative

Published for the same reason the positive ones are.

- **0 out of 8 found** on one external challenge set (DVMCP, using Claude Haiku 4.5).
- **On InjecAgent** (100 cases per split, using a local `llama3.2:3b`) the judge scored
  **F1 1.000** on the direct-harm split and **F1 0.833 at 0.714 recall** on the
  data-stealing split in 0.10.0 (0.9.0 measured 0.400 at 0.25 recall). That recall rests
  on only 7 attacks that succeeded, so we record it as unresolved at this sample size, not
  as an improvement. The gap between the splits is the finding, so both are published.
- **Judge agreement of F1 0.41** against AgentDojo's own labels. Mylonite's judge asks "did
  harm actually happen?"; AgentDojo asks "was the exact goal achieved?". Some of that gap
  is a genuine difference in question, which we have not resolved.
- **No model-fooling weakness found in an external app.** A robust model resisted every
  generic injection. The one thing that landed was a flaw in how the app was built.

### Current limits

- **Against a single-build app, only the weaker statement is available.** With no
  `control_env` to switch, the safeguard is Mylonite's stand-in rather than your code, and
  no output will claim otherwise.
- **Finding nothing is the normal outcome** for a well-built app on a robust model. See
  [below](#finding-nothing-is-also-a-result).
- **The evidence rests largely on one model** — Claude Haiku 4.5 — at small, deliberately
  cost-capped sample sizes.
- **The published figures were measured between 25 June and 14 September 2026.** The
  benchmark results carry the version they were measured against
  (`verification/results/0.9.0/` and `verification/results/0.10.0/`); the run logs in the
  capability matrix do not. Figures
  have not been re-measured for every release since, so read them as a floor rather than a
  current reading. Per-release re-measurement is planned.
- **Run transcripts are not published.** The harness and its scorers are, so you can
  produce your own numbers; you cannot yet audit ours.
- **No third party has built a plugin** against the extension points yet.

Full scorecard with caveats: [docs/verification.md](./docs/verification.md). Everything that
limits the tool's reach is collected in [docs/limitations.md](./docs/limitations.md).

## Finding nothing is also a result

Worth knowing before you run it. Against a well-built app on a robust model, Mylonite will
often correctly find **nothing** — that is the tool working, not failing. Proving a
safeguard carries the security requires a weakness that actually lands, which in practice
means a design flaw (an action with real consequences and no approval step, an unrestricted
outbound request) or an app configured to act on its own.

That is why [Try it](#try-it) starts with the bundled practice app rather than your code.
That app is deliberately insecure, so it finds something every time and you can watch the
machinery work before pointing it somewhere the honest answer may be "nothing".

## Where this sits

Static scanners read your tool descriptions and flag whatever looks risky, leaving you to
judge which flags matter. Model-eval harnesses swap models and score which behaves best.
Mylonite includes a quick structural check of that first kind (`mylonite check`), but its
purpose is the step neither of those takes: run the attack against your app, then hold the
model constant and switch only your safeguard. The result is evidence about **your
safeguard**, not about how a description reads or how a model scored today.

## Project status

**Beta, and essentially a single maintainer** — one outside contribution to date, the rest
of the history from the maintainer and Dependabot. Over 2,300 tests, with CI (ruff, mypy,
pytest, pre-commit) enforced on every pull request. The extension points are versioned
public API, but nobody outside the project has built against them yet. If you are weighing
this as a dependency in a security pipeline, pin a version — and read
[Known limitations](./docs/limitations.md) first.

## Install

```bash
pip install mylonite                      # the CLI, from PyPI
pip install "mylonite[demo]"              # ...plus the bundled practice app
```

Python 3.11–3.14.

The `[demo]` extra installs the bundled practice app, and you need it for **any**
`reference:...` command — `demo`, `check reference:...` and `scan reference:...` alike.

Scanning your own app needs a model: an API key for a hosted provider, or no key at all for
one you host yourself (Ollama, vLLM, or a LiteLLM proxy — see
[self-hosted models](./docs/self-hosted-models.md)). `check`, `scan --scaffold` and `report`
never need a model at all, and `demo` replays recorded responses rather than calling one.

## Try it

**No API key, no install, one command** (needs [uv](https://docs.astral.sh/uv/)):

```bash
uvx --from "mylonite[demo]" mylonite demo
```

On every pull request, CI builds Mylonite from source and runs this command against that
build on Python 3.14, on Linux and Windows, in an 80-column terminal.

With the `[demo]` extra already installed (see [Install](#install)), the same demo is:

```bash
mylonite demo
```

Either way, that runs the comparison against the bundled practice app — deliberately insecure, runs
in-process, opens no network ports — and prints what got through on the unguarded build
next to what was stopped on the guarded one. Same attacks, two builds, different outcomes.
**That contrast is the point of the tool.**

`demo` replays model responses recorded against those bundled apps, so it is offline and
gives the same answer every time. The scan, the adapters, the checks and the comparison are
all the real ones; only the model's replies are pre-recorded, and the output tells you which
model produced them and when. Treat the numbers as a demonstration of the machinery rather
than a fresh measurement of today's model — `mylonite demo --live` is the fresh measurement,
and it does call a model (by default one you host locally). Where a cell could not be
decided either way the table says so rather than showing it as a pass, and if a recording is
ever missing or out of date the command fails and explains why instead of reporting a clean
result it did not earn.

The next step also needs no key, and works against your own server too:

```bash
mylonite check reference:vulnerable   # structural report, no model call
```

Then, with a model configured, the real thing:

```bash
mylonite scan reference:vulnerable   # finds the weaknesses built into it
mylonite scan reference:guarded      # same attacks, comes up clean
```

See [the practice app](./docs/quarry.md) for what is built into it and why.

### Then point it at your own app

**The first two steps are free** — no API key, no model call, no spend.

```bash
# 1. Inspect a server and write a starter target.yaml
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml --scope my-app

# 2. Structural pre-check of that tool surface
mylonite check --target-file app.yaml
```

`--scaffold` connects to your server, lists its tools, says which weakness classes apply to
it, and flags the tools whose actions have real consequences. It works from the names,
descriptions and schemas your server advertises, matching them against keyword patterns, so
treat everything it suggests as a hint to confirm rather than a verdict.

`check` reports structural exposure: consequential tools with no approval step, descriptions
that steer the agent, tools that take a network destination, content-processing tools that
could be injection routes, and descriptions that are not pinned. `--enforce` turns it into a
CI gate — it fails on the substantive findings and treats "unpinned descriptions" (which
fires on every tool of every server the first time) as advice rather than a gate, so you can
adopt it on day one.

Proving which weaknesses actually *land*, and which of your safeguards stops them, is the
scan itself. That needs a model:

```bash
mylonite scan --target-file app.yaml --authorize my-app
```

Expect this to find less than the practice app did — often nothing. See
[Finding nothing is also a result](#finding-nothing-is-also-a-result) above, and
[docs/limitations.md](./docs/limitations.md) for where the tool's reach genuinely ends.

## From a scan to a pull request that gates CI

`mylonite gate` runs the whole sequence — find a weakness, write a test for it, confirm the
test is meaningful, and optionally open a pull request that makes CI depend on it:

```bash
mylonite gate reference:vulnerable                                   # find -> test -> confirm
mylonite gate --target-file app.yaml --authorize my-app --open-pr    # ...and open the PR
```

**`gate` does not touch your repository unless you ask it to.** By default it writes its
files under `.mylonite/gate/` — the test, the weakness record, the confirmation report — and
prints the exact `git` and `gh` commands so you can commit and open the PR yourself. Add
`--open-pr` to have it create the branch, commit and open the PR; add `--workflows` to also
write two CI templates (a cheap per-PR gate and a nightly discovery run).

The pull request carries the finding, its OWASP/ASI/ATLAS/NIST tags, the supporting
evidence, and a recommended fix that names the actual tool and argument the attack used.
Full guide: [docs/ci-gating.md](./docs/ci-gating.md). Behind a corporate network, see
[docs/enterprise-networking.md](./docs/enterprise-networking.md).

## Commands

| Command | What it does | Needs a model? |
|---|---|---|
| `mylonite demo` | Replays the unguarded-vs-guarded comparison on the bundled practice app, offline. | No (`--live` does) |
| `mylonite check` | Structural pre-check of a tool surface. Takes `reference:vulnerable` or `--target-file`. `--enforce` makes it a CI gate. | No |
| `mylonite scan` | The weakness-finding loop. `--scaffold` inspects a server and writes a starter `target.yaml`. | Yes (except `--scaffold`) |
| `mylonite generate` | Writes the `pytest` test from a confirmed weakness. | No |
| `mylonite validate` | Confirms a test is meaningful by running the comparison. `--fast` makes it cheaper. | Yes |
| `mylonite gate` | End to end: scan → generate → validate → optionally open a gating PR. | Yes |
| `mylonite ablate` | Scores each safeguard as load-bearing, redundant, security theatre, untested, or inconclusive. Needs a target file. | Yes |
| `mylonite report` | Terminal summary, **SARIF 2.1.0**, or a JSON bundle — each carrying the supporting evidence and compliance tags. | No |
| `mylonite plugins` | Lists installed plugins across all five extension points. | No |
| `mylonite version` | Prints the installed version. | No |

`--fast` trades thoroughness for cost, and what it skips depends on the target: against
your own app it skips the safeguard comparison itself, leaving a weaker check; against the
bundled practice app the comparison is not optional, so it reduces the robustness checks
instead.

Exit codes are a documented contract (`0` success · `1` findings · `2` configuration ·
`3` budget · `4` provider · `5` not confirmed · `6` generate failed · `7` validate failed ·
`8` PR step failed). Full details in the [CLI reference](./docs/cli-reference.md).

Remote MCP transport (SSE / streamable-HTTP), the versioned extension points, and
entry-point plugins are covered in the [architecture guide](./docs/architecture.md).

## Compliance metadata

Every test and every finding carries tags from four frameworks: **OWASP LLM Top 10 2025**,
**OWASP ASI 2026**, **MITRE ATLAS**, and **NIST AI RMF**. They ride into the pytest markers,
the SARIF output and the JSON bundle, so a finding traces back to the control catalogue your
auditors already use. See [docs/standards-mapping.md](./docs/standards-mapping.md).

## Documentation

**Full docs site:** [abidemialade.github.io/mylonite](https://abidemialade.github.io/mylonite/)
(or `mkdocs serve` from a checkout). Highlights:

- [Quickstart](./docs/quickstart.md) · [Test your own app](./docs/test-your-app.md) — install and point it at your MCP server.
- [Weakness classes](./docs/weakness-classes.md) · [Attack modes](./docs/attack-modes.md) — what is tested, and how the attacks work.
- [The validation engine](./docs/validation.md) — how the safeguard comparison works.
- [Independent verification](./docs/verification.md) — the full scorecard against material Mylonite did not write.
- [Known limitations](./docs/limitations.md) — where the tool's reach ends, in one place.
- [Reading the results](./docs/reading-results.md) · [CLI reference](./docs/cli-reference.md) · [target.yaml](./docs/target-file.md).
- [CI gating](./docs/ci-gating.md) · [Re-validate on a new model](./docs/model-upgrade.md) — keep the gate proving your safeguard as models change.
- [Architecture](./docs/architecture.md) · [Plugin authoring](./docs/plugin-authoring.md) · [Threat model](./docs/threat-model.md).
- [ROADMAP.md](./ROADMAP.md) · [CONTRIBUTING.md](./CONTRIBUTING.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [SECURITY.md](./SECURITY.md).

## Responsible use

Mylonite reproduces working attacks against AI agents. **Use it only against targets you
control or are contractually authorised to test.** Every command that drives a real target —
`scan`, `gate`, `validate` and `ablate` — refuses to run without an explicit `--authorize`
flag naming that target: the value must match the target's declared `scope`, or its family
name where no scope is declared. The bundled insecure practice app runs in-process and opens
no network ports.

Full policy: [SECURITY.md](./SECURITY.md).

## Contributing

Bug reports, adapter requests and attack-pattern submissions are welcome — see
[CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, how to write a plugin, and the
pull-request conventions. The five extension points (attack modules, test generators,
validators, target adapters, compliance mappers) are versioned public API with reference
implementations in this repository.

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
