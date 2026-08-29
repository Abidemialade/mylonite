# Mylonite

> **Model robustness is not the same as application security.** A frontier model can
> resist every generic prompt-injection you throw at it and still hand an attacker a win,
> because the hole is in *your app's design*, not the model's alignment. Mylonite tests
> whether your **app-layer controls** are what stop the attack, writes a **validated
> regression test** for each weakness it finds, and gates CI so a model upgrade can't
> silently strip the protection away.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mylonite.svg)](https://pypi.org/project/mylonite/)
[![GitHub release](https://img.shields.io/github/v/release/Abidemialade/mylonite)](https://github.com/Abidemialade/mylonite/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Built for teams shipping MCP or agentic apps who need CI-enforced regression coverage on
the AI layer.**

Point Mylonite at any MCP (Model Context Protocol) app, whatever model or framework is
behind it. It attacks the AI/agentic layer — the system prompt and tool/function schemas —
finds app-specific weaknesses, and for each one emits a
**validated, CI-gating `pytest` regression test**.

Mylonite deliberately does *not* test the surrounding traditional code; that work belongs to
SAST/DAST tools.

## The core idea

The differentiator is the **control-efficacy check**: hold the model constant, toggle only
the safeguard, and keep a finding only when the attack *fires* on your app and is *resisted*
once the control is applied — across a repeat-run filter that absorbs LLM randomness.

That answers a question a point-in-time scan cannot: **is your control carrying the
security, or is the model's current good behaviour carrying it?** Only one of those survives
a model upgrade.

Two fidelities, and Mylonite always tells you which one you got:

| Guarded side | What a KEPT verdict proves | How to get it |
|---|---|---|
| **Your own control**, toggled | Your implementation is load-bearing. The strongest result. | Declare `control_env` in your `target.yaml` |
| **A canonical control** applied at the adapter boundary | The attack is real and this class of control closes it — but the guarded side was Mylonite's shim, not your code | The default; works on any single-build app |

The second is genuinely useful and it is what runs on most real targets. It is not the same
claim as the first, and Mylonite will not print the stronger wording for it.

## What's proven, what isn't

Mylonite maintains an [independent verification harness](./docs/verification.md) that scores
it against ground truth it did not author — runnable third-party MCP servers and published
academic benchmarks. The harness is in this repo and you can re-run it yourself.

Here is the honest split. Read the third bucket before the first.

### Proven, against targets we did not write

- **A KEPT external differential** on a third-party MCP email server: the attack fired
  **5/5** on the raw target, the guarded build leaked **0/5**, success-rate gap **1.00**.
- **Zero false positives** on a benign third-party server — the external precision baseline.
- **An external detection catch** on a peer-reviewed vulnerable MCP corpus.
- **The judge's positive class verified on real third-party positives** (AgentDojo
  trajectories from models that genuinely fell for attacks — not synthesised by us).
- **Honesty rails hold under test:** NOT-TESTED is never rendered as clean, vacuous
  agreement is flagged as vacuous, out-of-scope work is marked rather than scored.

### Measured, and negative

Published for the same reason the wins are.

- **0/8 recall** on one external challenge set (DVMCP, with Claude Haiku 4.5).
- **0/60** on another, flagged as vacuous — a model that resists every case leaves the
  judge no positives to classify, so the resulting F1 would have meant nothing.
- **LLM-judge agreement F1 of 0.41** against AgentDojo's oracle. The judge measures
  *effect* ("did harm materialise?"); AgentDojo measures *exact goal achievement*. Some
  of that gap is a real semantic mismatch we have not resolved.
- **No model-fooling catch on an external app.** Every generic injection was resisted by a
  robust model. The one thing that landed was an *app-design* flaw.

### Not claimed

- **On a single-build app, the strong claim is unavailable.** Without a `control_env` to
  toggle, the guarded side is Mylonite's own shim, not your code. That is a boundary proxy,
  and no surface will print the stronger wording for it.
- **A clean result is the common result.** Against a well-designed app and a robust model,
  the correct answer is usually "nothing". See [below](#a-clean-result-is-a-result).
- **The evidence base is essentially one model** — Claude Haiku 4.5 — at small,
  cost-bounded sample sizes.
- **The published figures date from June 2026 and are not version-stamped.** They have not
  been re-measured across the releases since, so treat them as a floor on current
  behaviour rather than a current reading. Per-release re-measurement is planned.
- **Run transcripts are not committed.** The harness and its scorers are public and
  re-runnable, so you can produce your own numbers; you cannot yet audit ours.
- **No third party has built a plugin** against the extension contracts yet.

Full scorecard with caveats: [docs/verification.md](./docs/verification.md). Everything
that limits the tool's reach is collected in [docs/limitations.md](./docs/limitations.md).

## A clean result is a result

Worth setting expectations before you run it. Against a well-designed app and a robust
model, Mylonite will often correctly find **nothing** — and that is the tool working, not
failing. A KEPT control-efficacy proof needs a weakness that actually lands, which in
practice means an app-design flaw (a consequential action with no approval step, an
unrestricted egress path) or an app configured to act autonomously.

This is why [Try it](#try-it) starts with the bundled reference app rather than your code:
it is deliberately vulnerable and finds weaknesses every time, so you can see the machinery
work before you point it somewhere the honest answer may be "nothing".

## Where this sits

Static scanners read your tool descriptions and flag the ones that look dangerous; you are
left to judge which flags matter. Model-eval harnesses swap models and score which one
behaves best. Mylonite does neither. It runs the attack against your app, then holds the
model constant and toggles only your safeguard — so the finding you get back is evidence
about *your control*, not about how a description reads or how a model scored today.

## Project status

**Beta, single maintainer.** As of v0.8.5 that is 241 commits from one contributor, with a
1,900-test suite and CI (ruff, mypy, pytest, pre-commit) enforced on every PR. The extension
contracts are versioned public API, but no third party has built a plugin against them yet.
If you are weighing this as a dependency in a security pipeline, pin a version — and read
[Known limitations](./docs/limitations.md) first.

## Install

```bash
pip install mylonite            # the CLI, from PyPI
pip install "mylonite[demo]"    # ...plus the bundled reference app, for `mylonite demo`
```

Python 3.11–3.13. (3.14 is not yet supported: `litellm` has no wheels for it.) Scanning
needs an LLM API key; `demo`, `check`, `--scaffold` and `report` do not.

## Try it

**No API key, one command:**

```bash
mylonite demo
```

That runs the differential against the bundled reference app — deliberately vulnerable,
in-process, binds to nothing — and prints weaknesses on the unguarded build and a clean
result on the guarded one. Same attacks, two builds, opposite results. **That contrast *is*
the product.**

`demo` replays LLM responses recorded against those bundled targets, so it is offline and
deterministic. The scan, the adapters, the predicates and the differential are the real
ones; only the model replies are canned, and the output tells you which model and date they
came from. Treat the numbers as a demonstration of the machinery, not as a fresh
measurement of today's model — `mylonite demo --live` is the fresh measurement. If a
fixture is ever missing or stale the command fails and says so rather than showing you a
clean result it did not earn.

The second free step needs no key either, and works against your own server too:

```bash
mylonite check reference:vulnerable   # static structural report, no LLM call
```

Then, with a key, the real thing:

```bash
mylonite scan reference:vulnerable   # finds seeded weaknesses
mylonite scan reference:guarded      # same attacks, comes up clean
```

See [the reference app](./docs/quarry.md) for what is seeded in it and why.

### Then point it at your own app

**The first two steps are free** — no API key, no model call, no spend.

```bash
# 1. Introspect a server and write a starter target.yaml
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml --scope my-app

# 2. Static structural pre-check of that tool surface
mylonite check --target-file app.yaml
```

`--scaffold` connects to your server, lists its tools, tells you which weakness classes
apply to that surface, and flags the consequential-action tools worth guarding. Treat it as
a scope check, not a verdict: it reads your tool *surface*, not your tool descriptions, and
everything it suggests is a hint for you to confirm.

`check` reports structural exposure — consequential tools with no approval step,
descriptions that steer the agent, tools taking a network destination, unpinned
descriptions. `--enforce` turns it into a CI gate: it exits non-zero on the substantive
W1–W4 structural findings and treats the "unpinned descriptions" advisory (which fires on
every tool of every server on first contact) as a suggestion, not a gate — so it is
adoptable on day one.

Proving which weaknesses actually *land*, and which of your controls stops them, is the scan
itself. That needs a key:

```bash
mylonite scan --target-file app.yaml --authorize my-app
```

Expect this to find less than the reference app did — often nothing. See
[A clean result is a result](#a-clean-result-is-a-result) above, and
[docs/limitations.md](./docs/limitations.md) for where the tool's reach genuinely ends.

## From scan to a gating PR

`mylonite gate` runs the whole pipeline — find an exploit, write a regression test, validate
it against the control-efficacy check, and optionally open a PR that gates CI on it:

```bash
mylonite gate reference:vulnerable                                   # find -> test -> validate
mylonite gate --target-file app.yaml --authorize my-app --open-pr    # ...and open the PR
```

**`gate` does not touch your repository unless you ask it to.** By default it writes its
artefacts under `.mylonite/gate/` — the regression test, the exploit JSON, the validation
report — and prints the exact `git` and `gh` commands to commit and open the PR yourself.
Add `--open-pr` to have it create the branch, commit, and open the PR; add `--workflows` to
scaffold the two CI templates (a cheap per-PR gate and a nightly discovery run).

The PR carries the finding, its OWASP/ASI/ATLAS/NIST tags, the validation evidence, and an
evidence-anchored recommended fix naming the actual tool and argument that landed the
exploit. Full guide: [docs/ci-gating.md](./docs/ci-gating.md). Behind a corporate network,
see [docs/enterprise-networking.md](./docs/enterprise-networking.md).

## Commands

| Command | What it does | Needs a key? |
|---|---|---|
| `mylonite demo` | Offline replay of the vulnerable-vs-guarded differential on the bundled reference app. `--live` re-runs it for real. | No |
| `mylonite check` | Static structural pre-check of a tool surface. Takes `reference:vulnerable` or `--target-file`. `--enforce` makes it a CI gate. | No |
| `mylonite scan` | The exploit-finding loop. `--scaffold` introspects a server and writes a starter `target.yaml`. | Yes (except `--scaffold`) |
| `mylonite generate` | Emits the `pytest` regression test from a confirmed exploit. | No |
| `mylonite validate` | Proves an emitted test is meaningful via the control-efficacy check. `--fast` skips it for a weaker gate. | Yes |
| `mylonite gate` | The end-to-end flow: scan → generate → validate → optionally open a gating PR. | Yes |
| `mylonite ablate` | Scores each safeguard as load-bearing, redundant, or security theater. Needs a target file. | Yes |
| `mylonite report` | Terminal trust panel, **SARIF 2.1.0**, or a JSON bundle — all carrying the differential proof and compliance tags. | No |
| `mylonite plugins` | Lists installed extension plugins across all five contract groups. | No |
| `mylonite version` | Prints the installed version. | No |

Exit codes are a documented contract (`0` success · `1` findings · `2` config · `3` budget ·
`4` provider · `5` not kept · `6` generate failed · `7` validate failed · `8` gate PR step
failed). Full details in the [CLI reference](./docs/cli-reference.md).

Remote MCP transport (SSE / streamable-HTTP), versioned extension contracts, and
entry-point plugins are covered in the [architecture guide](./docs/architecture.md).

## Compliance metadata

Every emitted test and every finding carries tags from four frameworks: **OWASP LLM Top 10
2025**, **OWASP ASI 2026**, **MITRE ATLAS**, and **NIST AI RMF**. They ride into the pytest
markers, the SARIF output and the JSON bundle, so a finding is traceable to the control
catalogue your auditors already use. See [docs/standards-mapping.md](./docs/standards-mapping.md).

## Documentation

**Full docs site:** [abidemialade.github.io/mylonite](https://abidemialade.github.io/mylonite/)
(or `mkdocs serve` from a checkout). Highlights:

- [Quickstart](./docs/quickstart.md) · [Test your own app](./docs/test-your-app.md) — install and point it at your MCP server.
- [Weakness classes](./docs/weakness-classes.md) · [Attack modes](./docs/attack-modes.md) — what's tested and how attacks work.
- [The validation engine](./docs/validation.md) — the control-efficacy check and the differential.
- [Independent verification](./docs/verification.md) — the honest scorecard against ground truth Mylonite didn't author.
- [Known limitations](./docs/limitations.md) — where the tool's reach ends, in one place.
- [Reading the results](./docs/reading-results.md) · [CLI reference](./docs/cli-reference.md) · [target.yaml](./docs/target-file.md).
- [CI gating](./docs/ci-gating.md) · [Architecture](./docs/architecture.md) · [Plugin authoring](./docs/plugin-authoring.md).
- [ROADMAP.md](./ROADMAP.md) · [CONTRIBUTING.md](./CONTRIBUTING.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [SECURITY.md](./SECURITY.md).

## Responsible use

Mylonite reproduces working weaknesses in AI agents. **Use it only against targets you
control or are contractually authorized to test.** Every command that live-drives a real
target — `scan`, `gate`, `validate`, and `ablate` — refuses to run without an explicit
`--authorize` flag naming that target: the value must equal the target's declared `scope`,
or its family name when no scope is declared. The bundled vulnerable reference agent runs
in-process and binds to nothing.

Full policy: [SECURITY.md](./SECURITY.md).

## Contributing

Bug reports, adapter requests, and attack-pattern submissions are welcome — see
[CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, how to author a plugin, and the PR
conventions. The five extension points (attack modules, test generators, validators, target
adapters, compliance mappers) are versioned public API with reference implementations
in-repo.

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
