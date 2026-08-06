# Mylonite

> **Model robustness is not the same as application security.** A frontier model can
> resist every generic prompt-injection you throw at it and still hand an attacker a win,
> because the hole is in *your app's design*, not the model's alignment. Mylonite tests
> whether your **app-layer controls** are what stop the attack, writes a **validated
> regression test** for each weakness it finds, and gates CI so a model upgrade can't
> silently strip the protection away.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Built for teams shipping MCP or agentic apps who need CI-enforced regression coverage on
the AI layer.**

Point Mylonite at any MCP (Model Context Protocol) app, whatever model or framework is
behind it. It attacks the AI/agentic layer — the system prompt and tool/function schemas —
finds app-specific weaknesses, and for each one emits a
**validated, CI-gating `pytest` regression test**.

The core differentiator is the **control-efficacy check**. It holds the model constant and
toggles only the safeguard, keeping a finding only when the attack *fires* on your app and
is *resisted* once the control is applied, across a repeat-run filter that absorbs LLM
randomness. That proves the *control* carries the security, not the model's current good
behavior, and it works on a single real app with no second build required. Every headline
claim is backed by an independent [verification harness](./docs/verification.md) that scores
Mylonite against external ground truth it did not author.

Mylonite deliberately does *not* test the surrounding traditional code; that work belongs to
SAST/DAST tools.

**Where this sits.** Static scanners read your tool descriptions and flag the ones that look
dangerous; you are left to judge which flags matter. Model-eval harnesses swap models and
score which one behaves best. Mylonite does neither. It runs the attack against your app,
then holds the model constant and toggles only your safeguard — so the finding you get back
is evidence about *your control*, not about how a description reads or how a model scored
today.

**Example: same model, two versions of one app.** Run the *same* model against the two
versions of the bundled reference app. Against the deliberately-vulnerable version Mylonite
catches a `send_email` dispatched with **no approval step** — a pure app-design flaw no
amount of model alignment fixes. Against the guarded version it finds nothing. Same model;
the app's design decides the outcome. That is the difference between "your chatbot behaved
today" and "your app is secure." See the full [independent scorecard](./docs/verification.md),
negatives included.

See [ROADMAP.md](./ROADMAP.md) for the architecture, scope, and direction, and the
[documentation site](https://abidemialade.github.io/mylonite/) for guides and reference.

> **Status:** the full `scan → generate → validate → gate` pipeline works end to end,
> against your own MCP app over stdio or remote SSE/HTTP (`--target-file`) and the bundled
> reference app. The control-efficacy check proves which safeguard is load-bearing on any
> single-build app; `mylonite ablate` scores the whole control set (load-bearing vs.
> security theater). A third-party [verification harness](./docs/verification.md) checks every
> claim against external ground truth. `pip install mylonite` installs the CLI from PyPI;
> the offline demo target is an opt-in extra — `pip install "mylonite[demo]"`. See
> [CHANGELOG.md](./CHANGELOG.md).

## Try it in 60 seconds

*(Once installed.)* `mylonite demo` runs the real scan offline against a deliberately
vulnerable agent and its guarded version — no API key, deterministic. Sample output is
[below](#demo-output).

**Install the CLI and run the demo** — `mylonite` is on PyPI. The base install is just the
tool that scans your app; the offline demo target is an opt-in extra (a
deliberately-vulnerable mock agent, never pulled by a plain install). Requires **Python
3.11–3.13** — `litellm` (the model-agnostic LLM layer) has no 3.14 wheels yet, so create
your virtualenv with a 3.11–3.13 interpreter. The CLI prints a clear note if it detects
3.14+.

```bash
pip install "mylonite[demo]"   # the [demo] extra adds the offline reference target
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

**No API key needed** — the demo replays recorded model behavior; add `--live` to re-run
for real.

<a id="demo-output"></a>
The demo runs the real scan twice — once against the deliberately vulnerable reference
agent and once against its guarded version — and prints a safety banner, a weakness table,
and the headline differential (an example run; which patterns land depends on the planner
model):

```text
  DEMO ONLY — the reference app is a deliberately vulnerable in-process agent.

  tool-description-instruction-smuggling   LLM01 / ASI02 / AML.T0051     ✓
  indirect-injection-via-note-body         LLM01, LLM05 / ASI01, ASI06   ✓
  unrestricted-web-fetch                   LLM06 / ASI02, ASI05          ✗
  unconfirmed-email-send                   LLM06 / ASI02                 ✗

  reference app: 2 exploits on vulnerable, 0 on guarded
  mode: replay (offline)
```

That **vulnerable-vs-guarded differential is what validates every generated regression
test.** Whatever fires on the vulnerable version is resisted on the guarded one; a robust
model resists some patterns outright, which is why the exact count varies by model. The
reference app runs entirely in-process and never binds to a network. Full walkthrough:
[docs/quarry.md](./docs/quarry.md).

Once you've seen it, point `scan` at your own MCP app. **The first step is free** — it needs
no API key and makes no model call:

```bash
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml --scope my-app   # free, no API key
```

That connects to your server, lists the tools it exposes, tells you which weakness classes
apply to that surface, flags the consequential-action tools worth guarding, and writes a
starter `app.yaml`. Treat it as a scope check, not a verdict: it reads your tool *surface*,
not your tool descriptions, and everything it suggests is a hint for you to confirm.

Proving which weaknesses actually land — and which of your controls stops them — is the
scan itself, and that needs a key:

```bash
mylonite scan --target-file app.yaml --authorize my-app                    # needs an LLM API key
```

## From scan to a gating PR

`mylonite gate` runs the whole pipeline — find an exploit, write a regression test,
validate it against the control-efficacy check, and (opt-in) open a PR that gates CI on it:

```bash
mylonite gate reference:vulnerable          # find -> test -> validate -> print the PR command
mylonite gate --target-file app.yaml --authorize my-app --open-pr   # ...and open it
```

`gate` writes a validated regression test under `.mylonite/gate/` plus two CI workflows (a
cheap per-PR gate + nightly discovery), then prints (or, with `--open-pr`, opens) a PR
carrying the finding, its OWASP/ASI/ATLAS/NIST tags, the validation evidence, and a
human-applied suggested fix. Full guide: [docs/ci-gating.md](./docs/ci-gating.md). Behind a
corporate network, see [docs/enterprise-networking.md](./docs/enterprise-networking.md).

## What works today

Every command has a backing [verification](./docs/verification.md) number or a committed
differential proof. The core surface:

- **`mylonite gate <target>`** — the end-to-end flow: scan → generate → validate →
  optionally open a gating PR. Writes the regression test and two CI workflow templates.
- **`mylonite scan <target>`** — the exploit-finding loop against the bundled reference app
  or your own MCP app (`--target-file`). `--scaffold` introspects a server and writes a
  starter `target.yaml`.
- **`mylonite generate <dir>`** — emits the `pytest` regression test from a confirmed
  exploit (run for you as a stage of `gate`).
- **`mylonite validate <dir>`** — proves an emitted test is meaningful via the
  control-efficacy check (the core differentiator); `--fast` skips it for a weaker gate.
- **`mylonite ablate <target>`** — scores each safeguard as load-bearing vs. security theater.
- **`mylonite report <dir>`** — a terminal trust panel, **SARIF 2.1.0**, or a JSON bundle,
  all carrying the differential proof and the compliance tags.
- **`mylonite init`** — guided setup that writes a runnable `target.yaml` for your app
  (HTTP agent or MCP server).
- **`mylonite demo` / `doctor` / `taxonomy list`** — offline demo, provider diagnostics,
  and the bundled OWASP/ASI/ATLAS/NIST threat taxonomy.

Full command details in the [CLI reference](./docs/cli-reference.md). Remote MCP transport
(SSE / streamable-HTTP), versioned extension contracts, and entry-point plugins are covered
in the [architecture guide](./docs/architecture.md).

## Documentation

**Full docs site:** [abidemialade.github.io/mylonite](https://abidemialade.github.io/mylonite/)
(or `mkdocs serve` from a checkout). Highlights:

- [Quickstart](./docs/quickstart.md) · [Test your own app](./docs/test-your-app.md) — install and point it at your MCP server.
- [Weakness classes](./docs/weakness-classes.md) · [Attack modes](./docs/attack-modes.md) — what's tested and how attacks work.
- [The validation engine](./docs/validation.md) — the control-efficacy check and the differential.
- [Independent verification](./docs/verification.md) — the honest scorecard against ground truth Mylonite didn't author.
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

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
