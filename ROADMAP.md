# Mylonite roadmap

Mylonite is an open-source framework for **AI-layer security testing**. It
ingests an application's AI/agentic layer — the system prompt, tool/function
schemas, RAG pipeline, agent planning loop — autonomously probes for
app-specific weaknesses, and emits a **validated regression test** for each
one it finds, gating CI. It deliberately does *not* test the surrounding
traditional code; that work belongs to SAST/DAST tools.

This document covers what Mylonite does, how it's built, and where it's going.
For an overview and install instructions, see [README.md](./README.md); for
contribution mechanics, see [CONTRIBUTING.md](./CONTRIBUTING.md); for guides and
reference, see the [documentation site](https://abidemialade.github.io/mylonite/).

## Scope

The unit of focus is the **AI attack surface**: system prompt, tool/function
schemas, RAG pipeline, agent planning and memory. Nothing else.

This boundary is technical as much as strategic:

- The AI layer is the whole of an AI-native application and a slice of every
  hybrid SaaS that bolted on a chatbot or agent, so a single tool serves
  both shapes.
- The validation engine we depend on (see below) only has power where
  behaviour is non-deterministic — i.e., where the AI layer lives.

The tool **will not** add general application-code scanning, traditional
SAST/DAST behaviours, or non-AI test generation. Drifting off the AI layer
destroys the core differentiator.

## Architecture

Eight components organised around a single core use case:

1. **Ingestion / app-understanding layer.** Reads the target's system
   prompt, tool/function schemas (including MCP `tools/list` output and tool
   descriptions), data sources, and declared business logic. Produces a
   structured "app model."
2. **Exploit-finding agent.** An LLM-driven loop that, given the app model
   and a threat taxonomy, generates app-specific attack candidates,
   executes them against a target adapter, and uses an LLM-as-judge scorer
   (with deterministic checks layered on top) to detect success.
3. **Attack / exploit engine and probe modules.** A pluggable registry of
   attack modules; the LLM layer customises each to the specific app's
   prompt, tools, and data.
4. **Test-generation layer.** Emits a self-contained `pytest` file that
   reproduces the exploit as an assertion.
5. **Validation engine — the core differentiator.** See [§ Validation engine](#validation-engine)
   below.
6. **CI integration.** A GitHub Action that runs the committed suite on
   PRs, posts pass/fail, and gates merges on thresholds (e.g.,
   attack-success-rate must stay at 0).
7. **Plugin / extensibility architecture.** Entry-point-based plugins for
   five contract types: attack/probe modules, test generators,
   validators/scorers, target adapters, and compliance mappers. Stable
   versioned `Protocol`s + JSON schemas; reference implementations in-repo.
8. **Community attack-pattern registry (planned, not yet built).** A versioned,
   contributable repository of attack patterns (schema-validated), each tagged with
   OWASP / ASI / ATLAS IDs. See "Direction" below.

### Tech choices

Python 3.11+, Typer/Click CLI, Pydantic for typed config, LiteLLM for
model-agnostic LLM calls (no provider SDK is imported directly — there is
no default provider, so misconfigured runs fail loudly), `pytest` as the
first emitted test framework, GitHub Actions as the first CI integration.
Apache-2.0.

## Validation engine

This is the most important and most defensible piece. A "generated security
test" is only useful if it actually means something — if it would fail on a
real weakness and would pass when the weakness is fixed. The validation
engine proves that, in five layers:

1. **Build → reliably pass → coverage / improvement.** A filter sequence with
   a **flakiness filter** to absorb LLM stochasticity.
2. **Differential seeded-vulnerability oracle (the novel extension).** Ship
   a deliberately *unguarded* variant of the reference target alongside the
   *guarded* one. A generated test is meaningful iff it **FAILS on the
   unguarded variant AND PASSES on the guarded one**, across repeated runs.
   The fail-on-vulnerable side is the security analog of "killing a mutant"
   in mutation testing.
3. **Metamorphic robustness (gating).** Apply semantically-neutral
   perturbations of the exploit (paraphrase, casing, encoding, language,
   real-world evasion encodings) and re-drive each through both builds. A robust
   guard resists a majority; a violation reveals a brittle, over-fit test.
4. **Security mutation score.** Maintain a bank of distinct seeded
   weaknesses and report the fraction a generated test correctly fails on
   — a quantitative quality signal per emitted test.
5. **Control-efficacy check (the extension that generalises the core differentiator).** On a
   real target with no second build, hold the model constant and vary only the
   safeguard: synthesize a *guarded build* by applying a canonical control (W1–W4)
   at the adapter boundary, and keep a finding only when the attack fires on the
   raw target and is resisted with the control applied — proving the *control*
   carries the security. The plant and effect probe bypass the boundary shim so
   the attack stays undiluted; the result is reported as a boundary proxy with an
   explicit fidelity caveat and a server-side fix. `mylonite ablate` scores the
   whole control set as load-bearing / theater / redundant.

The deliberately-vulnerable reference target (`reference_targets/mcp_kitchen_sink/`)
exists from v0.1.0 onwards for exactly this purpose. It is intentionally
insecure; the seeded weaknesses are catalogued in
`reference_targets/mcp_kitchen_sink/seeds/seeds.yaml`.

## Standards mapping

Every generated test carries compliance metadata at generation time:

- An **OWASP LLM Top 10 (2025)** ID (e.g., LLM01 Prompt Injection, LLM06
  Excessive Agency).
- An **OWASP Agentic Security Initiative (2026)** ID (e.g., ASI01 Agent
  Goal Hijack, ASI02 Tool Misuse).
- One or more **MITRE ATLAS** technique IDs.
- A **NIST AI RMF** function / subcategory tag (predominantly MEASURE,
  since these are tests/red-team evidence; MANAGE for the gating action).

The bundled taxonomy lives under `src/mylonite/taxonomy/data/`. Each file
cites its upstream publisher in `SOURCE.md`.

## Status & direction

The end-to-end pipeline is complete and in active use: `scan → generate →
validate → gate` runs against the bundled reference agent and your own MCP app,
proves each finding with the control-efficacy check (the differential generalised to
any single-build app), and emits a committed regression test that gates CI.

**What the evidence shows: model robustness ≠ app security.** A
[third-party verification harness](https://abidemialade.github.io/mylonite/verification/)
runs Mylonite against external ground truth it did not author (DVMCP, InjecAgent,
AgentDojo). The result that reframes the product: a frontier model resisted *generic*
injection everywhere, but the *same model* was caught immediately where the **app's own
design** was the flaw — a `send_email` dispatched with no approval step. Mylonite's
demonstrable value is **app-flaw detection, differential/control-efficacy validation,
regression gating, and honesty** (NOT-TESTED is never reported as clean), not
out-fooling frontier alignment. The product surface is scoped to exactly that.

**Available today (the proven core):**

- A zero-key on-ramp: `pip install "mylonite[demo]"` then `mylonite demo` replays a
  recorded scan against the bundled reference app's vulnerable and guarded builds and
  prints the differential, with no API key and no configuration. It labels itself as a
  replay and names the model and date it was recorded against, because a canned result
  presented as a fresh measurement would undercut the thing this project is for.
- Ingestion of MCP/tool-using agents over in-process, stdio, and remote
  SSE / streamable-HTTP transports — any app that speaks MCP.
- The four weakness classes — W1 tool-description smuggling, W2 indirect injection,
  W3 excessive egress / SSRF, W4 unconfirmed consequential action — with
  deterministic predicates and an LLM-judge fallback.
- The full validation engine above, including the **control-efficacy check** and
  **control ablation** (which safeguard is load-bearing vs. security theater).
- Custom-target support via a declarative `target.yaml` (scaffolded by
  `scan --scaffold`), the one-command `mylonite gate` flow, a reusable GitHub
  Action, and CI workflow templates.
- Results in the formats teams consume — a terminal trust panel, SARIF for GitHub
  code scanning, a machine-readable JSON bundle, and a gating PR with a proven-fix
  diff — all carrying OWASP / OWASP-ASI / MITRE ATLAS / NIST compliance tags.
- The third-party verification harness itself, with a published honest scorecard
  (negatives included).

**Removed (v0.7.4), by design.** Deeper attack *tactics* — an adaptive refinement loop,
tool-chaining synthesis, stateful memory poisoning, and cross-model durability — were
cut, not just hidden. They were never the core differentiator (the control-efficacy check is), they
were beaten by frontier-aligned models on every external target, and none had a
third-party proof path. Their value was the lesson (model robustness ≠ app security),
which is banked into the positioning; the code lives in git history and returns only if
a real external need re-justifies it. Every shipped feature now runs on an MCP app we
did not author and is on a path to third-party proof.

**Direction.** Near-term work strengthens and externally *proves* the core rather than
widening it:

- **Land a real external differential** — a non-self-seeded finding that fires
  unguarded, is resisted with the control, and survives the flakiness gate, on a real
  OSS MCP app. This is the single highest-value open item.
- **Triage judge precision against independent labels.** The published
  LLM-judge agreement F1 of 0.41 is the weakest number on the scorecard and it is
  published rather than hidden; improving it needs labels the project did not author.
- **Make the extension contracts usable end to end, not just published.** They are
  versioned public API, but no third party has built against them yet. The concrete gap
  is that a contributor writing a genuinely new detector needs a new *predicate* and
  there is no supported way to ship one — a `contract-change` tracked in
  [`TODOS.md`](./TODOS.md). Until it lands, contributed detectors compose existing
  predicates.

Longer-term themes
include additional target adapters (RAG, custom HTTP agents), a second test-output
language, more attack classes across the OWASP ASI Top 10, a contributable
attack-pattern registry, and — demand permitting — hosted CI, dashboards, and
compliance/audit evidence packs. See [the changelog](./CHANGELOG.md) for what shipped in
each release.

## Open-source engineering standards

This is a public, community-owned project; it is built to open-source
norms from the first commit, not retrofitted later. Concretely:

- **License & governance** — Apache-2.0, Contributor Covenant 2.1, documented
  governance; a formal registry-contribution flow is planned (see "Direction").
- **Repo hygiene** — clear quickstart, issue/PR templates, `CODEOWNERS`,
  `CHANGELOG` following "Keep a Changelog", semantic versioning.
- **Security posture** — `SECURITY.md` with private vulnerability
  disclosure and an explicit responsible-use / dual-use policy.
- **Quality gates** — CI runs ruff, ruff format, mypy, pytest, and
  pre-commit on every PR; coverage reporting; Dependabot for updates.
- **Extensibility contracts as first-class public API** — five stable,
  versioned Protocols with JSON schemas, reference implementations, and
  entry-point-based plugin loading.
- **Responsible-use defaults** — targets default to "you must own them",
  scans require an explicit `--authorize` flag, and secret-shaped values
  are redacted before any log/report/test artifact is written.

## How decisions are made

Substantive scope changes (new attack classes, new target adapters,
contract-API changes) go through an RFC-style issue labelled
`contract-change` or `scope-change`. Routine bug fixes and improvements
flow through normal PRs. Issues tagged `roadmap` track the direction above.
