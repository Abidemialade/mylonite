# Mylonite roadmap

Mylonite is an open-source framework for **AI-layer security testing**. It
ingests an application's AI/agentic layer — the system prompt, tool/function
schemas, RAG pipeline, agent planning loop — autonomously finds an
app-specific weakness, and emits a **validated regression test** that gates
CI. It deliberately does *not* test the surrounding traditional code; that
work belongs to SAST/DAST tools.

This document covers what we are building, in what order, and why. For the
pitch and the install instructions, see [README.md](./README.md). For
contribution mechanics, see [CONTRIBUTING.md](./CONTRIBUTING.md).

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
destroys the validation moat.

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
4. **Test-generation layer.** Emits a self-contained `pytest` file (jest
   later) that reproduces the exploit as an assertion.
5. **Validation engine — the moat.** See [§ Validation engine](#validation-engine)
   below.
6. **CI integration.** A GitHub Action that runs the committed suite on
   PRs, posts pass/fail, and gates merges on thresholds (e.g.,
   attack-success-rate must stay at 0).
7. **Plugin / extensibility architecture.** Entry-point-based plugins for
   five contract types: attack/probe modules, test generators,
   validators/scorers, target adapters, and compliance mappers. Stable
   versioned `Protocol`s + JSON schemas; reference implementations in-repo.
8. **Community attack-pattern registry.** A versioned, contributable
   repository of attack patterns (schema-validated), each tagged with
   OWASP / ASI / ATLAS IDs.

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
engine proves that, in four layers:

1. **Build → reliably pass → coverage / improvement.** The well-tested
   filter sequence from Meta's TestGen-LLM work, with a **5-run flakiness
   filter** to absorb LLM stochasticity.
2. **Differential seeded-vulnerability oracle (the novel extension).** Ship
   a deliberately *unguarded* variant of the reference target alongside the
   *guarded* one. A generated test is meaningful iff it **FAILS on the
   unguarded variant AND PASSES on the guarded one**, across repeated runs.
   The fail-on-vulnerable side is the security analog of "killing a mutant"
   in mutation testing.
3. **Metamorphic robustness.** Auto-generate semantically-neutral
   perturbations of the exploit (paraphrase, encoding, casing, language).
   A robust guard resists all variants; a violation reveals a brittle,
   over-fit test.
4. **Optional security mutation score.** Maintain a bank of distinct seeded
   weaknesses and report the fraction a generated test correctly fails on
   — a quantitative quality signal per emitted test.
5. **Control-efficacy oracle (the extension that generalises the moat).** On a
   real target with no second build, hold the model constant and vary only the
   safeguard: synthesize a *guarded twin* by applying a canonical control (W1–W4)
   at the adapter boundary, and keep a finding only when the attack fires on the
   raw target and is resisted with the control applied — proving the *control*
   carries the security. The plant and effect probe bypass the boundary shim so
   the attack stays undiluted; the result is reported as a boundary proxy with an
   explicit fidelity caveat and a server-side fix. `validate --prove-control`
   proves one control load-bearing (with `--adaptive`, whether it survives an
   adaptive attacker); `mylonite ablate` scores the whole control set as
   load-bearing / theater / redundant.

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

## Phases

### Phase 0 — Foundations, OSS scaffolding, and threat-model grounding

**Status:** shipped in v0.1.0.

Deliverables:

- Apache-2.0 `LICENSE` + `NOTICE`; full contributor scaffolding
  (`CONTRIBUTING`, `CODE_OF_CONDUCT`, `GOVERNANCE`, `SECURITY` with
  responsible-disclosure and dual-use policies); `CHANGELOG`; semantic
  versioning from v0.1.0; `.github/` templates + `CODEOWNERS`; the
  project's own CI (ruff / mypy / pytest matrix) and pre-commit hooks.
- Typed config schema (Pydantic Settings, required LLM provider — no
  default).
- Five versioned extension-point contracts (Protocols + ABCs + JSON
  schemas) with `CONTRACT_VERSION` checks in the plugin registry. One
  reference implementation per contract.
- Threat-taxonomy module encoding OWASP LLM Top 10 2025, OWASP ASI 2026
  (ASI01–ASI10), relevant MITRE ATLAS techniques, and NIST AI RMF
  function tags.
- Deliberately-vulnerable reference MCP agent (`mcp_kitchen_sink`) with a
  guarded twin and a seeded-weakness catalogue.
- `mkdocs-material` docs scaffold.

### Phase 1 — Ingestion + exploit-finding on one target

**Status:** shipped in v0.2.0 (W1+W2) → v0.2.1 (W3+W4) →
**v0.2.2 (in-process AND stdio MCP transport)**.

Implements both an in-process target adapter against the bundled
reference MCP agent (`reference:vulnerable` / `reference:guarded`)
**and** an MCP stdio transport adapter against three bundled real
open-source MCP servers (filesystem, fetch, github). The exploit-finding
agent covers W1 (tool-description instruction smuggling), W2 (indirect
injection via tool result / note body / file body / issue body), W3
(unrestricted egress / SSRF), and W4 (unconfirmed sensitive actions).
Deterministic predicates first with an LLM-judge fallback. Async-first
via `asyncio.gather` + `Semaphore`. Fresh subprocess per `invoke()`
isolates per-attempt state.

*Expected outcome (delivered):* the tool reliably finds ≥1 W1-W4
exploit on `reference:vulnerable` and zero on `reference:guarded`, AND
≥1 app-specific exploit on each of the three bundled real OSS MCP
agents (`mcp:filesystem:<sandbox>`, `mcp:fetch`, `mcp:github:<owner/repo>`)
where the finding names a target-specific tool with attacker-controlled
arguments and execution evidence.

**Deferred to v0.3+:** MCP Streamable HTTP transport; more OSS targets
(brave-search, puppeteer, postgres, slack); `.mylonite/targets.yaml`
pre-registered targets config; multi-target scan in one command.

### Phase 2 — Test generation + the validation engine

**Status:** shipped in v0.4.0 (core engine) → v0.5.0 (multi-provider +
custom MCP targets + effect-aware findings + custom-target validation +
runnable emitted tests).

Emit `pytest` reproductions; implement the validation pipeline (build
→ differential seeded-vulnerability oracle → 5-run flakiness filter →
metamorphic variants). v0.5.0 extended the validator to cover custom
MCP targets (no in-repo twin) via stability + effect probe + adversarial
multi-judge consensus, and added first-class custom-target support across
`scan`, `generate`, `validate`, and `init-target`.

*Delivered:* generated tests that are *proven* meaningful — each fails on
the unguarded agent and passes on the guarded one across repeated runs;
a measurable "kept-test" survival ratio; emitted tests runnable out of
the box against the bundled or real target.

### Phase 3 — CI gating + the magic moment, end-to-end

**Status:** shipped in v0.6.0.

Delivers the `scan → generate → validate → open gating PR` end-to-end
flow in a single command, plus the GitHub Action and CI workflow templates
that keep the gate running forever:

- **`mylonite gate`** — the one-command magic moment. Runs scan →
  generate → validate, writes the regression test and two CI workflow
  templates under `.mylonite/gate/`, then prints (or with `--open-pr`
  opens via `gh`) a gating PR carrying the finding, its OWASP/ASI/ATLAS/NIST
  compliance tags, the validation evidence, and a deterministic suggested-fix
  PR body. Optional `--llm-enrich` appends a labelled (unverified) LLM fix
  suggestion.
- **`mylonite.gate` package** — deterministic PR-body renderer; per-weakness-class
  remediation snippets; opt-in labelled LLM enrichment cleanly separated from
  the deterministic path.
- **Two scaffolded CI workflow templates** (per-PR gate + nightly discovery)
  encoding the cost-tier split: the cheap per-PR job replays the committed
  offline fixture in seconds; the nightly job re-runs the full live scan to
  catch regressions and discover new weaknesses. `--runs-on` lets operators
  target a self-hosted runner for in-perimeter MCP backends.
- **Reusable composite Action** (`Abidemialade/mylonite/gate-action@v1`) so
  any repo can add the gate in three lines of workflow YAML.
- **Enterprise / air-gapped support** documented in
  `docs/enterprise-networking.md` (OS trust-store, `SSL_CERT_FILE`,
  self-hosted runners, offline fixture replay without egress).
- **`pip install mylonite`** on PyPI lands with this release.

*Expected outcome:* a one-command demo a stranger can run on their own
agent and get a committed, gating regression test, with the CI gate
running on every subsequent PR.

### Phase 4 — Launch and community

Public launch, attack-pattern registry, positioning content.

*Expected outcome:* initial GitHub traction, first external contributors,
first registry contributions.

### Phase 5 — Platform expansion

Add target adapters (RAG, custom HTTP agents), a `jest` generator, more
attack classes (memory/context poisoning ASI06, inter-agent ASI07,
cascading ASI08), additional compliance mappers, and the self-improving
registry contribution loop.

*Expected outcome:* coverage across the full ASI Top 10 and a
multi-language test-output story.

### Phase 6 — Open-core monetisation (demand-gated)

Hosted CI, dashboards, and compliance/audit evidence packs mapped to the
four frameworks.

## Open-source engineering standards

This is a public, community-owned project; it is built to open-source
norms from the first commit, not retrofitted later. Concretely:

- **License & governance** — Apache-2.0, Contributor Covenant 2.1,
  documented governance and registry-contribution flow.
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
flow through normal PRs.

Strategy for the project lives with the maintainer; the technical
roadmap lives here. Issues tagged `roadmap` track delivery against the
phases above.
