# Architecture & modules

This page is the map for reading the code: how a scan flows from a target to a kept
test, and where each piece lives. If you want to *extend* Mylonite, pair this with
[Plugin authoring](plugin-authoring.md).

## Two validation layers

Everything in Mylonite answers one of two questions:

- **Layer 1 — "did the attack land?"** (is one attempt a *finding*) → a deterministic
  **predicate**, then an **LLM judge** if inconclusive, then an **effect probe**. See
  [Weakness classes](weakness-classes.md#how-did-it-land-is-decided-layer-1).
- **Layer 2 — "is the finding worth a committed test that gates CI?"** (is it *kept*) →
  the **differential oracle**. This is the moat. See [The validation engine](validation.md).

## The flow

```
target ──> scan (Layer 1) ──> generate ──> validate (Layer 2) ──> gate ──> PR / CI
            findings           pytest file    kept?               workflows
```

## Module map

### Scanning & attacks — `mylonite.scan`
- **`engine.py`** — `ScanEngine`: the single-shot orchestrator (customise → invoke →
  judge, with the scan-time flakiness filter and the LLM-call budget).
- **`seeds.py`** / **`predicates.py`** — the bundled attack seeds (W1–W4) and the
  deterministic success predicates.
- **`judge.py`** — the Layer-1 success ladder (predicate → LLM judge → effect probe).
- **`attack_loop.py`** — `AdaptiveAttackDriver`: the [`--adaptive`](attack-modes.md#adaptive)
  strategist refinement loop and `discover_attack_plan` (auto-find plant/retrieve tools).
- **`chain_synth.py` / `chain_driver.py` / `chain_validator.py` / `synthesis_runner.py`**
  — [`--synthesize`](attack-modes.md#synthesis) tool-chaining.
- **`memory_poison.py`** — [`--memory`](attack-modes.md#memory-poisoning)
  cross-turn poisoning: `MemoryPoisoningDriver` / `MemoryPoisonValidator` / `MemoryPoisonRunner`.
- **`control_shim.py`** — the `BoundaryControl` subclasses (W1–W4) and `ControlServerShim`
  that synthesize a *boundary*-guarded twin of any target (a server-layer control needs
  `control_env`); the [control-efficacy oracle](validation.md#beyond-the-bundled-twin-the-control-efficacy-oracle).
- **`cross_model.py`** — the [cross-model durability](validation.md#cross-model-durability) summary.
- **`tool_roles.py`** — heuristics that classify a tool surface (store / retrieve / sink).
- **`artefacts.py`** — the terminal trust panel.

### The validation moat — `mylonite.plugins._reference.reference_validator`
`DifferentialValidator` implements the oracle legs: **build · differential · flakiness ·
metamorphic** (gating, incl. the evasion encodings) **· mutation score** (report-only),
plus the custom-target legs **stability · effect · consensus**. The honesty invariant
(plant + effect probe bypass the control) lives here and in `control_shim.py`.

### Targets — `mylonite.plugins._mcp` & `_reference`
- **`_mcp/stdio_adapter.py`** — `MCPStdioAdapter` (drives any stdio MCP server) + the
  bundled family adapters (filesystem/fetch/github) + the `AttackSession` (stateful,
  multi-turn) used by the adaptive/synthesis/memory drivers.
- **`_mcp/target_file.py`** — the [`target.yaml`](target-file.md) model + auto-wiring.
- **`_mcp/target_registry.py`** — the bundled family `TargetSpec`s.
- **`_reference/reference_target_adapter.py`** — the in-process **Quarry** twins
  (`reference:vulnerable` / `reference:guarded`), the ground-truth differential.

### Outputs — `mylonite.report` & `mylonite.gate`
- **`report/html.py`**, **`report/sarif.py`**, **`report/bundle.py`** — the
  [HTML / SARIF / JSON](reading-results.md) renderers.
- **`gate/orchestrator.py`** — the scan→generate→validate→PR sequence + exit codes.
- **`gate/mitigation.py`** + **`gate/fixes/`** — the PR body and the **proven-fix diff**.
- **`gate/localize.py`** + **`gate/annotate.py`** — pin a finding to its locus and post
  inline PR check-run annotations.
- **`gate/pr.py`** / **`gate/workflows.py`** — the git/`gh` PR flow and CI workflow templates.

### Compliance — `mylonite.taxonomy`
The bundled OWASP-LLM / OWASP-ASI / MITRE ATLAS / NIST data and the mapper that stamps
every finding. See [Standards mapping](standards-mapping.md).

## The five extension contracts — `mylonite.contracts`

Public API from day one (versioned `Protocol`/ABCs + JSON schemas + entry-point loading):

| Contract | Role | Reference impl |
|----------|------|----------------|
| `AttackModule` | generate payloads for a target | `PromptInjectionAttackModule`, … |
| `TargetAdapter` | speak to a target (sync/async; optional `SupportsAttackSession`) | `MCPStdioAdapter`, `InProcessReferenceAdapter` |
| `TestGenerator` | emit a regression test | `ReferencePytestGenerator` |
| `Validator` | the differential oracle | `DifferentialValidator` |
| `ComplianceMapper` | tag with OWASP/ATLAS/NIST | `ReferenceComplianceMapper` |

Plugins are discovered via setuptools entry-point groups
(`mylonite.attack_modules`, `mylonite.validators`, …). Treat any change to a contract as
an API change — see [Plugin authoring](plugin-authoring.md).

## Constraints worth knowing

- **All LLM access flows through LiteLLM** — no provider SDKs imported directly; there's
  no default provider (you must configure one). This is what makes the
  [model roles](attack-modes.md#composing-modes-with-the-model-roles) and cross-model
  durability possible.
- **The reference twin is ground truth.** The bundled `mcp_kitchen_sink` vulnerable/guarded
  pair is *intentionally* (un)guarded; the differential is proven against it.
- **Scope discipline.** Only the AI attack surface — no general SAST/DAST, no non-AI test
  generation.
