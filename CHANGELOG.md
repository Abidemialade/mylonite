# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Every persist/print/publish path now runs through redaction**, closing
  several independently-discovered credential-leak findings (DCR-0003,
  DCR-0006, DCR-0007, DCR-0010, DCR-0011, DCR-0016, DCR-0019, DCR-0021).
  `install_log_redaction` only ever filtered `logging` records; every
  `typer.echo` call bypassed it, and three review passes independently
  rediscovered the same gap. `src/` no longer calls `typer.echo` directly —
  every human-facing string leaves through a new console boundary
  (`mylonite._cli_io.echo` / `echo_err` / `echo_exc`), enforced by
  `tests/test_cli_output_boundary.py`. Specifically:
  - A pydantic `ValidationError` from a malformed `--target-file`/`--env` no
    longer echoes its raw `input_value` (e.g. an `Authorization` header or a
    DB password) — `redact_exception` renders field path + message only.
  - `mylonite scan`'s scan-dir copy, `mylonite generate`'s co-located copy,
    and `mylonite gate`'s PR copy of a custom `target.yaml` are no longer
    verbatim: `redact_target_yaml` masks every `headers` /
    `request.headers` value and every credential-shaped `env` value before
    the file is written, so a live bearer token or DB password never lands
    in a directory the operator is told to commit. `dump_target_file` masks
    by default for the same reason (`redact_secrets=False` opts out for the
    in-memory-only round-trip).
  - The `scan --scaffold` "relative SQLite path" warning (#18) no longer
    prints the env value, only the key name.
  - The SARIF artefact uploaded to GitHub code scanning redacts a finding's
    narration before it is rendered into the `message`.
  - The retained attack-evidence trace (`mcp_trace_planner`, persisted into
    `exploit_*.json` / `scan_report.json`) masks credential-shaped tool-call
    argument *values* while leaving non-secret values (URLs, prose bodies)
    intact — the fetch/filesystem/github oracle predicates read those exact
    values to detect exfiltration, so blanket-dropping them would have
    silently disabled detection.
  - `redact()` now also masks `scheme://user:pass@host` URL credentials.
  - `redact_value`/`redact_env` mask a credential-shaped value by KEY NAME
    (`password`, `api_key`, `token`, ...) as well as by shape — a plain
    passphrase with no provider-key prefix under a credential-named key
    previously sailed through unmasked.
  - `scan --scaffold` / `mylonite init --transport mcp` no longer writes a
    `--env` value verbatim into the starter `target.yaml` it generates — a
    fourth, earlier-in-the-lifecycle origination path for the same leak class
    as the scan/generate/gate copy sites.
  - The output boundary now also covers `console.print` and bare `print` —
    not just `typer.echo`. `mylonite report` rendered a scan/validation
    summary via a bare `console.print(...)` with no redaction, even though
    `mylonite scan` redacted the exact same string.
  - The JSON finding bundle (`report --json`) now redacts a finding's
    narration the same way the SARIF artefact does.

  See "What Mylonite does with your credentials" in `SECURITY.md`.

- **One `--authorize` gate for every command that live-drives a real target**
  (DCR-0008, DCR-0009), replacing three independent, drifted implementations.
  New `src/mylonite/_authz.py` (`required_authorization` / `check_authorization`)
  derives the required `--authorize` value from the target's own data — its
  declared `scope`, else its `family` name — and is now the single
  implementation shared by `scan`, `gate`, `validate`, and `ablate`.
  - **Fixed:** a custom target file could declare a sensitive `scope` (e.g.
    `scope: /home/alice/private`) while also setting `requires_scope: false`,
    downgrading the check to the guessable literal family name instead of the
    scope (DCR-0008). The gate no longer trusts that self-asserted flag — a
    declared scope is now always the required value, and `TargetFile`
    normalises `requires_scope` to `true` whenever a `scope` is set, as
    defense in depth for any other consumer of the field.
  - **BEHAVIOUR CHANGE:** `mylonite validate` against a custom target
    (`--target-file`) now requires `--authorize` and refuses (exit 2) without
    it. Previously `validate` live-drove the real target — including sending
    live attack payloads such as exfil probes — with **no authorization check
    at all** (DCR-0009). Reference targets (`reference:vulnerable` /
    `reference:guarded`) are unaffected; they never required `--authorize`.
  - **BEHAVIOUR CHANGE:** `mylonite ablate` now validates that `--authorize`
    actually names the target (its scope or family), not merely that some
    non-empty value was supplied.

## [0.7.5] - 2026-07-04

> **Adoption + professionalization.** Point Mylonite at a plain HTTP agent with no MCP
> wrapper and no changes to the app under test; sharpen probes with a one-line `--purpose`;
> and read docs written as plain technical English instead of a pitch. The demo install
> path is fixed end to end.

### Added

- **Generic HTTP-agent adapter (`transport: rest`).** Point Mylonite at any plain HTTP
  agent by declaring its request shape in a `target.yaml` `request` block (`url`, `method`,
  `headers`, a `body` template with a `{prompt}` placeholder, and a dotted `response_path`
  into the JSON reply) — no MCP wrapper, no changes to the app under test. A black-box agent
  has no tool surface, so it is tested for the prompt-injection / goal-hijack class (`W2`),
  judged on the reply. See `docs/http-agent.md`. `request.headers` may carry auth and are
  never logged. `scan --scaffold OUT --rest-url URL` writes a runnable HTTP-agent target
  file in one command (no hand-editing). `validate`/`gate --prove-input-control` opt into
  an input data-framing ("spotlighting") differential that measures whether wrapping the
  payload as untrusted data is load-bearing for the agent (the black-box analogue of the
  untrusted-data envelope); by default a rest target is gated by stability + effect +
  consensus, so a real finding is never falsely rejected.
- **`--purpose "…"` on `scan` and `gate`** (and a `purpose` field in `target.yaml`): a
  one-line description of what the app is for, threaded into the payload customiser so
  probes are tailored to the app's domain. Persisted for a custom target so
  `generate`/`validate` reuse it.
- **`--iterations N` on `gate`** (default 3): the gate's validation leg now runs the
  differential across several iterations by default, so the `kept` verdict reflects
  reproducibility (the attack must fire in all but one run and the guarded side must resist
  every run). Pass `--iterations 1` for the fastest, weakest gate.
- **`mylonite init`** — a guided setup command that writes a runnable `target.yaml` for
  either a plain HTTP agent or an MCP stdio server (prompts for what it needs, or takes
  flags to be scriptable). It is the interactive front-end over `scan --scaffold`; distinct
  from the `init-target` command removed in 0.7.4.

### Changed

- **`--randomize-exfil` defaults ON for live custom-target runs** (now a tri-state
  `--randomize-exfil/--no-randomize-exfil`). A kept finding proves the control blocks
  exfiltration to *any* attacker address, not just the one demo literal — no more accidental
  teaching-to-the-test. The reference/replay path never randomizes.
- **Documentation rebranded to plain technical English.** Removed the pitch vocabulary
  (`moat`, `magic moment`, `keystone result`, `the thesis`, "the pitch") from every shipped
  doc, and renamed the coined terms to plain ones: **the Quarry → the reference app**,
  **twins → the vulnerable and guarded builds**, **seeds (as a concept) → attack patterns**.
  The `control-efficacy oracle` section is now `control-efficacy check`. README trimmed to
  the essentials.
- **The boundary-proxy caveat is surfaced up front** in `validate` output (a prominent
  banner) when the guarded side is the synthetic boundary control rather than your real
  server-side guard — matching what the gate PR body already stated.

### Fixed

- **The `pip install "mylonite[demo]"` path now resolves** end to end: the reference target
  `mcp-kitchen-sink` is published to PyPI, so `mylonite demo` runs with no clone. Reconciled
  the README/quickstart contradictions — Python **3.11–3.13** (litellm has no 3.14 wheels),
  one canonical (illustrative, model-dependent) demo count, and a single Windows activation
  command.
- Removed a dead CLI helper and stale local working artifacts; no product behaviour change.

## [0.7.4] - 2026-06-24

> **Narrowed to the provable core — *model robustness ≠ app security*.** The third-party
> verification harness (`verification/`) showed where Mylonite's value is demonstrable —
> **app-flaw detection, control-efficacy validation, regression gating, and honesty** — and
> where it isn't. The doctrine for this release: every shipped feature has to run on an MCP
> app we did **not** author and have a path to third-party proof; everything else is **cut,
> not hidden**. The **control-efficacy oracle** — which proves a control is load-bearing on
> any single-build app by holding the model constant and toggling only the safeguard — is now
> the headline moat; the two-build differential (fail-on-vulnerable, pass-on-guarded) is the
> bundled-twin / `demo` case. The remote SSE/HTTP transport is promoted to first-class (real
> MCP apps are remote). Because the project has no external users yet, this breaking cut costs
> nothing now.

### Removed

- **BREAKING:** the `mylonite export` command (portable eval-format bridge). Mylonite's
  artifact is the validated, CI-gating pytest regression test; the eval-format export was
  unproven surface. Consume the JSON bundle (`report --json`) or SARIF (`report --sarif`)
  instead.
- **BREAKING:** the `mylonite report --html` / `--html-style` dashboard and its HTML
  renderer (`mylonite.report.html`). The terminal trust panel, SARIF (`--sarif`, for GitHub
  code scanning), and the JSON finding bundle (`--json`) cover every consumer; the HTML
  dashboard was redundant. The shared `severity_for` rule moves to `mylonite.report.severity`
  (SARIF/JSON still import it).
- **BREAKING:** the standalone `mylonite init-target` command and the deprecated `mylonite
  init` alias — folded into `scan --scaffold` (see Changed).
- **BREAKING:** the deeper attack *tactics* — `scan --adaptive` / `--verbose-strategist`,
  `scan --synthesize` (tool-chaining synthesis), `scan --memory` (stateful memory poisoning),
  and `validate --models` (cross-model durability) — plus their modules (`scan/attack_loop.py`,
  `chain_synth`, `chain_driver`, `chain_validator`, `synthesis_runner`, `memory_poison`,
  `cross_model`), the `validate --adaptive` grading leg, and `testkit.assert_synthesized_chain_resists`.
  They were never the moat (the control-efficacy oracle is), were beaten by frontier-aligned
  models on every external target (DVMCP recall 0/8, InjecAgent 0/60), and had no third-party
  proof path. The single-shot W1–W4 engine, the control-efficacy oracle, and `ablate` are
  unaffected. The code lives in git history and returns only if a real external need
  re-justifies it.

### Changed

- **Folded target scaffolding into `scan`.** `mylonite scan --command 'python server.py'
  --scaffold target.yaml` introspects a custom MCP server (one launch, **no LLM call and no
  attack**, so it does **not** require `--authorize`) and writes the same commented starter
  `target.yaml` — with suggested `weakness_classes`/`primary_tools` and auto-detected
  `seed_arm`/`effect_probe` candidates — that `init-target` used to. One entry point instead
  of two. Edit the scaffold, then scan it with `--target-file`.
- **Crowned the control-efficacy oracle as the moat; promoted remote MCP to supported.**
  `validate` and `gate` lead with the **control-efficacy oracle** (it synthesizes a guarded
  twin of your single-build app at the adapter boundary and proves the control carries the
  security); the two-build differential is now framed as the bundled-twin / `demo` case. The
  **remote SSE/HTTP transport** is no longer "experimental" — declare `transport: sse|http`
  + `url` in `target.yaml`. The supported surface is `scan` (W1–W4 over MCP **stdio or remote
  SSE/HTTP** + your own `--target-file` app; `--scaffold` to generate a target.yaml),
  `generate`, `validate`, `gate`, `report` (terminal / SARIF / JSON), `ablate`, `demo`,
  `doctor`, `taxonomy`, and `version`. README / ROADMAP / docs reposition on "model robustness
  ≠ app security" and "any MCP app" (not "any LLM-native app").

### Fixed

- **SARIF `partialFingerprints`.** `report --sarif` now emits a per-result
  `partialFingerprints` (`mylonitePatternLocus/v1`) keyed on the finding's stable identity
  (pattern + weakness class + implicated tool/field locus + target), so GitHub code scanning
  correctly dedups the same weakness into a single alert across commits instead of
  re-raising it on every line move. Found by running Mylonite's own SARIF output against the
  GitHub ingestion requirements during third-party verification.

### Added

- **Verification report: false-positive-rate honesty rail.** The Layer-2 judge-agreement
  report (`verification/report.py`) now emits `fpr_informative` and `negative_cases`, and
  appends a note when `tn=0` — the case where false-positive rate is mechanically pinned
  at 1.0 by the absence of any benign / true-negative control cases (e.g. the AgentDojo
  injection subset), so the number is never misread as a trigger-happy judge. Triaging the
  15 AgentDojo disagreements confirmed every one is the effect-based-judge vs
  exact-goal-oracle *definitional* difference (the attacker's consequential tool actually
  executed), not a judge bug — recorded in `verification/FINDINGS.md`.
- **Descriptor-driven seed delivery channels (seed portability).** Mylonite's seeds
  no longer assume the kitchen-sink store→recall workflow. `mylonite.scan.seed_synth`
  synthesises a probe for the channel a target's *introspected tool surface* actually
  exposes: **direct_content** (a tool that processes attacker-supplied free text, e.g.
  `process_document`) and **tool_description** (an existing tool whose own description
  steers the agent — plain-prose tool poisoning, which `sanitize_tool_description` only
  partially caught). New `tool_roles` detectors (`content_processor_tools`,
  `instruction_bearing_tools`, `description_carries_instruction`), a `verbatim` seed
  drive, a `judge_context` field (tells the judge about a tool-description smuggle
  without revealing it to the planner), and a `customise` flag (synthesised seeds run
  direct). The scan pre-flight is channel-aware (W2 no longer hard-blocks when a
  content-processing tool provides the direct_content channel). Verified live: on a real
  MCP server Mylonite didn't write (DVMCP), W1/W2 seeds that previously *skipped*
  (`SeedArmUnavailable`) now run real attacks and are honestly judged.
- **Remote MCP transport (SSE / streamable-HTTP).** A new `MCPRemoteAdapter`
  (`mylonite.plugins._mcp.remote_adapter`) connects to a remote MCP server over SSE or
  streamable-HTTP, alongside the existing stdio adapter. Target files gain additive
  `transport: stdio|sse|http`, `url`, and `headers` fields — `stdio` stays the default and
  existing target files are byte-for-byte unchanged. A transport-aware factory
  (`mylonite.plugins._mcp.factory.build_mcp_adapter`) picks the adapter. The `TargetAdapter`
  contract is unchanged: this is an additive implementation behind the existing protocol, so
  there is **no `CONTRACT_VERSION` bump**. Auth headers are passed to the transport but never
  logged and never shown in the target descriptor (host only). Remote MCP is the dominant
  real-world deployment, so this is what lets Mylonite scan apps it didn't author.
- **Third-party verification harness (`verification/`).** A tiered system that scores
  Mylonite against external ground truth it did not author (lives outside `src/`, excluded
  from the wheel; external data fetched at pinned commits/digests, never vendored — see
  `verification/SOURCE.md`). Layer 2 ships first: InjecAgent (MIT) judge-agreement via a
  `record → score` runner that compares Mylonite's success-judge to the benchmark's own
  success rule (reusing `corpus.ConfusionMatrix`), with a CI-safe hermetic test on a
  synthetic fixture. Layer 1 ships as scaffolding: DVMCP (the runnable vulnerable MCP
  server) is fetched at a pinned commit and gated behind `--include-unlicensed` (its
  README claims MIT but it ships no LICENSE file), with a challenge→W-class catalogue and a
  recall scorer; the live SSE scan is a documented user step. The one Mylonite-authored
  input (the label→W-class crosswalk/catalogue) is isolated for audit. See
  `verification/README.md` and `verification/SOURCE.md` (which also records why the
  research-suggested DVAA target was verified unusable). All external data is fetched at
  pinned commits/digests, never vendored. Layer 3 (precision / false-positive control on a
  known-good target) ships a scorer + `reference:guarded` clean baseline. Layer 2 adds an
  opt-in `--elicit-positives` record mode (a compliant agent that manufactures successful
  attacks so the judge's positive class can be verified) and a `judge_agreement_exercised`
  honesty flag (precision/recall are vacuous at ASR=0). Layer 2 also adds **AgentDojo** as a
  second dataset, scored from its **released runs** (real third-party transcripts incl.
  positives from a model that fell for attacks) — closing judge-positive-class verification
  live without a model run. An opt-in `.github/workflows/verification.yml` runs the larger-N
  live numbers on dispatch/schedule; the hermetic checks gate every PR via
  `tests/verification/`. `verification/FINDINGS.md` records what the live runs showed
  (headline: model robustness ≠ app security; a robust model is still caught on app-design
  flaws like an unconfirmed `send_email`).

The remainder of Unreleased is an accuracy & honesty pass from an independent evaluation
against a real, server-guarded MCP target. One theme: **never report "couldn't test" or
"low-fidelity test" as "tested-and-clean / confirmed."** That pass added no new attack
classes and no contract-version bump (schemas unchanged).

### Fixed

- **W4 false negative on real targets.** `send_email_without_confirmation` read the
  reference-adapter-private `store_emails_sent` metadata; on a real MCP target that key
  is *absent*, so the predicate returned a confident `success=False` (a guaranteed false
  negative whenever the agent actually sent). It now returns *inconclusive* (`None`) when
  the evidence key is absent — distinct from a present-but-empty blob (a genuinely
  staged/queued send, still a confident non-finding). Detection now defers to the effect
  probe / LLM judge instead of falsely vouching the target is safe.
- **W1 false positive on apps that summarize by default.** The tool-description
  summary-smuggle predicate fired on any summary marker. When the *target's own system
  prompt* mandates a summary, the marker can't be attributed to the smuggle. The
  customiser now flags that baseline (`baseline_solicits_summary`) and the predicate
  stays inconclusive, deferring to the differential oracle. The bundled reference finding
  is unaffected (its summary lives in a tool description, not the system prompt).
- **`scan reference:*` dumped a raw traceback** when the reference target wasn't
  importable (editable checkout without `pip install -e ./reference_targets/...`). It now
  fails with the same friendly message `demo` gives (shared `_exit_if_missing_kitchen_sink`
  helper).

### Changed

- **Offline demo target is now an opt-in `[demo]` extra.** The base `pip install mylonite`
  stays "just the tool that scans your app" and never pulls the deliberately-vulnerable
  reference agent. `pip install "mylonite[demo]"` adds it so `mylonite demo` and
  `scan reference:*` run offline with no clone and no API key; the graceful CLI error
  points users to the extra (or the editable-checkout path). NOTE: the extra requires
  `mcp-kitchen-sink` to be published to PyPI to resolve — until then the demo remains
  clone-first.
- **`truststore` is now a base dependency** (was the `[enterprise]` extra). Users behind a
  TLS-inspecting corporate proxy or local AV — whose CA is in the OS trust store but not
  certifi's bundle — no longer hit `CERTIFICATE_VERIFY_FAILED` out of the box. Auto-enabled
  (opt out with `MYLONITE_NO_TRUSTSTORE=1`), pure-Python, zero transitive deps, a no-op in
  CI. `[enterprise]` is kept as a back-compat alias.
- **`validate` differential measures real server-layer controls.** Its guarded twin was
  always the synthetic adapter-boundary shim, so a control enforced inside the server (an
  approval gate, an allowlist) "leaked" and the test was rejected with a verdict that read
  as "your protection is theater." When the target declares `control_env` for the control,
  the differential now uses the REAL server (raw side env-disables the guard; guarded side
  is the default launch) — at parity with `ablate`'s server-layer mode (shared
  `_guarded_factory`, also used by `--synthesize`/`--memory`). When only the synthetic shim
  is available, a rejection is reframed honestly: it points to `control_env`/
  `vulnerable_launch` and states the boundary twin cannot see server-side guards, rather
  than implying the control is ineffective.
- **`--memory` / `--synthesize` no longer silently no-op.** When no plant+retrieve /
  plant+sink surface is discoverable they reported a clean `no_finding` in 0.0s; they now
  report a loud **NOT TESTED** outcome (naming the tools they looked for vs the target's
  actual tools) and exit non-zero, so a CI gate can't read the no-op as "safe." Discovery
  also consults a declared `seed_arm` / `control_config.consequential_tools` before the
  name heuristics, so a real app whose tool names don't match is still exercised.
- **Adaptive attacker-refusal is reported distinctly.** When the (aligned) strategist
  declines to refine an obviously-malicious payload, the loop aborts and the attempt is
  reported as *skipped (alignment refusal) — NOT evidence the target is safe*, instead of
  a clean no_finding that read as "the target resisted." `--randomize-exfil` help now
  recommends it for live custom-target runs (with an inline nudge); documented the
  aligned-attacker ceiling in `docs/attack-modes.md`.

### Added

- **Pre-flight warning that side-effecting weaknesses (W3/W4) need an `effect_probe`.** On
  a real target without one, those seeds can't confirm the effect and may read as clean;
  the scan now warns loudly (and `mylonite init-target` already suggests an `effect_probe`
  candidate from the tool surface).

## [0.7.3] - 2026-06-19

Second depth-first release. Deepens the moat into the #1 real-world agentic threat
(stateful memory poisoning), proves a fix durable across model upgrades, promotes the
real evasion encodings from a report-only sideshow into the gating layer, and opens a
machine-readable findings channel. No new attack classes or adapters; no
contract-version bump.

### Added

- **Stateful memory-poisoning attack + differential validation (T1).** Models the
  threat the single-turn loop misses: poison planted ONCE, left to PERSIST across
  unrelated turns, then retrieved and acted on in a LATER turn (the "zombie agent" /
  slow-drip shape). `MemoryPoisoningDriver` runs plant → N benign turns → retrieve
  over one persistent `AttackSession`; `MemoryPoisonValidator` re-drives that
  cross-turn attack against both twins and keeps it as a finding only when it fires
  on the vulnerable twin and is resisted on the guarded one (which quarantines the
  *recalled* memory) across a flakiness filter — the same differential moat applied
  to memory poisoning. `MemoryPoisonRunner` discovers the plant/retrieve plan from
  the live tool surface, validates, and emits a finding stamped
  `attack_shape=memory_poisoning` with the plant/retrieve turn separation. It also
  confirms the poison resurfaced in the retrieval turn (`cross_turn_delivered`), so a
  non-delivery reads as NOT TESTED rather than a false clean pass. No new attack class
  or adapter — deepens W2 over existing session machinery. New `scan/memory_poison.py`.
  Exposed as **`scan --memory`** (mirrors `--synthesize`): a reference twin uses the
  bundled twins; a custom `--target-file` uses the synthetic W2-boundary-guarded twin,
  so the differential proves the *memory* control (quarantining recalled content) is
  load-bearing.
- **Machine-readable JSON finding bundle (`report --json <path>`).** A self-contained
  `finding.json` (severity, weakness class, compliance tags, R4 localization, the R2
  differential proof, and the proven control) for teams not on GitHub/pytest —
  dashboards, SIEM, chat bots, custom CI. Reuses the exact data the SARIF/HTML
  reports already compute; no new analysis. New `report/bundle.py`.

### Changed

- **Cross-model durability (`validate --models a,b,c`).** A weakness fixed and gated
  against one model can silently re-emerge when a team upgrades the model — a blind
  spot with no regression. Because Mylonite is model-agnostic, it now re-proves the
  *same* differential across several models and flags the ones where the guarantee no
  longer holds ("durable on A and B, RE-EMERGES on C"), exiting non-zero if any model
  fails and writing a `cross_model_report.json`. Single-model `validate` now also
  stamps the validated model into the report so the committed regression is honest
  about which model version it gates. New `scan/cross_model.py`.
- **Real-world evasion encodings are now GATING, not a report-only sideshow.** The
  differential oracle's metamorphic layer gained three new strategies — zero-width
  (`unicode-tag`), word-`split`, and `multilingual` framing — so a kept test must
  survive re-encoding (EchoLeak's invisible text, RAG unicode/split tricks), not just
  rewording. Each preserves the exfil email/URL literal so the attack still lands and
  the majority threshold stays honest.

### Removed

- **The standalone `scan --obfuscate` tier.** It was report-only with no path into
  the moat; its one useful idea (the evasion encodings above) now lives in the
  *gating* metamorphic layer, so this is strictly less surface for more depth. The
  `obfuscate_payload` transform utility remains (now feeding the metamorphic gate).

## [0.7.2] - 2026-06-18

Depth-first release (no new attack classes or adapters): makes the differential
oracle's guarantee actually *land* and *gate* on real targets, promotes metamorphic
robustness to a gating leg so the moat is enforced rather than merely reported, and
surfaces findings + proven fixes where developers already consume them (GitHub code
scanning, the gating PR). No breaking changes; no contract-version bump.

### Changed

- **The differential oracle now gates real (`--target-file`) targets BY DEFAULT.**
  Previously a custom-target finding was kept on `build ∧ stability ∧ effect ∧
  consensus` and the differential leg (re-driving a boundary-guarded twin to prove
  the *safeguard*, not the model, carries the security) ran only with
  `--prove-control` — so a real app's regression test could be kept even if its
  safeguard was broken, as long as the attack reproduced. `validate` and `gate`
  now build the guarded twin and run the differential automatically whenever a
  boundary control can be inferred for the finding's weakness. `--fast` opts out
  (≈ half the live runs, but the weaker stability+consensus gate); a weakness with
  no inferable control falls back to that gate **loudly** (never silently weaker).
  `--prove-control` is now the default behaviour and kept for back-compat; on
  `validate`, `--adaptive` no longer requires it.
- **Metamorphic robustness now GATES the kept decision (was report-only).** The
  reference oracle's gate is now `kept = build ∧ differential ∧ flakiness ∧
  metamorphic`: a generated test must survive a MAJORITY (default 60%) of
  deterministic, semantically-neutral rewordings of the exploit body (paraphrase /
  casing / whitespace / unicode confusables, each genuinely re-driven through both
  twins) to be committed. This makes the fourth named moat mechanism actually
  enforce — a test over-fit to one literal payload ("teaching to the test") is now
  rejected. A majority threshold (not all-or-nothing, configurable via
  `metamorphic_robustness_threshold`) avoids rejecting a real finding just because a
  single aggressive rewording didn't reproduce. Mutation score stays near-free
  observability (not gating).

### Added

- **SARIF 2.1.0 output (`report --sarif <path>`) for GitHub code scanning.** AI-layer
  findings now land in the GitHub **Security tab** and PR checks — where developers
  already triage every other finding — instead of only a terminal/HTML panel. Each
  SARIF result carries a severity (`security-severity` + level), the compliance tags
  (OWASP-LLM/ASI · MITRE ATLAS · NIST), and — the trust signal — the **differential
  proof** in its message ("fired N/N on the vulnerable target, resisted M/M with the
  control — the safeguard, not the model, carries the security"). Reuses the existing
  exploit/validation data and the dashboard's severity rule; no new finding logic.
- **Auto-wired `seed_arm` from the tool surface (frictionless real-target on-ramp).**
  When a custom `--target-file` declares an indirect-injection weakness (W2) but no
  `seed_arm`, `scan` now describes the target's live tool surface and infers how to
  plant untrusted content — so a real MCP app can be tested with near-zero config
  instead of hitting a hard pre-flight block. To avoid the "plants but never lands"
  trap, it auto-wires **only when a no-id recall path exists** (so the planted
  payload is guaranteed to be surfaced back to the planner); otherwise it explains
  why and leaves the seed_arm to the operator. The inferred value is printed
  (`auto-wire: inferred seed_arm: …`) and overridable in the target file. New
  `infer_seed_arm` / `needs_seed_arm_autowire` reuse the existing `_classify_tools`
  heuristics — no new attack logic.
- **Proven fix rendered as a reviewable diff in the gating PR.** The "Suggested
  mitigation" section now carries a concrete, class-specific code diff (the
  server-side change that implements the boundary control the differential proved
  load-bearing) alongside the prose rationale — "here's the fix we proved works",
  not a guess. For a control-efficacy finding it is framed as a **Proven fix**; for
  other findings as a **Recommended fix**. New `gate/fixes/{W1-W4,generic}.md`.
- **Findings are localized to their exact locus, and rendered where developers
  read.** Mylonite ingests the AI layer, so it now pins each finding to the precise
  place to fix it — which tool's *description* smuggled the instruction, which tool's
  *returned content* was trusted, which action *handler* fired without a guard, or
  which *system-prompt line* is at fault — derived deterministically from data every
  finding already carries. The locus shows as a **Located at:** line in the gating
  PR and as a SARIF `logicalLocation` (plus a real prompt-file line where available)
  so GitHub code scanning pins it. With `--open-pr`, a finding that maps to a
  committed prompt line also posts a best-effort inline **check-run annotation**
  (GitHub Checks API); loci with no source line (a remote MCP tool) ride in the PR
  body + SARIF instead — never silently dropped. New `gate/localize.py` +
  `gate/annotate.py`.

## [0.7.1] - 2026-06-18

Responds to an external v0.7.0 effectiveness assessment: hardens the differential
oracle's precision, extends the differential machinery to server-layer-controlled
real targets, and closes several CLI / report / packaging gaps. No breaking
changes and no contract-version bump (`TargetFile`/`TargetSpec` are not under
`contracts/`).

### Added

- **Server-layer twin launch for the differential machinery.** Ablation,
  `validate --prove-control`, and `scan --synthesize` previously synthesised the
  "raw"/unguarded side by emptying the *adapter-shim* controls — blind to targets
  that bake their guards into the **server** (env-/profile-driven, the common real
  architecture): the raw side stayed fully guarded, so ablation classified every
  control `no-attack`. A target file can now declare how to run a genuinely
  unguarded variant:
  - `control_env` — a per-weakness map of env vars that disable one server-layer
    guard. `mylonite ablate` toggles controls individually through it (raw side
    disables all; "only control C" leaves just C on), restoring per-control
    load-bearing/theater attribution on server-layer targets.
  - `vulnerable_launch` — an alternate `command`/`args`/`env` that starts a fully
    unguarded variant, used as the raw side by `validate --prove-control` and
    `scan --synthesize`.
  Both fields are optional and additive (omitting them is byte-for-byte today's
  behaviour). Launching a deliberately-unguarded server is gated by `--authorize`,
  announced on stderr, and env **values are never logged**. When a declared raw
  launch doesn't actually disable the guard, the raw side never fires and the tool
  says so (`no-attack` + a hint) rather than emitting a wrong verdict.
- **`generate --prove-control`.** The standalone `generate` command can now emit a
  control-efficacy test (`assert_control_holds`) — proving the control blocking a
  finding is load-bearing (the attack lands without it, is resisted with it) —
  instead of only the standard resists/guard test. Previously this assertion was
  reachable only through the full `gate --prove-control` pipeline. Custom targets
  only (needs `--target-file`); a reference or non-controllable finding falls back
  to the standard test with a notice.
- **Strategist observability for `--adaptive`.** The adaptive loop now records a
  per-round log (the injection tried, the planner's tool calls, and *why* that
  round failed — the input the strategist refines from), where previously only the
  attempt *count* survived. The trace is persisted in the finding's evidence
  (`adaptive_log`) so a finding records HOW it was reached, and a new
  `--verbose-strategist` flag echoes each round live to stderr (payloads redacted).
- **Stakeholder HTML report dashboard (`report --html`).** `mylonite report --html`
  now writes a structured, self-contained dashboard by default: an executive
  summary (target / verdict / run metadata), per-finding cards with a **severity
  badge** (High = a consequential action materialized or an exfil/egress/
  excessive-agency weakness landed; Medium = fires without a damaging effect;
  Low = situational), compliance chips (OWASP-LLM / ASI / ATLAS / NIST), and
  collapsible raw evidence via native `<details>` — interactivity with **zero
  JavaScript**, no CDN, and no web fonts, so it still screenshots cleanly in CI.
  The previous raw trust-panel export is preserved as `--html-style terminal`.
- **Windows install guide** (`docs/install-windows.md`) covering the platform
  friction: selecting a supported Python (3.11–3.13, not 3.14), cloning with the
  schannel TLS backend behind a corporate proxy, the separate `mcp_kitchen_sink`
  editable install, OS-trust-store TLS, and `PYTHONUTF8=1` for the console.

### Changed

- **`gate` reads `mylonite.yaml` like `scan`.** `gate` now accepts `--config` and
  auto-discovers `./mylonite.yaml`, filling `target_file` / `authorize` /
  `provider` / `model` / `max_llm_calls` from it when the matching flag is omitted
  (an explicit flag always wins). Previously `gate` ignored the project run config
  and exited 2 ("no target given") unless you re-passed `--target-file`.
- **`--adaptive` auto-sizes its LLM-call budget.** An active adaptive scan that
  leaves `--max-llm-calls` at the single-shot default (50) now raises it to an
  adaptive-appropriate default (200) with a notice, instead of silently aborting
  partway through a multi-seed run. Any explicit value (flag or `mylonite.yaml`) —
  including a deliberately low one — is respected unchanged.
- **Clearer `generate --latest` message on a clean scan.** When the newest scan
  found no exploits, the message frames it as a PASS (a clean/guarded target), not
  a bare error, and points at passing an earlier scan dir explicitly.
- **`truststore` is now in the `[dev]` extra** (as well as `[enterprise]`), so a
  dev install gives contributors behind a corporate proxy OS-trust-store TLS for
  the live-gated tests and `mylonite doctor` without extra steps. The `[dev]`
  extra also documents the separate `pip install -e ./reference_targets/mcp_kitchen_sink`
  the full test suite needs.

### Fixed

- **Oracle precision: W1/W4 false positives on the guarded side.** Two
  deterministic success-predicates over-fired on a guarded target when the planner
  model behaved benignly, destabilising the differential oracle (a single benign
  guarded-side fire trips the strict 5-run flakiness filter and rejects an
  otherwise-valid regression test). Both are now model-robust and target-agnostic:
  - `planner_summarised_against_user_intent` (W1) is **drive-aware** — it stays
    inconclusive when the seed's `drive` explicitly solicits a summary (e.g.
    `read_note_for_summary`); the summary-marker set was tightened to high-signal
    *unsolicited* phrasings (dropping incidental `summary:` / `tl;dr`).
  - `send_email_without_confirmation` (W4) returns a confident `success=False`
    (short-circuiting the permissive LLM judge) when an approval step ran or
    `send_email` only staged without dispatch — instead of `None`, which let the
    judge re-introduce a finding on the guarded twin. The approval step generalises
    beyond the reference `confirm_send` via `payload.metadata['approval_tool']` /
    `['confirmation_tool']`.
- **NIST AI RMF tags now appear in `mylonite report`, matching the emitted test's
  marks.** NIST was derived (from the OWASP cross-refs) only inline when emitting a
  test's pytest marks, while the persisted exploit JSON `report` reads stayed
  un-enriched — so NIST showed in the test but not the report. `generate` now
  persists the enriched exploit, and `report` enriches compliance on read, so
  OWASP / ASI / ATLAS / NIST are consistent across the test, the scan report, and
  the validation report.

## [0.7.0] - 2026-06-17

### Added

- **Control-efficacy oracle on real targets.** Mylonite can now prove
  which safeguard is load-bearing on a real MCP target, not just the bundled
  reference twin. A `ControlServerShim` (`mylonite.scan.control_shim`) synthesizes
  a *guarded twin* of a real target by applying a canonical control at the adapter
  boundary (**W2**, the untrusted-data envelope) — the model is held
  constant, so the differential measures the *control's* marginal contribution.
  Only the planner's view is guarded; the attacker's plant and the effect probe
  bypass the shim, so the measurement stays honest. `DifferentialValidator` gains
  an optional `guarded_adapter_factory`; for a custom target it adds a
  `differential` leg (reusing the statistical `_decide`): the attack must fire on
  the raw target and be resisted with the control, scored as a control-contribution
  rate gap. No contract bump (reuses the `differential` stage +
  `ReproducibilityEvidence`). The emitted regression test and the gating PR are
  reframed to "control verified load-bearing — fails if it regresses", with an
  explicit boundary-proxy fidelity caveat.
- **`mylonite.testkit.assert_control_holds`** — new public testkit gate (a
  stability-promised surface): asserts a boundary control is load-bearing (the
  attack fires on the raw target and is resisted once the control is applied). The
  reference pytest generator emits it for control-efficacy findings (those
  carrying `synthetic_control` metadata).
- **Per-run exfil-destination randomization (`--randomize-exfil`).** Mints a
  unique, fully-distinct exfil destination per run (reserved `.test` TLD, sharing
  no substring with the demo literal) and keys the success predicate on the
  minted token, so a finding proves the control/target stops exfil to ANY
  attacker destination, not just the one demo address. The destination predicates
  (`send_email_to_attacker`, `web_fetch_to_unauthorised_url`) now read the
  per-payload token, defaulting to the demo literal — so behaviour is unchanged
  with the flag off, and the recorded-fixture replay path never randomizes. Wired
  into `validate` and `gate`.
- **Full boundary control set (W1-W4) + control-ablation matrix (`mylonite ablate`).**
  Adds the W1 tool-description sanitizer (strips `(Note:)` / `<IMPORTANT>` / HTML-comment
  / bracketed-directive smuggles and non-ASCII / invisible-tag-char ASCII-smuggling),
  W3 egress host-allowlist gate, and W4 confirm-gate (blocks unconfirmed consequential
  actions). `mylonite ablate` scores each safeguard's marginal contribution on a real
  target — toggling each control on vs off against its weakness (model held constant) —
  and reports load-bearing vs "security theater". An optional `control_config` in the
  target YAML declares egress / consequential tools and the URL param so W3/W4 are
  precise on an arbitrary tool surface (name heuristics otherwise).
- **Safeguard-aware adaptive strategist.** The `AdaptiveAttackDriver` accepts a
  `control_context` describing the active boundary control (and how it works), so
  on a control-guarded target it crafts injections to evade THAT specific defense
  rather than re-wording blindly.
- **Stateful MCP sessions — `--adaptive` now works on real targets.**
  `MCPStdioAdapter` implements `SupportsAttackSession.open_session`, returning a
  session that persists one subprocess across `call_tool` (raw plant) +
  `drive_planner` (planner view, boundary-control-guarded) and closes it cleanly
  (open/use/close in one coroutine, verified against a real subprocess — no anyio
  cancel-scope violation). Previously `--adaptive` silently degraded to
  single-shot on every real MCP target. The engine probes the session once before
  activating the adaptive path and falls back to single-shot if it can't open, so
  a target whose server fails to spawn never reports a misleading "nothing found".
- **Adaptive-aware control oracle (`validate --prove-control --adaptive`).** The
  headline depth capability: drive the *guarded* side of the control-efficacy
  differential under the adaptive loop (with the active control fed to the
  safeguard-aware strategist via `control_context`), while the raw side stays
  single-shot. The verdict now distinguishes a control that "holds under adaptive
  pressure" from one that "holds static but falls to adaptive" — grading control
  *robustness*, not just presence. `--adaptive` requires `--prove-control`. No
  contract bump (reuses `_decide` + the `differential` stage).
- **Adaptive-path effect-probe rigor.** Adaptive findings on real targets now get
  the same judge rigor as the single-shot path: `_MCPAttackSession.drive_planner`
  stamps `payload_delivered` and runs the target's `effect_probe` against the
  **raw** session (bypassing the control shim — the honesty invariant), so the
  judge's effect-probe override applies on the adaptive path and a "fired" verdict
  reflects a confirmed effect, not just a plausible reply.
- **Payload obfuscation as live attack tiers (`scan --obfuscate <strategy>`).**
  Tests whether a filter/control generalizes beyond plaintext: `unicode-tag`
  (invisible-tag-char ASCII smuggling), `split` (payload-splitting), `multilingual`
  (fixed phrase table, no LLM), and `base64-wrapper` (encodes the instruction
  wrapper only). Every transform keeps the exfil destination **literal** so the
  body-agnostic success predicates still match the emitted tool-call blob. Stamps
  `payload.metadata["obfuscation"]`; the recorded-fixture replay path never
  obfuscates. Deterministic and pure.
- **Effect-trace-aware chain escalation + chains on real custom targets.**
  `ChainAttackDriver._next_drive` now synthesizes turn N+1 from turn N's per-step
  effect trace + the judge's reason via the strategist (degrade-safe fallback to a
  static sink-nudge), instead of a fixed follow-up. `scan --synthesize` now accepts
  a custom `--target-file` (with `--authorize`): it synthesizes the chain and
  differentially validates it against the **synthetic guarded twin** (raw vs a W2
  boundary-guarded variant via the control shim), reusing the control-efficacy
  machinery — previously synthesis was reference-twin-only.
- **Auto-derived NIST AI RMF tags + attack-tier signal.** The reference compliance
  mapper (previously never invoked) is now wired into the generate / gate / PR
  boundary and auto-derives `nist_ai_rmf` ids from an exploit's OWASP LLM/ASI tags
  via the bundled taxonomy cross-references (single source of truth, idempotent).
  Every exploit also carries `payload.metadata["attack_tier"]`
  (static / obfuscated / adaptive / adaptive+obfuscated), surfaced in the gating PR
  body and the emitted-test docstring. No contract bump (the `nist_ai_rmf` field
  pre-existed; tier rides metadata).
- **Ablation thoroughness — multiple seeds + redundancy mode (`ablate --redundancy`,
  `--max-seeds`).** `mylonite ablate` now probes multiple kitchen-sink seeds per
  weakness (capped by `--max-seeds`) instead of a single representative. The new
  `--redundancy` mode toggles each control OFF against the **full** control set
  (rather than on-vs-nothing), surfacing a `redundant` status — a control whose
  weakness is still covered by another control — distinct from `theater` (fires
  with and without). Prints a run-count estimate up front.

## [0.6.0] - 2026-06-17

### Added

- **App-specific tool-chaining synthesis (`scan --synthesize`).**
  Synthesizes a multi-tool exploit chain from the target's own tool surface (a
  store/plant tool → a harmful sink, e.g. `read_note → send_email`) — the
  app-specific depth generic probe libraries can't reach — then **differentially
  validates** it: the synthesized sink must be reached on the vulnerable twin and
  blocked on the guarded twin across a flakiness filter, or it is not a finding.
  `ChainSynthesizer` proposes the chain (deterministic tool selection + one
  constrained LLM call, with a deterministic skeleton on fallback);
  `ChainAttackDriver` executes it by reusing the adaptive loop and
  escalates to multi-turn steering when a single drive doesn't reach the sink;
  `ChainDifferentialValidator` is the moat. A validated chain emits an
  `ExploitRecord` with the chain embedded for replay, and `mylonite generate`
  emits a live-gated regression test (`testkit.assert_synthesized_chain_resists`)
  that fails if the guard regresses. Opt-in, reference-twin targets for now
  (custom single-variant validation is deferred); the per-seed scan is unchanged.
- **Multi-step `AttackSession` adapter capability** (target-adapter contract
  `0.3.0` → `0.4.0`, additive). Optional `SupportsAttackSession.open_session()`
  returns an `AttackSession` exposing raw `call_tool` + `drive_planner` +
  `close`, letting an attack loop carry target state across steps. Implemented
  for the in-process reference adapter; single-shot adapters are unaffected.
- **Adaptive attack loop (`AdaptiveAttackDriver`).** When an indirect-injection
  attempt does not fire (e.g. an aligned planner refusing a poisoned note), an
  LLM strategist re-crafts the injection from the planner trace + judge reason
  and retries against a fresh session, within an attempt budget — turning a
  single-shot miss into a finding. A single attempt that raises is tolerated
  (the loop refines and continues; `BudgetExceededError` still aborts).
- **`scan --adaptive` — engine-wired adaptive path.** Opt-in flag that, against
  a session-capable target (e.g. `reference:*`) with a discoverable plan, runs
  the plant-drive-judge-refine loop for indirect-injection seeds instead of the
  single-shot path; the outcome maps onto the usual `ScanAttempt`/`ExploitRecord`
  (with `adaptive_attempts` evidence and the refined body). Off by default — the
  single-shot path and the `seed_arm`/`effect_probe` config stay the fallback;
  `--adaptive` degrades with a notice when the target can't open sessions.
- **`AttackPlan` auto-discovery (`discover_attack_plan`).** The adaptive loop
  builds its plant/drive plan from the target's tool surface (a store tool with
  a genuine free-text slot, an id-keyed read-back), so it needs no hand-authored
  `seed_arm`/`effect_probe`. Because the loop mints and controls the id, it can
  exploit id-keyed read-backs the single-shot scaffold heuristic must skip. The
  tool-role heuristics now live in `mylonite.scan.tool_roles` (shared by the
  scaffold and the loop).
- **Chain-aware session judging.** A session `drive_planner` now emits an
  `effect_trace` (per-step tool, `is_error`, result) that the effect-aware judge
  consumes, so a session-driven attempt is judged on the chain's per-step
  outcomes (incl. refusals), not just bare tool names. **Contract:** the
  target-adapter contract is **0.4.0 → 0.5.0** (additive): `drive_planner` gained
  an optional `pattern_id` kwarg so findings carry the originating seed's id
  instead of the `"session-drive"` sentinel.

### Changed — Effectiveness hardening (custom-target accuracy)

- **Statistical differential oracle.** The reference differential now keeps a
  test on the attack **success-rate gap** between the twins
  (`vulnerable-fire-rate − guarded-leak-rate ≥ 50%`, vulnerable firing ≥ 40%,
  guard leak ≤ 0%) instead of the brittle count gate ("vulnerable fires ≥ N-1
  of N"). The old gate rejected genuinely-present-but-probabilistic,
  LLM-mediated exploits — e.g. an indirect injection that lands 3/5 runs is now
  KEPT, not REJECTED. Thresholds are configurable on `DifferentialValidator`
  (`min_rate_gap` / `min_vuln_rate` / `max_guard_leak`). **Contract:** the
  validator contract is **0.4.0 → 0.5.0** (additive): `ReproducibilityEvidence`
  gained `guard_fired` (guard leak count) and `rate_gap`.
- **Role-separated models.** `scan` accepts `--planner-model` /
  `--customiser-model` / `--judge-model` (each defaults to `--model`);
  `ScanConfig`, `build_scan`, and `DifferentialValidator` thread them through.
  The planner — the agent-under-test decision-maker — is what an aligned model
  makes refuse injection on *both* twins, collapsing the differential; pointing
  the planner at a representatively exploitable model while keeping an aligned
  judge restores signal.
- **Robust delivery confirmation.** Indirect-injection "delivered?" detection
  now scans the **untruncated** tool results and folds in **JSON-decoded**
  structured returns (a `recall`-style tool returning a list of records), and
  matches several high-signal tokens — so a planted note nested in a JSON list
  or sitting past the trace cap no longer reads as a false `NOT TESTED`.
- **`init-target` config synthesis.** The scaffold now classifies discovered
  tools (store / retrieve / sink / observe) and pre-fills concrete `seed_arm`
  and `effect_probe` candidates instead of blank templates, and warns when a
  content-storing tool has no id-free retrieval path (the `save_note`/`read_note`
  trap that silently makes injection seeds undeliverable).

### Fixed

- **`export --format eval-yaml`** no longer splices the raw predicate reason
  into the rubric ("MUST NOT planner called web_fetch …"); it maps the weakness
  class to a grammatical consequence clause.
- **`generate <scan_dir>`** now emits one test per finding (into per-pattern
  subdirs) instead of silently dropping all but the alphabetically-first.
- **`doctor --config`** pings the model declared in `mylonite.yaml` rather than
  defaulting to `claude-sonnet-4-6` when you configured another.
- CLI help clarity: `taxonomy list --framework` is marked required; `report
  --html` documents that it takes a file-path argument.

### Added — flow + verification legibility

- **`mylonite export` — eval/CI interop.** Mylonite is the validation layer;
  `mylonite export <dir|exploit.json> --format eval-yaml` hands a
  differential-oracle-validated finding to the eval/CI harness a team already
  runs. It emits a portable eval test case (the attack as input + a rubric assert
  that the agent must resist it) carrying the OWASP/ATLAS/NIST compliance tags
  and a `validated_by: mylonite-differential-oracle` provenance marker — so the
  team gets a Mylonite-validated regression in their existing suite. Offline, no
  LLM. `--out` writes the config and prints the next step.
- **Declarative `mylonite.yaml` run config.** A new `RunConfig`
  (`mylonite.config.load_run_config`) threads a run so the same flags need not be
  re-passed: `scan --config mylonite.yaml` fills any omitted `target_file` /
  `authorize` / `provider` / `model` / `max_llm_calls` (an explicit flag always
  wins). Single-file run ergonomics for the custom-target journey.
- **Measured precision/recall corpus.** A new `mylonite.corpus` module +
  `scripts/measure_precision_recall.py` drive the bundled kitchen-sink twins
  across the W1-W4 seeded weaknesses with no LLM and no network, then compute a
  confusion matrix (TP/FP/FN/TN) and report precision / recall / false-positive
  rate / F1 — turning "the oracle is reliable" into a measured number CI can
  track. The seeded twins separate perfectly (precision = recall = 1.0, FPR = 0).
  (Multi-judge consensus already applies to every custom-target validation; this
  adds the offline measurement substrate.)
- **`mylonite report` command** — an offline trust panel. Point it at a scan
  dir, a validated dir, or a `scan_report.json` /
  `validation_report.json` and it renders a clean, screenshot-able "why you can
  trust this" readout: for a validation, the verdict + gating formula + live
  per-leg marks + fires/resists counts + per-seed kill matrix + compliance tags;
  for a scan, the findings + coverage (incl. any NOT TESTED gap) + compliance
  tags. `--html PATH` also writes a standalone, shareable HTML panel. `mylonite
  validate` now persists `validation_report.json` next to the test so the panel
  (and the JSON artefact) carry the full oracle evidence.

- **Frictionless custom-target flow.** `scan` now persists the resolved target
  YAML into the scan dir as `target.yaml`; `generate` and `validate`
  auto-resolve it from the scan/generated dir, so a custom-target journey needs
  `--target-file` at most once (at `scan`). `scan` and `validate` print a
  `Next:` hint pointing at the following command. `scan --help` documents its
  exit codes.
- **Differential-oracle evidence is now legible.** `mylonite validate` renders
  the gating formula with live per-leg marks (`kept = build [ok] AND
  differential [ok] AND flakiness [x]`), the vulnerable-fires / guarded-resists
  reproducibility counts, the per-seed mutation kill matrix, and a one-line
  metric legend — previously all buried in `report.notes` and rendered nowhere.
  The gating PR body (`mylonite gate`) mirrors the same evidence.
- **A misfire can never read as "clean" (correctness safeguards).** A scan
  attempt that was *not exercised* — its planted payload was never delivered, or
  the target declared no `seed_arm` to plant it — now gets a loud `NOT TESTED`
  mark (distinct from the benign `clean`) plus a red `coverage:` warning in the
  summary, so a `findings_count == 0` scan with undelivered seeds is never
  mistaken for safety. `scan` also runs a blocking pre-flight: declaring an
  indirect-injection-only weakness class (e.g. W2) with no `seed_arm` errors out
  with a fix hint unless `--allow-no-seed-arm` is passed (a `--dry-run` only
  warns). New `mylonite.plugins._mcp.target_file.validate_for_scan` helper.

### Changed

- **Validator contract `0.3.0 → 0.4.0` (additive).** `ValidationReport` gained
  optional structured-evidence fields — `gating_formula`, `gating_legs`,
  `reproducibility` (a `ReproducibilityEvidence`), and `mutation_matrix` (a list
  of `SeedKill`) — lifted out of the free-text `notes` so surfaces can render
  the oracle's discrimination. All fields are optional/defaulted; existing
  reports remain valid. `SeedKill` and `ReproducibilityEvidence` are exported
  from `mylonite.contracts`.

### Added — CI gating + the magic moment

- **`mylonite gate` command** — the end-to-end magic moment: `scan →
  generate → validate → (opt-in) open a gating PR`. Writes all artefacts
  under `.mylonite/gate/` (test, exploit, fixtures, target YAML for custom
  targets, CI workflow templates). Mirrors `scan` routing: accepts
  `reference:vulnerable`, bundled `mcp:<family>`, or `--target-file
  target.yaml --authorize <scope>` for custom MCP apps. Flags: `--open-pr`
  (push a branch + open via `gh`), `--llm-enrich` (labelled LLM fix
  suggestion, clearly marked unverified), `--runs-on` (runner label for
  scaffolded workflows), `--workflows/--no-workflows` (scaffold CI
  templates), `--out` (output directory), `--max-llm-calls`, `--provider`,
  `--model`. Exit codes mirror `scan`/`validate`.
- **`mylonite.gate` package** — deterministic PR-body renderer with
  per-weakness-class remediation snippets (W1 tool-description smuggling,
  W2 indirect injection, W3 unrestricted egress, W4 unconfirmed
  consequential action), compliance-tag section (OWASP LLM / ASI / ATLAS /
  NIST), and validation-evidence summary. The deterministic path never calls
  an LLM; `--llm-enrich` appends a labelled section cleanly separated from
  the deterministic body, so the human reviewer sees exactly what is machine-
  generated vs LLM-suggested.
- **Two scaffolded GitHub Actions workflow templates** written by
  `gate`/`write_workflows`: a per-PR gate job (offline fixture replay — fast,
  cheap, no LLM egress) and a nightly discovery job (full live scan — catches
  new weaknesses and regressions). The cost-tier split is encoded in the
  template: per-PR stays under the free tier; nightly uses a capped
  `max-llm-calls` budget. `--runs-on` lets operators target a self-hosted
  runner for in-perimeter MCP backends.
- **Reusable composite `gate-action`** (`Abidemialade/mylonite/gate-action@v1`)
  — a three-line drop-in for any repo's workflow that installs Mylonite,
  resolves the Python + provider environment, and runs `mylonite gate` with
  the caller's inputs.
- **`docs/ci-gating.md`** — the end-to-end CI gating guide: from first
  `mylonite gate` run through reviewing the PR, merging the committed
  regression test, and operating the two-job CI setup over time.
- **`docs/enterprise-networking.md`** — TLS/proxy setup for corporate and
  air-gapped environments: OS trust-store (`pip install "mylonite[enterprise]"`
  + `truststore`), `SSL_CERT_FILE`, `MYLONITE_NO_TRUSTSTORE`, self-hosted
  runner configuration for in-perimeter MCP backends, and the offline
  fixture-replay path that needs no LLM egress at all for the per-PR gate.

### Fixed — emitted-test runnability + shared environment bootstrap

- **The emitted custom-target test is runnable out of the box.** `mylonite generate`
  gained `--target-file`, which co-locates your target YAML next to the test as
  `target.yaml` (copied verbatim, comments preserved) — the live test re-drives your
  real app and needs it. Generating a custom-target test without `--target-file` now
  warns loudly, and `testkit.assert_target_resists` raises a clear, actionable error
  (instead of a bare `FileNotFoundError`) when `target.yaml` is missing. `generate`
  also prints the live-test prerequisites (pytest, a provider key, a runnable MCP
  server, the co-located YAML) and both the `pytest` and `validate` commands.
- **TLS trust-store setup is shared with the library/testkit path.** Truststore
  injection moved to a reusable `mylonite._bootstrap.enable_truststore()` that the
  CLI callback and the testkit (`assert_target_resists` / `assert_guard_holds`) both
  call, so an emitted test run under `pytest` behind a TLS-inspecting proxy no longer
  fails `CERTIFICATE_VERIFY_FAILED` the way only the CLI used to avoid. Still honors
  `MYLONITE_NO_TRUSTSTORE=1`; inert on the offline replay path.
- **No import-time cost-map SSL warning.** `mylonite` now defaults
  `LITELLM_LOCAL_MODEL_COST_MAP=True` (overridable) so litellm uses its bundled cost
  map instead of fetching the remote one at import — which logged a noisy
  `CERTIFICATE_VERIFY_FAILED` on proxied machines. Affects only cost/token-accounting
  metadata, never provider routing.
- **`--api-key-file` / `--env-file` override an ambient key.** A key passed via a
  flag now wins over a (often wrong) value already in the environment — the exact case
  the flags exist for — and warns on stderr when it overrides, naming only the variable,
  never the secret.

### Added — effect-aware findings, delivery verification, custom-target validation

- **Findings now turn on the damaging *effect*, not the tool name.** Both MCP
  adapters (stdio + in-process reference) capture each tool's `content` + `isError`
  into a normalized `effect_trace` in the response metadata, and the judge requires
  the consequence to have *materialized*: a deferred / refused / `is_error` result
  (e.g. "queued for approval", "host not in allowlist") is **not** a success even
  when the consequential tool was named. The deterministic weight rests on the
  MCP-protocol `isError` flag and a target-declared effect probe — provider- and
  wording-independent — with the LLM judge as a secondary signal only.
- **Effect probe (`EffectProbeSpec`).** A target file / seed can declare, per
  consequential capability, how to confirm the effect end-to-end (run a verify tool
  after the planner and check for an expected marker), plus an overridable
  `deferred_markers` list. The adapter stamps `effect_confirmed = true|false|unprobed`.
  Generic over email / file-write / issue / payment / egress / DB mutation — any
  consequential action — so a finding can mean "damage confirmed" on an arbitrary app.
- **One generic deterministic predicate.** `consequential_action_executed` reads a
  seed's declared consequential tool plus the effect trace (priority: `isError` →
  executed-not-deferred check → an overridable marker heuristic as last resort) and
  is available for custom seeds that set `consequential_tool` in their metadata. In
  the live path the target-declared effect probe drives the verdict structurally via
  the judge's `effect_confirmed` short-circuit (above); the predicate is the
  effect-trace-only fallback. No English keyword is load-bearing for either.
- **Delivery verification — a misfire no longer reads as clean.** For indirect
  seeds the adapter detects whether the poison was actually retrieved by checking
  that a distinctive token from the planted payload appears in a planner tool
  result (no marker is injected — the attack stays realistic), and captures the
  planted handle robustly (`SeedArmSpec` gained `id_key` / `id_pattern`). If the
  poison is never retrieved into the model's context, the attempt is reported
  `skipped_payload_not_delivered` rather than `no_finding` (mirroring the existing
  `skipped_no_seed_arm` honesty precedent). A `recall_all` drive lets a keyless
  target still surface the poison.
- **Custom-target validation — the moat no longer requires the bundled twin.**
  `DifferentialValidator` now honours `target` / `oracle`: a `reference:*` exploit
  takes the unchanged twin differential; a **custom** `target_id` re-drives the
  operator's REAL MCP server (fresh subprocess per run, `--authorize`-gated) and
  keeps the test only if it passes **stability** (the attack reproduces across N
  runs) ∧ **effect** (the effect probe confirms damage — replacing the missing
  twin) ∧ **consensus** (adversarial multi-judge majority). New public testkit
  helper `assert_target_resists(exploit, *, target_file=…)` re-drives the real
  target and asserts it still resists (live-gated behind `MYLONITE_LIVE_TARGET=1`);
  the pytest generator emits this for custom targets while reference targets stay
  byte-for-byte (`assert_guard_holds`). `mylonite validate --target-file …` runs
  the custom path.
- **`mylonite.testkit` / `mylonite generate` no longer require the reference
  package.** `reference_target_adapter` imports `mcp_kitchen_sink` lazily (inside
  `describe()` / `invoke()`), so importing the testkit or generating a test works
  without the optional reference install. The scan engine re-raises an `ImportError`
  from `describe()` (a missing optional dependency is a configuration error, not a
  target failure) so the CLI maps it to a clear exit instead of a generic
  `describe_failed`.

### Changed

- **`validator` contract `CONTRACT_VERSION` 0.2.0 → 0.3.0** (minor, additive).
  `ValidationOutcome.stage` gained `stability` / `effect` / `consensus` legs for the
  custom-target validation path. Existing reference-path reports are unaffected.
- **`target_adapter` contract `CONTRACT_VERSION` 0.2.0 → 0.3.0** (minor, additive).
  The scan report's `ScanAttemptOutcome` enum gained `skipped_payload_not_delivered`.
  Backward-compatible for adapters; report readers see one new outcome value.

### Added — plug-and-play on-ramp (scaffold, keys, docs)

- **`mylonite init-target`** scaffolds a custom-target YAML by launching your MCP
  server once (no LLM call), listing its tools, and writing a commented starter
  with SUGGESTED `weakness_classes` / `primary_tools` (taxonomy-grounded hints,
  always user-confirmed) and a `seed_arm` + `effect_probe` template. Warns on a
  relative SQLite DB path (the #18 Windows footgun) and round-trip-validates the
  YAML before writing. (`mylonite init` is now a deprecated alias.)
- **Provider key handling.** Global `--api-key-file` (a bare key or a dotenv
  line; the provider is inferred from the key shape, never printed) and
  `--env-file` (loads ONLY known provider API-key vars from a `.env`, never
  blanket env injection). `mylonite doctor` now warns when a resolved key clearly
  isn't key-shaped (placeholder / path / truncated paste) without echoing it.
- **Natural-language planting checks (R7).** A custom target whose `seed_arm`
  embeds `{payload}` inside a JSON/structured string, or omits it entirely, now
  gets a loud warning (the plant must be natural language at a bare string leaf).
  The scan summary also surfaces `customiser`-fallback and N-run-disagreement
  counts so a low-quality or flaky plant isn't invisible.
- **Python 3.11–3.13 guidance (S4).** The CLI prints a clear note on Python 3.14+
  (litellm has no 3.14 wheels yet); README states the supported range.

### Added — bounded runs (timeouts, progress, scan-time flakiness filter)

- **Scan-time N-run flakiness filter.** New `ScanConfig.runs` (default 1, no
  behaviour change) invokes + judges each payload N times; the payload is a
  finding only if it fires in a strict majority, so a 1-in-N fluke is rejected.
  Observed disagreement is surfaced in the report's `fallback_breakdown`
  (`nrun_disagreement`) and `single_run` now reflects reality (`runs == 1`).
- **Wall-clock bound on a scan.** New `ScanConfig.wall_clock_timeout_s` (default
  None) stops a scan that exceeds its budget — even a hung task — returning
  `aborted="wall_clock_timeout"` with whatever completed, instead of running
  open-ended.
- **Validator timeout + progress.** `DifferentialValidator` gained
  `iteration_timeout_s` (per-scan wall-clock bound for a custom target, threaded
  into the engine) and `progress_cb` (streams "iteration k/N …" so a long live
  validation no longer goes silent for minutes). `mylonite validate` exposes
  `--iteration-timeout` and streams progress to stderr.

### Fixed

- **Compliance provenance now comes from the firing seed, not the umbrella
  module.** A module spans several weakness classes (W1–W4); stamping
  module-level tags mislabelled which OWASP/ASI/ATLAS IDs an emitted test
  actually proves. The emitted `ExploitRecord` now carries the precise
  per-seed compliance.
- **Seeds are no longer double-emitted.** The prompt-injection module owns the
  W1/W2 family only (mirroring the excessive-agency module's W3/W4 filter), so
  the W3/W4 seeds are emitted once, not twice; the engine also dedupes by
  `pattern_id` across modules as a backstop. This lowers the demo's per-run
  attempt count (the 2-vs-0 vulnerable/guarded differential is unchanged); eight
  now-unreachable demo replay fixtures were pruned.

## [0.5.0] - 2026-06-12

### Added — cross-LLM robustness (JSON ingestion/emission + provider-agnostic auth)

- **Provider-native structured output.** The judge and customiser now request
  `response_format` (json_schema where the model supports it, else json_object),
  capability-gated via LiteLLM introspection (`supports_response_schema` /
  `get_supported_openai_params`) and degrading to prose-only for providers/local
  models that don't support it. So OpenAI/Gemini/etc. return valid JSON by
  construction, not just Claude — every introspection call is guarded so an
  unknown model never errors.
- **Provider-tolerant JSON parsing** (belt-and-suspenders behind structured
  output): reads JSON from `message.content` (fences/prose) **or** a tool call's
  `arguments` (some providers' JSON mode, previously ignored); rescues non-strict
  JSON (trailing commas, single quotes, Python `True/False`, unquoted keys) via
  the new MIT `json-repair` dependency, strict-parse-first; and **rejects
  truncated output honestly** (never lets repair fabricate a missing close).
- **Planner cross-LLM hardening:** sends `tool_choice="auto"` only when tools are
  present; tool-call arguments are repair-rescued too.
- **Provider-agnostic auth/diagnostics:** new `scan/providers.py` maps each
  provider to its API-key env var(s) (OpenAI→`OPENAI_API_KEY`,
  Google→`GEMINI_API_KEY`, Bedrock→AWS vars, …, with LiteLLM spelling aliases);
  `classify_provider_error` now matches **LiteLLM typed exceptions first**
  (`AuthenticationError`/`RateLimitError`/`APIConnectionError`/
  `ContextWindowExceededError`/…) before substring fallback, and the auth remedy
  names the **right** env var for the provider in use (`LLMConfig.api_key_env_var`
  overrides). `mylonite doctor` reports the provider-correct remedy.
- A `tests/scan/test_llm_crossmodel.py` regression matrix exercises Claude/OpenAI/
  Gemini/tool-call/non-strict/truncated output shapes, the capability gating
  (incl. the raising-introspection fail-safe), and the diagnostics-per-provider —
  so "we only tested Claude" can't regress.

### Changed

- **`target_adapter` contract `CONTRACT_VERSION` 0.1.0 → 0.2.0** (minor, additive).
  `TargetDescriptor` gained the optional `weakness_classes` field. The
  `scan_report` / `scan_attempt` report schemas also gained optional fields
  (`inconclusive_attempts`, `fallback_breakdown`, `tool_call_trace`,
  `judge_evidence`) and one new `ScanAttemptOutcome` value (`skipped_no_seed_arm`).
  All changes are backward-compatible for existing adapters and report readers.

### Security

- **Implemented the `redact_secrets` control (previously documented but inert).**
  New `mylonite._redaction` module masks secret-shaped tokens (provider key
  prefixes like `sk-ant-…`/`sk-…`, AWS access-key ids, `Bearer …` tokens, PEM
  private-key blocks, and `api_key`/`token`/`secret`/`password` `key=value`
  assignments) behind `***REDACTED***`. A `SecretRedactingFilter` is installed
  on the `mylonite` logger tree on every CLI invocation (honouring the
  `LoggingConfig.redact_secrets` default), and the rendered CLI scan summary is
  redacted before it is echoed. Redaction is deliberately NOT applied to
  persisted replay fixtures, `exploit_*.json` / `scan_report.json` artefacts, or
  generated test source — masking those would corrupt loadable/replayable data.
  Example emails and attack strings (`attacker@example.com`, `[SYSTEM OVERRIDE]`,
  tool-call ids, note ids) are preserved. `config.py` and `SECURITY.md` updated
  to describe the now-real behaviour.
- **Patched known-vulnerable dependencies.** Bumped `litellm>=1.83.10`
  (CVE-2026-40217) and added security floors for litellm's transitive deps
  `aiohttp>=3.14.0` (CVE-2026-34993, CVE-2026-47265) and
  `python-dotenv>=1.2.2` (CVE-2026-28684). `pip-audit` now reports no known
  vulnerabilities; the full test suite is unaffected.
- **Continuous security scanning in CI.** Added a permanent `security` job to
  `.github/workflows/ci.yml` that runs on every push and pull request:
  `bandit` SAST over `src/mylonite/` at medium+ severity (blocking),
  `detect-secrets` over the full tracked tree against a committed
  `.secrets.baseline` (blocking), and `pip-audit` for dependency CVEs
  (informational). The deliberately-vulnerable reference targets are excluded
  via `[tool.bandit]` so the ground-truth oracle is never "hardened". A
  `detect-secrets` pre-commit hook gives the same secret-scan locally, and
  `SECURITY.md` documents the tooling.

### Added

- **Environment & diagnostics hardening.**
  - `mylonite doctor` makes a 1-token provider ping and classifies any failure
    as **auth** / **TLS** / **network** / **rate-limit** / **unknown**, each with
    a concrete remedy (new `scan/diagnostics.py`) — a corporate-proxy cert
    failure no longer masquerades as a bad API key.
  - **OS trust store support.** With `pip install "mylonite[enterprise]"` the CLI
    auto-enables `truststore` so TLS verification uses the OS trust store (which
    holds the corporate CA); opt out via `MYLONITE_NO_TRUSTSTORE=1`. Verification
    is never disabled. `SECURITY.md` documents `SSL_CERT_FILE` as the alternative.
  - **Model routing.** When `--provider` is set explicitly and the model carries
    no `provider/` prefix, the CLI now prefixes it so Anthropic aliases like
    `claude-3-5-haiku-latest` route instead of failing "LLM Provider NOT
    provided"; the model string is validated up front.
  - **ASCII-safe summary.** `render_summary(..., ascii_safe=...)` (auto-detected
    from stdout encoding) renders a completed scan without non-cp1252 glyphs, so
    embedded/driver callers on a legacy Windows console can't crash on output.
- **Declared supported Python range.** `requires-python = ">=3.11,<3.14"` — the
  upper bound matches litellm (no installable litellm on 3.14), turning a
  confusing resolver error into a clear "unsupported Python". Revisit when
  litellm supports 3.14.
- Docs/clarity: `reference_example` is marked example-only (filtered out of real
  scans); SECURITY.md documents the custom-target `--authorize` rule and the
  Windows SQLite-URL footgun; a session-reuse design note is recorded for a
  future `--reuse-session` mode.
- **First-class custom MCP targets.**
  "Test *your* AI app" is now reachable through the CLI for any MCP stdio server,
  not just the three bundled families:
  - `mylonite scan --target-file target.yaml --authorize <fam|scope>` — a
    declarative `TargetFile` (`plugins/_mcp/target_file.py`) declares the launch
    `command`/`args`/`env`, `scope`, `system_prompt`, `primary_tools`, the
    `weakness_classes` the app exposes, and a `seed_arm` for planting poisoned
    content. Also reachable inline via `mylonite scan mcp:custom --command … --arg
    … --weakness-class W2 …`. Custom specs register into a runtime registry
    (`register_target`) that can never shadow a bundled family.
  - **Descriptor-driven seed applicability.** Seed selection now resolves from
    `TargetDescriptor.weakness_classes` when declared (a custom target opts into
    attack shapes) and falls back to the legacy family mapping otherwise — the
    bundled reference/filesystem/fetch/github targets produce byte-for-byte the
    same seed sets (golden-tested). The attack modules call
    `seeds.seeds_for_descriptor` through the module namespace, removing the
    triple-namespace monkeypatch footgun.
  - **Declarable seed arm for indirect injection.** `MCPStdioAdapter._run_setup`
    honours a target-declared `seed_arm` (tool + `{payload}`/`{scope}` arg
    template), so indirect prompt injection — the primary threat for an
    email/RAG agent — can finally be exercised against a custom target. The note
    drives (`read_note_*`) emit neutral, seeded-record-referencing instructions
    so the attack travels through the planted content, not the user message.
  - **Auditable attempts.** `ScanAttempt` now persists `tool_call_trace`
    and `judge_evidence` on every judged outcome (including `no_finding`), so a
    finding is verifiable from `scan_report.json` alone without querying the
    target's own database.
  - Schema note: `target_descriptor.schema.json` and `scan_attempt.schema.json`
    regenerated; all changes additive/backward-compatible.
- **Expanded metamorphic robustness check (report-only).** The
  `DifferentialValidator` metamorphic stage now applies MULTIPLE deterministic
  perturbation strategies to the exploit body — `paraphrase`, `casing`,
  `whitespace`, and `unicode` (fullwidth confusables) — each a pure
  `body -> body` string transform (no LLM, no randomness). Each reworded payload
  is GENUINELY driven through BOTH reference twins + the judge — the adapter
  writes the perturbed body into the poisoned note the planner reads, with
  payload customisation disabled so the reworded text is used verbatim — so the
  reworded attack is actually executed (not a catalogue re-run of the original
  seed body). The stage reports a ROBUSTNESS fraction
  (`held / total`, in `[0,1]`) plus a per-strategy breakdown
  (e.g. `paraphrase:held, casing:held, whitespace:broke, unicode:held`). The
  set is configurable via a new `metamorphic_strategies: list[str] | None = None`
  constructor arg (default = all built-ins). **Report-only: metamorphic does NOT
  gate `kept`** — even if every perturbation breaks, `kept` is unaffected.
- **Per-seed mutation kill matrix (report-only).** The mutation score is now
  computed PER-SEED over every kitchen-sink seed (not per-weakness-family): a
  seed is "killed" when the vulnerable twin fired its `pattern_id` AND the
  guarded twin resisted it across the differential iterations.
  `ValidationReport.mutation_score` is now `killed_seeds / total_kitchen_sink_seeds`
  (bounded `[0,1]`), and the report notes surface the full matrix
  (e.g. `mutation: killed 3/4 kitchen-sink seeds … W2:<id>✓ …`). Report-only —
  does not gate `kept`.
- **`mylonite validate` now closes the validate→committed-artefact loop.** When
  the differential loop finds a clean discriminating run, `validate` RECORDS the
  canonical guarded fixtures into the generated dir's `fixtures/`, writes the
  on-disk test + co-located exploit next to them, and runs that ON-DISK committed
  test offline as a **full-pass** build stage (pytest exit 0 — the guard holds
  against the recorded fixtures), replacing the old collect-only + re-emit. The
  command leaves behind a ready-to-commit, replayable test + fixtures and proves
  it passes offline. `validate` no longer re-renders the test from the exploit —
  it validates the ACTUAL file on disk. If no clean discriminating run exists,
  the build stage falls back to collect-only and records nothing.
  `DifferentialValidator` gains a `record_fixtures_dir: Path | None = None`
  constructor arg (default `None` preserves the prior collect-only behavior).
- **Per-exploit fixture isolation: the offline gate now runs a single seed.**
  `ScanConfig.pattern_id_filter` (new, default `None` = unchanged full scan)
  scopes a scan to one pattern_id, dropping non-matching payloads *before* any
  customiser/judge/LLM work. `mylonite.testkit.assert_guard_holds` now sets this
  filter to the exploit's own `pattern_id`, so the offline gate replays only that
  exploit's seed — keeping committed fixtures small and decoupled. Because the
  recorded-fixture scope changed from "all seeds" to "one seed",
  `FIXTURE_FORMAT_VERSION` is bumped `1 → 2`; v1 (full-scan-scoped) fixtures are
  refused by the gate. The demo never sets the filter, so its full-scan replay is
  unaffected.
- **MITRE ATLAS and NIST AI RMF compliance markers are now registered and
  emitted.** The bundled pytest11 plugin registers one marker per bundled-taxonomy
  ATLAS technique (`atlas_<id>`, e.g. `atlas_aml_t0051`) and NIST AI RMF
  subcategory (`nist_<id>`, e.g. `nist_measure_2_6`), and the reference generator
  emits the corresponding `@pytest.mark.*` decorator for any in-taxonomy tag.
  `pytest -m atlas_aml_t0051` now selects emitted tests warning-free (no
  `PytestUnknownMarkWarning`). Out-of-taxonomy IDs still fall back to the
  docstring; the raw IDs continue to appear in the test docstring as before.

### Hardened

- The two machine-readable validation-metric fields —
  `ValidationOutcome.metric` and `ValidationReport.mutation_score` — now enforce
  their documented `[0,1]` bounds (`ge=0.0, le=1.0`) at construction; an
  out-of-range value hard-fails. Defensive only: the validator's produced values
  are already in-range fractions, so no runtime behavior changes for real data,
  and the validator contract version is unchanged (no contract-shape change).

### Improved — JSON parsing & scan-result reliability

- **Robust JSON extraction from model output.** `scan/_llm.py` now tolerates
  code fences (` ```json `), surrounding prose, and string-literal braces,
  extracting the first balanced `{…}` span — so customiser/judge output parses
  reliably across providers. Regression tests cover fenced, bare-fence,
  embedded-in-prose, and brace-in-string output.
- **Distinct fallback diagnostics.** The LLM-judge fallback distinguishes
  `"LLM call raised: …"` (provider/TLS/auth error) from `"LLM output not
  parseable as JSON"`, carried via a reserved fallback-cause sentinel that
  callers strip before it can reach a `Verdict` or `Payload.metadata`.
- **Inconclusive-rate reporting.** `ScanReport` gained `inconclusive_attempts`
  and `fallback_breakdown`; the CLI summary surfaces the inconclusive rate
  (bold-red when every judged attempt was inconclusive) so a scan that couldn't
  judge never reads as clean.
- **Honest skip reporting.** When a seed's setup arm cannot be planted (e.g.
  `seed_note` on a non-bundled target), the adapter raises `SeedArmUnavailable`
  and the engine records the new `skipped_no_seed_arm` outcome rather than
  `no_finding`.
- **Loud no-op detection.** When no seeds apply to a target the engine names the
  known families and sets `aborted="no_payloads"`; the `scan` CLI exits `2` with
  an actionable hint. An adapter `describe()` failure (`aborted="describe_failed"`)
  likewise exits non-zero rather than 0.
- Schema note: `scan_report.schema.json` and `scan_attempt.schema.json` were
  regenerated. All changes are additive (new optional fields; one new
  `ScanAttemptOutcome` enum value) and backward-compatible for readers.
- **Deterministic offline demo.** The reference wiring gained an `llm_assist`
  flag (`scan/wiring.py`); the demo/replay/record paths run with
  `llm_assist=False` (`ScanConfig.customise=False` + `SuccessJudge(llm_fallback
  =False)`), driving raw seed bodies judged purely by deterministic predicates so
  the recorded fixtures stay reproducible. The 4-vs-0 vulnerable/guarded
  differential is unchanged (fixtures consolidated 36/38 → 20/20).

## [0.4.0] - 2026-06-10

### Added — the validation engine (scan → generate → validate)

- **`mylonite generate` and `mylonite validate` now work** (replacing the
  not-implemented stubs), wiring the pytest generator to the
  `DifferentialValidator`.
  - `mylonite generate [SCAN_PATH] [--latest] [--out DIR]` is offline and
    deterministic (no LLM call). It resolves an exploit from an explicit
    `exploit_*.json`, a scan dir, or `--latest` (the newest `.mylonite/scans/<ts>/`),
    emits the pytest regression test, writes a co-located copy of the exploit JSON
    (under the exact name the emitted test loads) plus a `fixtures/` placeholder,
    and prints the exact `mylonite validate <out-dir>` command to run next.
  - `mylonite validate TARGET [--iterations N] [--provider X] [--model Y]` runs
    the `DifferentialValidator` **live by default** (real LLM, Haiku) and renders
    a per-leg Rich report (build / differential / flakiness / metamorphic) with
    the mutation-score headline and the kept verdict; on rejection it prints a
    per-leg remediation line. It discloses cost/latency/key up front (a one-line
    banner and in `--help`) and fails fast with a distinct exit code when no
    provider is reachable.
- **New exit code `EXIT_NOT_KEPT = 5`** so a CI gate can distinguish a cleanly
  validated-but-rejected test (`kept=False`) from success (0), config error (2),
  budget (3), and provider-unreachable (4). `mylonite validate` exits 0 when the
  test is kept and 5 when it is cleanly rejected.
- **`DifferentialValidator` — the validation-engine moat.** A new reference
  validator (`mylonite.plugins._reference.reference_validator:DifferentialValidator`,
  registered under the new `differential` entry point in `mylonite.validators`;
  the existing `null` entry point is unchanged) proves a generated security test
  is *meaningful*. It runs the full attack scan against BOTH reference twins
  across a multi-run flakiness filter (default 5 iterations) and assembles a
  `ValidationReport` from four stages:
  - **build** — the emitted test artefact is well-formed and *collectable* under
    pytest (imports the testkit, registers its markers). A full
    offline-pass-against-committed-fixtures is intentionally not asserted here
    (the fixtures are recorded later, in PR 7); that leg is proven by the
    reference example.
  - **differential** — across the iterations, does the exploit's `pattern_id`
    FIRE on the vulnerable twin and RESIST (a clean `no_finding`) on the guarded
    twin at all? `metric` is the agreement fraction.
  - **flakiness** — does it do both *reliably* (vulnerable fires
    `>= iterations - 1`, guarded resists `iterations`/`iterations` by default)?
    `metric` is the reproducibility fraction `min(fires, resists) / iterations`.
  - **metamorphic-lite** (report-only) — one deterministic neutral paraphrase
    perturbation of the exploit body, re-checked once on both twins.

  `kept = build ∧ differential ∧ flakiness`; metamorphic and the mutation score
  are reported, not gating. The report also carries a **mutation score**: the
  fraction of the four kitchen-sink weakness families (W1–W4) that show the
  differential (vulnerable fired ≥1 seed in the family AND guarded resisted it),
  computed for free from the scans already run. Config (iterations / thresholds /
  provider / model / `completion_fn` / `run_build`) lives in `__init__` because
  the contract `validate(test, target, oracle)` signature is fixed;
  `completion_fn=None` is the live LiteLLM path and an injected callable is the
  deterministic offline seam. A tiny `ReferenceVulnerableOracle` supplies a
  structurally-valid oracle for the bundled reference target.
- **Real testkit-based pytest generator.** `ReferencePytestGenerator` now emits a
  deterministic, self-contained regression test (replacing the `@pytest.mark.skip`
  stub). The emitted test imports the public `mylonite.testkit` API and, at
  runtime, replays the recorded attack against the GUARDED reference twin via
  `assert_guard_holds` — the offline regression gate. `load_exploit` /
  `assert_guard_holds` live inside the test body, so the file collects cleanly
  before its exploit JSON / fixtures exist. Output is template-driven with sorted
  taxonomy IDs (no LLM call, clock, or RNG), so it is byte-stable and
  snapshot-testable. Each emitted test carries compliance metadata as a docstring
  plus pytest markers (`mylonite_security` + per-tag `owasp_llm0N` / `owasp_asi0N`);
  unbounded ATLAS / NIST IDs ride in the docstring.
- **Bundled pytest marker plugin.** A new `pytest11` entry point
  (`mylonite.testkit._pytest_plugin`) auto-registers the markers emitted tests
  carry (`mylonite_security`, `owasp_llm01`..`owasp_llm10`,
  `owasp_asi01`..`owasp_asi10`) for any pytest run in an environment where
  `mylonite` is installed, so emitted tests stay warning-free even under
  `filterwarnings = error`.
- **`mylonite.testkit` — the public offline-gate API.** A new
  stability-promised module (on the same footing as `mylonite.contracts`) that
  Mylonite-emitted tests import: `load_exploit` reads an `exploit_*.json` into an
  `ExploitRecord`, and `assert_guard_holds(exploit, *, fixtures_dir=None)` is the
  **offline regression gate** — it replays the recorded attack against the
  in-process guarded reference twin and asserts the exploit's predicate did NOT
  fire. The gate is *honest*: a stale, missing, corrupt, or version-mismatched
  fixture, or an inconclusive run, **raises** (`TestkitFixtureError`) rather than
  silently passing, with a `_meta.json` (`{"format_version", "model",
  "pattern_id"}`) provenance check.
- **Neutral scan wiring (`mylonite.scan.wiring`).** The single source of
  scan-assembly truth — `build_scan(variant, ...)` + the deterministic
  `note_id_counter()` — promoted out of the demo into `scan/` so the demo, the
  record scripts, `mylonite.testkit`, and the `DifferentialValidator` all share
  one wiring path (no record/replay drift).
- **Programmatic pytest runner.** `mylonite.scan.pytest_runner.run_test_file`
  collects + runs an emitted test file in-process for the validator's build
  stage, distinguishing collection from execution.
- **Gated live e2e tests.** New `tests/e2e/` package (gated behind
  `MYLONITE_LIVE_E2E=1`, skipped in normal CI): `test_validate_live.py` runs the
  full live `DifferentialValidator` (Haiku) for the W2 seed and asserts `kept`,
  the mutation score, and high reproducibility; `test_real_target_generate_live.py`
  runs `mylonite scan mcp:fetch --authorize fetch` then `mylonite generate`
  against the real OSS fetch MCP server — the gated proof that the demo flow works
  on a real target.
- **Reference-example recording script.** `scripts/record_reference_example.py`
  (dev-time, run-once-with-`ANTHROPIC_API_KEY`) records the committed
  walking-skeleton example into `examples/reference_validation/`: a live W2
  `exploit_*.json` from the vulnerable twin, the recorded guarded `fixtures/` +
  `_meta.json`, and the emitted test — which then replays offline forever. Reuses
  `build_scan` / `note_id_counter` (no re-wiring), mirroring
  `record_demo_fixtures.py`.
- **Docs: the validation engine + de-stubbed quickstart.** New
  `docs/validation.md` ("The validation engine (the moat)") explains the two-tier
  model — LIVE periodic discovery vs the OFFLINE per-PR committed gate — answers
  the "is this a tautology?" objection (the differential proof across the 5-run
  flakiness filter + the mutation score + the testkit's honest-fail check), and
  defines `kept`, the reproducibility fraction, and the mutation score.
  `docs/quickstart.md` is de-stubbed to the real `scan → generate → validate`
  flow (`generate` offline, `scan`/`validate` live).
- **Machine-readable validation metrics.** `ValidationOutcome` gains an optional
  `metric: float | None` (per-stage numeric — flakiness reproducibility fraction,
  differential agreement fraction, metamorphic robustness rate) and
  `ValidationReport` gains an optional `mutation_score: float | None` (fraction of
  the seeded-weakness bank the generated test correctly catches). Both default to
  `None`, so the change is backward-compatible. These make the the validator validation
  engine's two headline numbers headline-able, chart-able, and CI-gate-able.

### Changed

- **Validator contract bumped `0.1.0 → 0.2.0`** (minor, backward-compatible — the
  two new fields above are optional with defaults). This is a `contract-change`
  per `GOVERNANCE.md`.
- **CI gains a Windows leg.** A `windows-latest` job runs the suite so the
  pytest-runner / emitted-test / testkit-replay paths are exercised on the
  platform contributors most often hit cp1252 / path-separator surprises on.

## [0.3.0] - 2026-06-10

### Added — the Quarry playground

- **`mylonite demo`** — a zero-config, **offline, deterministic** playground.
  It runs the real scan twice against the bundled deliberately-vulnerable
  reference agent ("the Quarry", `reference:vulnerable`) and its guarded twin
  (`reference:guarded`), then prints a safety banner, a W1–W4 weakness table
  with OWASP / ASI / ATLAS taxonomy IDs, and the headline
  **`4 exploits on vulnerable, 0 on guarded`**. No API key, no network. A
  `--live` opt-in re-runs the same scan with real LLM calls (needs a key).
- **Committed per-variant LLM fixtures** under `src/mylonite/demo/fixtures/`
  (`vulnerable/`, `guarded/`), recorded with
  `anthropic/claude-haiku-4-5-20251001`, so the default demo replays recorded
  model behavior byte-for-byte. Re-record via
  `python scripts/record_demo_fixtures.py` (needs `ANTHROPIC_API_KEY`).
- **Differential renderer** — the demo's table and headline join the two scan
  results by `pattern_id` and surface each weakness's compliance metadata
  (OWASP LLM / ASI / MITRE ATLAS IDs).
- **`docs/quarry.md`** — full playground walkthrough and W1–W4 scenario
  catalogue; mkdocs nav gains a "The Quarry" page.
- **`docs/assets/recording-script.md`** — controller script for producing the
  README demo GIF (`docs/assets/quarry-demo.gif`).

### Changed

- **Replay core promoted.** The record/replay LLM wiring used by the demo is
  shared with a strict replay check (a missing fixture is a hard error rather
  than a silent live call), keeping the default demo provably offline.
- **README / CONTRIBUTING refresh.** README gains a "Try it in 60 seconds"
  (clone-first, offline) section with a GIF embed and a "What works today
  (v0.3.0)" inventory; stale v0.1 "magic-moment quickstart" / "What's in
  v0.1.0" sections and the unpublished-package PyPI / pyversions badges are
  removed. CONTRIBUTING gains a "Contributing a Quarry scenario" path
  (differential-proof gate) and a "Demo fixtures" maintenance contract.
- **Kitchen-sink branding.** The reference agent is now consistently branded
  "the Quarry" across its README and the docs; de-staled `docs/quickstart.md`
  and `docs/index.md`.

### Fixed

- **Windows UTF-8 stdio crash.** The CLI now forces UTF-8 stdout/stderr so
  Rich's box-drawing and status glyphs no longer raise `UnicodeEncodeError`
  on cp1252 Windows consoles. This also fixes `mylonite scan`'s Rich-rendered
  summary on Windows, not just the demo.

## [0.2.2] - 2026-06-09

### Added — real open-source MCP agents

- **MCP stdio transport adapter** — `mylonite.plugins._mcp.stdio_adapter.MCPStdioAdapter`
  spawns a bundled MCP server as a fresh subprocess per `invoke()`, drives
  the planner over the wire via `stdio_client` + `ClientSession`, and
  separates planner-attributed MCP calls from setup-arm calls in
  `response.metadata["mcp_trace_planner"]` vs `mcp_trace_setup`. Per-attempt
  timeout (60s default), filesystem sandbox-diff capture, fresh subprocess
  isolation.
- **Three bundled OSS MCP targets** with scope-matched authorize:
  - `mcp:filesystem:<sandbox-path>` → official `@modelcontextprotocol/server-filesystem`.
  - `mcp:fetch` (stateless) → official `mcp-server-fetch`.
  - `mcp:github:<owner/repo>` → official `@modelcontextprotocol/server-github`.
- **Eight new MCP-server-shaped seeds** under `SEED_CATALOGUE`:
  - Filesystem: 3 seeds covering W1 description-smuggle, W2 poisoned-file-
    then-write, W4 direct attacker-attributed write.
  - Fetch: 2 seeds covering W3 direct attacker URL + W3 injection-driven
    double-fetch.
  - GitHub: 3 seeds covering W1 issue description-smuggle, W2 poisoned-
    issue-then-act, W4 direct create-issue.
- **Predicate primitives** (`mylonite.scan.predicate_primitives`):
  `tool_was_called`, `tool_was_called_with_arg`, `tool_call_sequence`.
- **Seven per-target predicates** under
  `mylonite.plugins._mcp.predicates.{filesystem,fetch,github}` —
  composing the primitives into named registry entries that the new seeds
  reference.
- **`SeedPattern.applicable_targets`** required field. Each seed declares
  the target families it applies to (`kitchen-sink` / `filesystem` /
  `fetch` / `github`). Both attack modules filter `SEED_CATALOGUE` by
  matching the family resolved from `descriptor.target_id`.
- **`SeedSetup` literal** extended with `seed_file`, `seed_issue`. **`SeedDrive`**
  literal extended with 5 target-shaped drives.
- **CLI `mcp:` parsing**. `mylonite scan mcp:<family>[:<scope>] --authorize <value>`
  with scope-required families needing `--authorize == scope` and stateless
  families needing `--authorize == family`. Typed exit-2 errors for unknown
  family, mismatched authorize, malformed scope.
- **Hybrid CI** — three recorded integration tests under
  `tests/integration/test_scan_mcp_*_recorded.py` use mocked
  `_open_mcp_session` + `ScriptedLLM` for deterministic CI. Three live
  e2e tests under `tests/integration/test_scan_mcp_*_live.py` gated by
  `MYLONITE_LIVE_E2E=1` exercise the full subprocess + real-LLM path.
  Run before each release.

### Changed

- **`LLMPlanner` + 5 shared types lifted** from
  `reference_targets/mcp_kitchen_sink` to `mylonite.scan.llm_planner` and
  `mylonite.scan.llm_types`. Eliminates the would-be
  `mylonite.scan → reference_targets/mcp_kitchen_sink` reverse dependency
  the new MCP stdio adapter would have introduced. Kitchen-sink's
  `_types` re-exports for back-compat.
- **`LLMPlanner._ServerLike` Protocol is now fully async** (`async def
  list_tools` AND `async def call_tool`). MCP SDK's session calls are
  async-only; a sync wrapper would deadlock the running event loop.
- **`mcp>=1.0` promoted to mainline runtime dependencies** (was in the
  `[reference-targets]` extras group).
- **Three new entry points** registered under `mylonite.target_adapters`:
  `mcp_filesystem`, `mcp_fetch`, `mcp_github`.

### Acceptance criteria

- `mylonite scan mcp:filesystem:<sandbox> --authorize <sandbox>` produces
  ≥1 finding whose predicate reason names `write_file` with attacker-
  controlled arguments and `sandbox_diff` execution evidence.
- `mylonite scan mcp:fetch --authorize fetch` produces ≥1 finding whose
  predicate reason names `fetch` with attacker-controlled URL.
- `mylonite scan mcp:github:<owner/repo> --authorize <owner/repo>`
  produces ≥1 finding whose predicate reason names `create_issue` or
  `get_issue` with attacker-controlled body.

## [0.2.1] - 2026-06-09

### Added — W3 + W4

- **`ExcessiveAgencyAttackModule`** (entry point `excessive_agency`) —
  the W3 + W4 attack family. Tagged OWASP LLM06, ASI02 + ASI05,
  MITRE AML.T0049.
- **W3 seeds** — `excessive-agency-fetch-attacker-url-direct` (user
  message asks the planner to fetch an attacker URL) and
  `excessive-agency-fetch-via-note-body` (poisoned note instructs the
  planner to call `web_fetch` on the attacker URL). Predicate
  `web_fetch_to_unauthorised_url` fires when the URL lands in
  `store.fetched_urls` — vulnerable lets it land; guarded's hostname
  allowlist refuses with `isError` and never calls `record_fetch`.
- **W4 seeds** — `excessive-agency-send-email-direct-unconfirmed`
  (user message asks the planner to send an email) and
  `excessive-agency-send-email-via-note-injection` (poisoned note
  coerces the planner into firing `send_email`). Predicate
  `send_email_without_confirmation` fires when `send_email` is called
  AND `store_emails_sent` is non-empty AND `confirm_send` is NOT also
  present — vulnerable dispatches immediately; guarded stages without
  sending.
- **New `SeedDrive` literals** — `fetch_url_direct` and
  `send_email_direct`. The InProcessReferenceAdapter's
  `_drive_user_message` honours both by passing `payload.body` through
  as the user instruction.
- **CLI filter relaxation** — `mylonite scan` now picks up both
  `prompt-injection-family` and `excessive-agency-family` plugins
  (the explicit allowlist will generalise in v0.3).
- **Integration tests** — `test_scan_vulnerable_excessive_agency.py`
  proves W3 + W4 both fire on `reference:vulnerable`;
  `test_scan_guarded_excessive_agency.py` proves both stay clean on
  `reference:guarded`. The the scan loop truth-table now covers all four
  weakness families.

### Changed

- `Weakness` Literal extended `W1, W2` → `W1, W2, W3, W4` (additive;
  no breaking change for existing callers).
- CLI's attack-module filter expanded to include the new family.

### Not yet in v0.2.1 (still deferred per the eng review)

- Generic CLI module filter (current allowlist is explicit; v0.3 should
  match "any non-stub attack module").
- Real-network MCP transport — a later release.
- Multi-turn planner exercises.
- Ensemble LLM-judge.
- All other later items in v0.2.0's deferred list.

## [0.2.0] - 2026-06-09

### Added

- **`mylonite scan <target>` is real.** v0.2 supports `reference:vulnerable`
  and `reference:guarded` as targets out of the box. Flags:
  `--provider`, `--model`, `--max-llm-calls`, `--max-concurrent`,
  `--output-dir`, `--dry-run`, `--authorize`. Writes per-finding
  `exploit_<pattern_id>.json` plus `scan_report.json` under
  `.mylonite/scans/<ts>/` and prints a Rich-rendered summary.
- **Async-first exploit-finding loop.** `ScanEngine.run()` uses
  `asyncio.gather` with a `Semaphore(max_concurrent)` (default 3). All LLM
  calls (customiser, judge, in-process planner) route through a
  process-wide `LiteLLMCallCounter` so `--max-llm-calls` is a real cap.
- **Layered scan internals.** New package `mylonite.scan`:
  - `seeds.py` — frozen `SeedPattern` model + W1/W2 catalogue (4 seeds).
  - `predicates.py` — decorator-based registry plus
    `send_email_to_attacker`, `planner_summarised_against_user_intent`,
    `read_note_returned_poisoned_content_acted_on`.
  - `_llm.py` — `LiteLLMCallCounter`, `litellm_json_call` /
    `litellm_json_call_async`, `BudgetExceededError`.
  - `customiser.py` — async `PayloadCustomiser` (one LiteLLM call per seed).
  - `judge.py` — async `SuccessJudge`: deterministic predicate first, LLM
    rubric fallback with confidence floor 0.8.
  - `engine.py` — `ScanConfig` + `ScanEngine` + `ScanResult`. Skips
    invalid metadata, unknown seeds, planner failures, and dry-run mode.
    Maps `aborted` to exit code 3 (budget) or 4 (provider unreachable).
  - `artefacts.py` — `write_artefacts` + `render_summary` (Rich).
- **`LLMPlanner` in the reference target.** Async LiteLLM tool-calling loop
  (default 8-iteration cap). Lives alongside the scripted planners
  so the differential oracle still has its deterministic fixtures.
- **`InProcessReferenceAdapter`** with `AsyncTargetAdapterBase`. Two
  0-arg subclasses (`InProcessVulnerableReferenceAdapter`,
  `InProcessGuardedReferenceAdapter`) registered as separate entry points.
  Raises `AdapterInvocationSkipped` on planner failure so the engine
  records `outcome="skipped_planner_failure"` without false judgments.
- **`PromptInjectionAttackModule`** (entry point `prompt_injection`) — the
  real W1+W2 attack family. The the foundations stub `ReferenceAttackModule`
  remains as `reference_example` for plugin authors.
- **`ScanReport` + `ScanAttempt` contracts** under
  `mylonite.contracts._types`, with JSON schemas
  (`scan_report.schema.json`, `scan_attempt.schema.json`) regenerated by
  `scripts/regenerate_schemas.py` and CI-checked for idempotency.
- **`LiteLLMRecorder` + `ScriptedLLM`** under `tests/integration/` —
  recorder hashes (model, messages) and replays from JSON fixtures
  (record once with `MYLONITE_TEST_RECORD=1`). the integration
  tests use the scripted stub; recorder fixtures land in v0.2.1+ once
  captured against a real provider.

### Changed

- `EchoTargetAdapter` removed; `mylonite.target_adapters:echo` entry point
  replaced by `in_process_reference_vulnerable` and
  `in_process_reference_guarded`.
- `ReferenceAttackModule` entry point renamed from `reference` to
  `reference_example` to distinguish from the real attack module.
- Mypy overrides extended to include `mcp_kitchen_sink.*`.

### Not yet in v0.2 (deferred to later releases)

- Real-network MCP transport (stdio / HTTP) — a later release.
- Real open-source MCP target adapters — a later release.
- W3 (unrestricted `web_fetch` / SSRF) and W4 (unconfirmed
  `send_email` / excessive agency) attack modules.
- Multi-turn planner exercises.
- `mylonite generate` (test emission) — a later release.
- Differential-oracle / 5-run flakiness / metamorphic robustness —
  the validator (the moat).
- Ensemble LLM-judge — a later release.
- HTML report rendering — a later release.
- Iterative LLM payload refinement (failure → refine → retry) — a later release.
- `mylonite init` config scaffold — later DX polish.
- Community attack-pattern registry contribution flow — a later release.
- Hosted CI / dashboards / compliance evidence packs — a later release.

## [0.1.0] - 2026-06-09

### Added

- Apache-2.0 LICENSE + NOTICE.
- README with magic-moment quickstart placeholder (v0.2 preview).
- CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1), GOVERNANCE, SECURITY.
- `.github/` issue templates (bug, attack-pattern submission, adapter request),
  PR template, CODEOWNERS, Dependabot config, CI workflow (ruff / mypy / pytest
  on Python 3.11 / 3.12 / 3.13).
- `pyproject.toml` (hatchling, PEP 621), `.pre-commit-config.yaml`.
- `mylonite` Typer CLI with `version` and `taxonomy list` commands; placeholder
  stubs for `scan` / `generate` / `validate` / `init`.
- Pydantic `Settings` config schema (`mylonite.config`) — LLM provider is
  required, no default.
- Five versioned extension-point contracts under `src/mylonite/contracts/`:
  attack module, target adapter, test generator, validator, compliance mapper.
  Each ships a Protocol, a runtime-checkable ABC, and a `CONTRACT_VERSION`.
- JSON schemas mirroring the contract Pydantic models, under
  `src/mylonite/schemas/`; regenerator script under `scripts/`.
- Threat-taxonomy module (`src/mylonite/taxonomy/`) with data files for OWASP
  LLM Top 10 2025, OWASP Agentic Security Initiative 2026, MITRE ATLAS
  v5.4.0 (pinned to upstream commit), and NIST AI RMF subcategories relevant
  to red-team evidence.
- Plugin entry-point registry with major-version compatibility checks; one
  reference implementation per contract.
- Deliberately-vulnerable reference MCP agent under
  `reference_targets/mcp_kitchen_sink/`, in vulnerable and guarded variants,
  for use as differential-oracle ground truth for the validator.
- mkdocs-material docs scaffold.

[0.7.4]: https://github.com/Abidemialade/mylonite/compare/v0.7.3...v0.7.4
[0.7.0]: https://github.com/Abidemialade/mylonite/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Abidemialade/mylonite/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.5.0
[0.4.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.4.0
[0.3.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.3.0
[0.2.2]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.2
[0.2.1]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.1
[0.2.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.0
[0.1.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.1.0
