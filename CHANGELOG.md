# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Multi-step `AttackSession` adapter capability** (target-adapter contract
  `0.3.0` → `0.4.0`, additive). Optional `SupportsAttackSession.open_session()`
  returns an `AttackSession` exposing raw `call_tool` + `drive_planner` +
  `close`, letting an attack loop carry target state across steps. Implemented
  for the in-process reference adapter; single-shot adapters are unaffected.

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

### Added — Pre-Phase-4 readiness: flow + verification legibility

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

### Added — Phase 3: CI gating + the magic moment

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

### Added — Phase 2 "the validation engine" (scan → generate → validate)

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
  `None`, so the change is backward-compatible. These make the Phase 2 validation
  engine's two headline numbers headline-able, chart-able, and CI-gate-able.

### Changed

- **Validator contract bumped `0.1.0 → 0.2.0`** (minor, backward-compatible — the
  two new fields above are optional with defaults). This is a `contract-change`
  per `GOVERNANCE.md`.
- **CI gains a Windows leg.** A `windows-latest` job runs the suite so the
  pytest-runner / emitted-test / testkit-replay paths are exercised on the
  platform contributors most often hit cp1252 / path-separator surprises on.

## [0.3.0] - 2026-06-10

### Added — Phase 1.5 "the Quarry" playground

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

### Added — Phase 1 truly complete (real OSS MCP agents)

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

### Acceptance criteria — Phase 1 truly complete

- `mylonite scan mcp:filesystem:<sandbox> --authorize <sandbox>` produces
  ≥1 finding whose predicate reason names `write_file` with attacker-
  controlled arguments and `sandbox_diff` execution evidence.
- `mylonite scan mcp:fetch --authorize fetch` produces ≥1 finding whose
  predicate reason names `fetch` with attacker-controlled URL.
- `mylonite scan mcp:github:<owner/repo> --authorize <owner/repo>`
  produces ≥1 finding whose predicate reason names `create_issue` or
  `get_issue` with attacker-controlled body.

## [0.2.1] - 2026-06-09

### Added — Phase 1 completion (W3 + W4)

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
  `reference:guarded`. The Phase 1 truth-table now covers all four
  weakness families.

### Changed

- `Weakness` Literal extended `W1, W2` → `W1, W2, W3, W4` (additive;
  no breaking change for existing callers).
- CLI's attack-module filter expanded to include the new family.

### Not yet in v0.2.1 (still deferred per the eng review)

- Generic CLI module filter (current allowlist is explicit; v0.3 should
  match "any non-stub attack module").
- Real-network MCP transport — still Phase 1.5 / 2 territory.
- Multi-turn planner exercises.
- Ensemble LLM-judge.
- All other Phase 2+ items in v0.2.0's deferred list.

## [0.2.0] - 2026-06-09

### Added — Phase 1

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
  (default 8-iteration cap). Lives alongside the scripted Phase 0 planners
  so Phase 2's differential oracle still has its deterministic fixtures.
- **`InProcessReferenceAdapter`** with `AsyncTargetAdapterBase`. Two
  0-arg subclasses (`InProcessVulnerableReferenceAdapter`,
  `InProcessGuardedReferenceAdapter`) registered as separate entry points.
  Raises `AdapterInvocationSkipped` on planner failure so the engine
  records `outcome="skipped_planner_failure"` without false judgments.
- **`PromptInjectionAttackModule`** (entry point `prompt_injection`) — the
  real W1+W2 attack family. The Phase 0 stub `ReferenceAttackModule`
  remains as `reference_example` for plugin authors.
- **`ScanReport` + `ScanAttempt` contracts** under
  `mylonite.contracts._types`, with JSON schemas
  (`scan_report.schema.json`, `scan_attempt.schema.json`) regenerated by
  `scripts/regenerate_schemas.py` and CI-checked for idempotency.
- **`LiteLLMRecorder` + `ScriptedLLM`** under `tests/integration/` —
  recorder hashes (model, messages) and replays from JSON fixtures
  (record once with `MYLONITE_TEST_RECORD=1`). Phase 1's integration
  tests use the scripted stub; recorder fixtures land in v0.2.1+ once
  captured against a real provider.

### Changed

- `EchoTargetAdapter` removed; `mylonite.target_adapters:echo` entry point
  replaced by `in_process_reference_vulnerable` and
  `in_process_reference_guarded`.
- `ReferenceAttackModule` entry point renamed from `reference` to
  `reference_example` to distinguish from the real attack module.
- Mypy overrides extended to include `mcp_kitchen_sink.*`.

### Not yet in v0.2 (deferred to v0.2.1 or later phases)

- Real-network MCP transport (stdio / HTTP) — Phase 1.5 or 2.
- Real open-source MCP target adapters — Phase 1.5.
- W3 (unrestricted `web_fetch` / SSRF) and W4 (unconfirmed
  `send_email` / excessive agency) attack modules.
- Multi-turn planner exercises.
- `mylonite generate` (test emission) — Phase 2.
- Differential-oracle / 5-run flakiness / metamorphic robustness —
  Phase 2 (the moat).
- Ensemble LLM-judge — Phase 2+.
- HTML report rendering — Phase 4.
- Iterative LLM payload refinement (failure → refine → retry) — Phase 5.
- `mylonite init` config scaffold — Phase 3 DX polish.
- Community attack-pattern registry contribution flow — Phase 4.
- Hosted CI / dashboards / compliance evidence packs — Phase 6.

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
  for use as differential-oracle ground truth in Phase 2.
- mkdocs-material docs scaffold.

[Unreleased]: https://github.com/Abidemialade/mylonite/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.5.0
[0.4.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.4.0
[0.3.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.3.0
[0.2.2]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.2
[0.2.1]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.1
[0.2.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.0
[0.1.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.1.0
