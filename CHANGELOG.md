# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Expanded metamorphic robustness check (report-only).** The
  `DifferentialValidator` metamorphic stage now applies MULTIPLE deterministic
  perturbation strategies to the exploit body — `paraphrase`, `casing`,
  `whitespace`, and `unicode` (fullwidth confusables) — each a pure
  `body -> body` string transform (no LLM, no randomness), re-running the
  differential check once per strategy. The stage reports a ROBUSTNESS fraction
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

[Unreleased]: https://github.com/Abidemialade/mylonite/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.4.0
[0.3.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.3.0
[0.2.2]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.2
[0.2.1]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.1
[0.2.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.0
[0.1.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.1.0
