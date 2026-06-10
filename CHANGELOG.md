# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Abidemialade/mylonite/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.3.0
[0.2.2]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.2
[0.2.1]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.1
[0.2.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.2.0
[0.1.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.1.0
