# TODOs / Deferred items

Work intentionally deferred during prior phases, captured here so it isn't lost
in the local plan/review files. Each item notes its rationale and the phase or
trigger where it should land. This is a tracking doc, not a roadmap — see
[ROADMAP.md](./ROADMAP.md) for the phase plan.

## 0.7.7 deep-code-review non-blocking findings (docs/reviews/2026-08-06-0.7.7-honest-results-review.md)

The two high-severity blockers (DCR-0005, DCR-0009) were fixed before merge. These are
the remaining medium/low findings from the same review, intentionally left for a
follow-up rather than expanding the 0.7.7 diff further. None are fail-opens; all are
either correctness gaps in already-correct-in-spirit code, or non-blocking performance.

- **`--target-file` silently overrides a non-`reference:`/non-`mcp:custom` positional
  `TARGET` in `scan()`** (originally DCR-0001/0.7.7 — `cli.py:1081`). **`gate()`'s
  equivalent instance is now fixed** (0.7.8's own deep-code-review, DCR-0001 —
  `cli.py:3487-3506`; the fix additionally covers the auto-discovered-`mylonite.yaml`
  case, not just an explicit `--target-file` flag). `scan()`'s is still open — same
  root cause, re-derives "did the operator mean `--target-file` or the positional
  argument" independently instead of sharing gate's now-fixed guard. **`gate()`'s
  custom-target `target_id` still drops the scope and diverges from `scan()`'s
  formula** (originally DCR-0004/0.7.7 — `cli.py:3593`, unchanged). *Trigger:* next
  patch release; candidate for a small `_resolve_target_and_file()` helper shared by
  both commands, since `gate()`'s new guard (0.7.8) is the pattern to replicate onto
  `scan()`.
- **`scan/engine.py`'s new exception redaction (0.7.8 DCR-0005) uses `redact(str(exc))`
  instead of the more defensive `redact_exception(exc)`** that already exists for this
  purpose (`_redaction.py:294-317`) — `redact_exception` also catches a pydantic
  `ValidationError`'s raw `input_value`, which `redact()`'s pattern set doesn't
  structurally guarantee catching. Currently low-risk (no `ValidationError` is raised
  inside the customiser/adapter/judge call chains these 3 sites wrap today), but a
  third-party plugin constructing a contract object there could raise one. *Trigger:*
  next patch release; not a drop-in swap since `redact_exception` prepends
  `type(exc).__name__:` — needs a shared helper so the two "make exception text safe to
  persist" call sites don't drift.
- **`_first_balanced_object` can silently pick an earlier draft JSON object over the
  model's real final answer** in prose-only response mode (DCR-0006 — `scan/_llm.py:231`).
  Only reachable when `build_response_format` degrades to prose (a model with no native
  JSON mode). *Trigger:* next patch release.
- **`DifferentialValidator`'s independent live re-drive loops run sequentially instead
  of concurrently**, across four call sites (DCR-0016 through DCR-0019 —
  `reference_validator.py:422,527,620,1061`) plus one quarantined-but-likely-real sibling
  in `ablation.py:285` (`run_control_ablation`, evidence didn't verbatim-match at review
  time — needs a human re-check, not dismissed). At default `--iterations 5`, a
  `validate` run against a guarded custom target costs roughly 17x a single scan's
  wall-clock instead of something closer to `max_concurrent`-bounded. *Trigger:*
  performance follow-up, not correctness-blocking; consolidate into one
  concurrency-bounded runner rather than four point fixes.
- **Metamorphic mislabeling**: a `vuln_fired=True` + guarded-adapter-error combination is
  classified `attack_malformed`, contradicting the branch's own comment (DCR-0011 —
  `reference_validator.py:1070`). **Guard-resisted count treats adapter errors/timeouts
  as genuine resistance** on the custom-target differential leg (DCR-0012 — `:677`).
  Both narrow the meaning of a `validate` verdict in an edge case; low-frequency but
  worth fixing before either metric is used unattended in CI. *Trigger:* next patch
  release, alongside DCR-0006.
- **Plugin entry-point discovery re-runs with no caching** on every custom-target
  validate iteration (DCR-0020 — `reference_validator.py:739`) and every ablate
  `scan_target_fires` call (quarantined finding, `ablation.py:476`, since demoted to
  false-positive on adjudication — amortised against minutes of LLM latency, not worth
  fixing on its own).

## 0.7.9 deep-code-review non-blocking findings (docs/reviews/2026-08-07-0.7.9-any-provider-review.md)

The review's 5 blockers (DCR-0001/0002/0003/0004/0006, 3 critical + 2 high — a
pervasive console-redacted-but-disk-persisted-unredacted gap, an auto-discovered
`mylonite.yaml` `api_base` SSRF/key-exfil path, and a silently-incomplete gating
formula) were fixed before merge (commit `79a4c68`), independently re-verified via a
red→green checkout cycle against the pre-fix source, not just re-run. Two
low-confidence findings from the same review (DCR-0005 credential-preflight,
DCR-0006 system-prompt-in-GitHub-annotation) were investigated and REFUTED with
regression tests locking in the correct behavior — see the review doc and commit
message for the full trace. The `gate mcp:<family>` route (DCR-0014/0015, medium
severity but a real regression in a documented CLI path) was also fixed in the same
pass since it's correlated with the redaction work and blocks the release's own
headline feature otherwise. These are the remaining medium/low findings, deferred
rather than expanding the 0.7.9 diff further:

- **`_load_api_key_file`'s bare-key mode picks the first whitespace-split token of
  the WHOLE file, not the key's own line** (DCR-0009 — `cli.py:267`). A file shaped
  `# my key\nsk-ant-abc123` (comment line + bare key) yields `key = "#"` instead of
  the real key, failing `_infer_key_env_var` and exiting `EXIT_CONFIG` even though a
  valid key is present. *Trigger:* next patch release; fix is small (derive from the
  first non-comment, non-blank line).
- **`scan mcp:<family> --target-file other.yaml` silently ignores the positional
  target** (DCR-0010 — `cli.py:1306`), scanning `other.yaml`'s target instead with no
  error — the symmetric `reference:` + `--target-file` case is explicitly rejected two
  lines above for the same reason. *Trigger:* next patch release; extend that guard to
  any non-`mcp:custom` positional target.
- **`_relative_sqlite_env_keys`'s unanchored `"sqlite" in low` substring match**
  misclassifies a non-SQLite URL whose hostname merely contains "sqlite" (e.g.
  `postgresql://sqlite-cache.internal:5432/app`) as a relative SQLite path warning
  (DCR-0011 — `cli.py:3243`). Cosmetic false-positive only. *Trigger:* next patch
  release; match against the URL scheme, not a bare substring.
- **`ScanConfig.provider_failure_threshold` has no lower-bound validation**, unlike
  `max_concurrent` (`Field(ge=1)`) (DCR-0012 — `scan/engine.py:331`). A
  `provider_failure_threshold=0` config aborts a scan after the very first attempt
  regardless of outcome. *Trigger:* next patch release; add the same `Field(ge=1)`
  guard.
- **`ScanEngine._process_one`'s `seed_id = payload.metadata.get("seed_id") or
  payload.pattern_id` uses truthy-`or`, not an `is None` check** (DCR-0013 —
  `scan/engine.py:437`), so a present-but-empty `seed_id` silently falls back to
  `pattern_id` for compliance provenance. *Trigger:* next patch release.
- **Reference-target `validate` never threads `--iteration-timeout` into
  `DifferentialValidator`**, unlike the custom-target branch (DCR-0007 —
  `cli.py:2906`) — a stalled provider call on the reference path can hang the CLI/CI
  job indefinitely. **`_post_gate_annotations`'s `post_check_run` call has no visible
  timeout** either (DCR-0008 — `cli.py:3614`), same hang class. *Trigger:* next patch
  release; both are one-line timeout threading fixes.
- **`_MCPAttackSession.drive_planner`'s effect-probe body falls back to an incidental
  (non-payload) planted string** when no real payload was planted short enough to skip
  `_MIN_PLANTED_PAYLOAD_CHARS` (DCR-0018 — `_session_adapter.py:895`), reintroducing
  the false-negative shape a prior fix (referenced in-repo as DCR-0006) closed for a
  different code path — silently under-reports confirmed exploits. **The delivery
  check pulls in the opposite direction**: it matches on ANY planted string arg
  (ids/paths/titles), not just payload-shaped content (DCR-0020 —
  `_session_adapter.py:889`), over-reporting delivery when an incidental filename
  happens to reappear in unrelated planner output. Both stem from tracking planted
  content in one generic list instead of a payload-typed subset, and share a fix
  shape (use the payload-shaped list in both places). *Trigger:* next patch release —
  this pair directly affects Mylonite's own detection precision/recall, prioritize
  ahead of the others in this section.
- **`_render_seed_args`'s chained `.replace("{payload}", ...).replace("{scope}", ...)`
  lets a payload containing the literal substring `{scope}` get silently re-mutated**
  by the second substitution (DCR-0019 — `_session_adapter.py:166`), so the actually
  planted content can diverge from `payload.body`, breaking downstream delivery-token
  matching. *Trigger:* next patch release; substitute both placeholders in one pass.
- **`_extract_first_number` runs an unbounded synchronous `re.search` directly on the
  event loop** inside `async def _run_setup`/`_run_seed_arm`, with no size cap unlike
  every other tool-result read in the file (DCR-0021 — `_session_adapter.py:1040`) —
  a large target-controlled result blocks every concurrently in-flight scan attempt.
  *Trigger:* next patch release; cap length and/or run via
  `run_in_executor`/`asyncio.to_thread`, matching `_bounded_regex_search`'s existing
  pattern in the same file.
- **`scripts/record_provider_fixtures.py`'s `_main` awaits each provider recording
  sequentially** instead of concurrently (DCR-0024, low — maintainer-run tooling, not
  production path). *Trigger:* quality-of-life only, no forcing trigger.
- **One high-severity finding was quarantined by the verification gate** for evidence
  spanning 4 lines against `verify.py`'s 3-line cap — confirmed genuinely verbatim,
  not noise (the original DCR-0007/0.7.9-review numbering, generate's
  `_emit_generated_test` colocated-exploit write — **this one was in fact fixed** as
  part of the redaction-gap coordinated pass in `79a4c68`, so no follow-up needed;
  noted here only so the quarantine event has a paper trail).
- **`scan/_llm.py` (the T14 LLM chokepoint, 842 lines) and
  `plugins/_reference/reference_target_adapter.py` were only swept, not
  deep-reviewed**, despite security-sensitive surface tags — risk-ranking scored them
  below this run's economy-profile deep-review cutoff. *Trigger:* a future
  `thorough`-profile review should reconsider both.

## Phase 4 launch infrastructure (pre-launch readiness landed; these remain — human-gated)

The pre-Phase-4 readiness work (flow, verification legibility, correctness
safeguards, trust panel, precision/recall corpus, eval/CI export + declarative
config) has landed. The remaining launch items need a maintainer because they
depend on the local SSL/cert environment or on tagging a release:

- **PyPI first publish.** ✅ done — `mylonite` published to PyPI with **v0.7.0**
  (2026-06-18) via the Trusted-Publishing workflow
  ([`.github/workflows/release.yml`](./.github/workflows/release.yml): build →
  TestPyPI → PyPI); the TestPyPI + PyPI trusted publishers are registered.
  **Remaining:** `mcp-kitchen-sink` (the reference app target) is not
  published, so the `mylonite demo` walkthrough is still clone-first — see the
  Phase 4 item below.
- **Demo GIF + reference-validation example.** See the two items below — both are
  blocked on the live SSL/cert environment (Norton HTTPS inspection /
  `SSL_CERT_FILE`) and are maintainer-run.
- **Precision/recall corpus is wired into CI** ([`ci.yml`] runs
  `scripts/measure_precision_recall.py` and uploads `corpus_report.json`); the
  asserted numbers live in `tests/corpus`. ✅ done.
- **Custom-target flow is regression-guarded** end-to-end
  (`tests/test_cli.py::test_custom_target_flow_needs_target_file_at_most_once`:
  scan → generate → export needs `--target-file` at most once). ✅ done.

## Phase 2 finishing touches (v0.4.0 shipped; these remain)

- **Record the committed reference-validation example.** Run
  [`scripts/record_reference_example.py`](./scripts/record_reference_example.py)
  with `ANTHROPIC_API_KEY` to produce `examples/reference_validation/` — the live
  W2 `exploit_*.json`, the recorded guarded `fixtures/` + `_meta.json`, and the
  emitted test. **Blocked on the live SSL/cert environment issue** (LiteLLM's
  HTTPS calls fail `CERTIFICATE_VERIFY_FAILED` on this machine): needs a Norton
  HTTPS-inspection exclusion, or `SSL_CERT_FILE` pointed at certifi's bundle,
  before the run will reach the provider. Once recorded, the example replays
  **offline** forever (analogous to the demo fixtures), and a committed offline
  test asserting it passes can be added. Human step.

## Phase 1.5 finishing touches (v0.3.0 shipped; these remain)

- **Record the demo GIF** → `docs/assets/quarry-demo.gif`. The recording script
  is ready at [`docs/assets/recording-script.md`](./docs/assets/recording-script.md);
  it needs a terminal recorder (terminalizer, or asciinema + agg). Human step.
  The README already embeds the path as a placeholder.

## Deferred to later phases (from the v0.3.0 review)

- **`--save` / `--out` demo artefact flag** — write the demo's differential
  report to disk. The demo is side-effect-free by design; add only on demand.
  *Trigger:* user request.
- **GitHub Codespaces / devcontainer one-click demo** — a zero-install,
  open-in-browser funnel that runs `mylonite demo`. Strong top-of-funnel asset,
  separate scope from the CLI. *Trigger:* Phase 4 launch prep.
- **PyPI publishing of `mcp-kitchen-sink`** (and a possible `mylonite-quarry`
  distribution rename). `mylonite` itself is now on PyPI (v0.7.0); the reference
  target is not, so the "60-second" demo promise is still clone-first until it
  ships. *Trigger:* Phase 4 launch.
- **Phase 2 walking skeleton before the public demo** — a thin end-to-end
  `scan → generate → validate` slice to de-risk the demo timeline.
  *Trigger:* Phase 2 sequencing decision.

## Rejected (recorded so they aren't re-raised)

- **`--variant` single-side demo flag** — the vulnerable-vs-guarded differential
  *is* the demo; a single-side view undercuts the point.
- **asciinema `.cast` as a second committed artifact** — the GIF is the single
  recording artifact.
- **Fresh-venv wheel-install CI job** — `ci.yml` stayed frozen for v0.3.0;
  packaged-fixture loading is proven by the recorded e2e plus a one-off
  wheel-content check.
