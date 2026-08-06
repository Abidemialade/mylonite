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
  `TARGET`, in both `scan()` and `gate()`** (DCR-0001, DCR-0003 — `cli.py:1081`,
  `:3530`), and **`gate()`'s custom-target `target_id` drops the scope and diverges
  from `scan()`'s formula** (DCR-0004 — `cli.py:3604`). Same root cause: both commands
  independently re-derive "did the operator mean `--target-file` or the positional
  argument" instead of sharing one resolution function — the exact fail-open class this
  release exists to close, just found too late in review to fold into this diff without
  re-triggering full verification. *Trigger:* next patch release; candidate for a small
  `_resolve_target_and_file()` helper shared by both commands.
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
