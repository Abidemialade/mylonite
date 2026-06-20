# TODOs / Deferred items

Work intentionally deferred during prior phases, captured here so it isn't lost
in the local plan/review files. Each item notes its rationale and the phase or
trigger where it should land. This is a tracking doc, not a roadmap — see
[ROADMAP.md](./ROADMAP.md) for the phase plan.

## Phase 4 launch infrastructure (pre-launch readiness landed; these remain — human-gated)

The pre-Phase-4 readiness work (flow, verification legibility, correctness
safeguards, trust panel, precision/recall corpus, eval/CI export + declarative
config) has landed. The remaining launch items need a maintainer because they
depend on the local SSL/cert environment or on tagging a release:

- **PyPI first publish.** ✅ done — `mylonite` published to PyPI with **v0.7.0**
  (2026-06-18) via the Trusted-Publishing workflow
  ([`.github/workflows/release.yml`](./.github/workflows/release.yml): build →
  TestPyPI → PyPI); the TestPyPI + PyPI trusted publishers are registered.
  **Remaining:** `mcp-kitchen-sink` (the Quarry reference target) is not
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
