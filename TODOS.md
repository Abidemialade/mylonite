# TODOs / Deferred items

Work intentionally deferred during prior phases, captured here so it isn't lost
in the local plan/review files. Each item notes its rationale and the phase or
trigger where it should land. This is a tracking doc, not a roadmap — see
[ROADMAP.md](./ROADMAP.md) for the phase plan.

## Phase 1.5 finishing touches (v0.3.0 shipped; these remain)

- **Record the demo GIF** → `docs/assets/quarry-demo.gif`. The recording script
  is ready at [`docs/assets/recording-script.md`](./docs/assets/recording-script.md);
  it needs a terminal recorder (terminalizer, or asciinema + agg). Human step.
  The README already embeds the path as a placeholder.
- **Tag `v0.3.0`** once the GIF is committed — matches the prior release tagging
  (v0.1.0–v0.2.2 are all tagged) and the master plan's "GIF then tag" sequence.

## Deferred to later phases (from the v0.3.0 review)

- **`--save` / `--out` demo artefact flag** — write the demo's differential
  report to disk. The demo is side-effect-free by design; add only on demand.
  *Trigger:* user request.
- **GitHub Codespaces / devcontainer one-click demo** — a zero-install,
  open-in-browser funnel that runs `mylonite demo`. Strong top-of-funnel asset,
  separate scope from the CLI. *Trigger:* Phase 4 launch prep.
- **PyPI publishing** of `mylonite` and `mcp-kitchen-sink` (and a possible
  `mylonite-quarry` distribution rename). Until then the "60-second" promise is
  honestly clone-first. *Trigger:* Phase 4 launch.
- **Phase 2 walking skeleton before the YC demo** — a thin end-to-end
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
