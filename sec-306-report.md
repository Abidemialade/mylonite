# sec-306: discovery workflow leaves a write credential in `.git/config` (#306)

## Contracts

No. `src/mylonite/contracts/_types.py` untouched; no `CONTRACT_VERSION` bump needed.

## What changed

`src/mylonite/gate/templates/mylonite-discovery.yml` was the only emitted
template with this shape (checked `mylonite-gate.yml`, the only other
template — it already sets `persist-credentials: false` and never pushes;
`gate-action/action.yml` does no checkout of its own, so it's out of scope).

- The checkout step now sets `persist-credentials: false`, matching
  `mylonite-gate.yml`'s existing pattern. Removed the now-unneeded
  `zizmor: ignore[artipacked]` justification comment.
- The one job step that both runs the target (via `mylonite gate`) and
  pushes the gate branch now runs `gh auth setup-git` first. That points
  git's credential helper at `gh`, which reads the already step-scoped
  `GH_TOKEN` only at the moment `git push` actually needs a token, instead
  of a static write-capable credential sitting in `.git/config` for the
  whole ~45-minute job.
- Updated comments explaining the new flow.

## Files touched

- `src/mylonite/gate/templates/mylonite-discovery.yml`
- `tests/gate/fixtures/no_secrets_render/mylonite-discovery.yml` (regenerated vendored render)
- `tests/gate/test_workflows.py` (new tests)
- `docs/ci-gating.md`
- `CHANGELOG.md`

## Tests added

- `tests/gate/test_workflows.py::test_emitted_workflows_never_persist_a_write_credential_past_checkout[mylonite-gate.yml]`
- `tests/gate/test_workflows.py::test_emitted_workflows_never_persist_a_write_credential_past_checkout[mylonite-discovery.yml]`
- `tests/gate/test_workflows.py::test_discovery_workflow_authenticates_its_push_with_gh_instead_of_a_persisted_credential`

The first is parametrized over `_TEMPLATES`, so a future third template with
the same shape is covered automatically.

## Check results

- `pytest tests/gate -q`: 443 passed, 2 skipped
- `pytest tests/gate/test_workflows.py -q`: 55 passed
- Full suite, keys unset (`env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GEMINI_API_KEY -u MYLONITE_API_KEY -u MYLONITE_LLM_KEY ... pytest -q -n auto`): **5442 passed, 21 skipped**
- `ruff check .`: all checks passed
- `mypy src`: no issues found in 145 source files
- `mkdocs build --strict`: built clean
- `scripts/check_docs_sync.py --base origin/main --ci`: docs in sync
- Offline e2e (`MYLONITE_OFFLINE_E2E=1 pytest tests/e2e/test_offline_deep_path.py tests/corpus tests/test_llm_call_count.py -q`): 23 passed, 1 skipped
- `zizmor`: not on `PATH` for a standalone run, but the pre-commit hook's own `zizmor` check ran as part of the commit below and passed.

## Snapshot changes

None of the listed shared files (exit codes, reason codes, testkit signature,
`command_tree.json`, golden snapshots) changed. The vendored
`tests/gate/fixtures/no_secrets_render/mylonite-discovery.yml` fixture did
change — it's a gate-specific vendored render fixture, not one of the
listed shared snapshots, but flagging it since it's a byte-for-byte golden
comparison.

## Anything not done / to look at hard

- The push and the target launch still happen inside the same shell step
  (the existing `mylonite gate --target-file ... --open-pr` single
  invocation does discovery, generate, validate, and the git/gh flow
  together) — there was no later, separate step to scope a push-only
  credential to. The fix instead removes the only persisted credential
  value from disk entirely and defers actual token retrieval to `git
  push`'s invocation of the `gh` credential helper, which happens after
  the target process has already stopped (discovery/generate/validate
  completes before `open_or_print_pr`'s commit/push runs). This matches
  the ledger report's own "smallest general fix" recommendation (size S,
  template-only).
