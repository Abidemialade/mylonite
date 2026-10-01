# Contributing to Mylonite

Thank you for considering a contribution. Mylonite is an Apache-2.0 open-source
project; see [GOVERNANCE.md](./GOVERNANCE.md) for how decisions are made and
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for the behaviour we expect.

This guide covers:

1. Setting up a dev environment
2. The five extension points and how to author a plugin
3. PR conventions (Conventional Commits, DCO)
4. The community attack-pattern registry flow (planned) and reference-app scenarios (live today)
5. Reporting security issues (link to `SECURITY.md`)

## Dev setup

Requirements:

- Python 3.11–3.14 (all four are CI-tested)
- `git`
- Optionally `bun` for some auxiliary scripts

Clone and install in editable mode with dev extras:

```bash
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

Run the local quality gates the same way CI does:

```bash
ruff check .
ruff format --check .
mypy src
pytest -n auto --dist worksteal --cov=mylonite
```

`-n auto` runs the suite across your CPU cores (it takes about a third of the
serial time). Plain `pytest` still works, and is easier to read when you are
debugging one failing test.

In CI, a pull request that changes only docs (`docs/`, top-level Markdown,
`mkdocs.yml`, the issue and PR templates) runs the suite once, on Linux with
Python 3.12. Any other change also runs 3.11, 3.13, 3.14 and Windows.

`pre-commit run --all-files` runs all of the above plus file hygiene.

## Authoring a plugin

Mylonite has five **versioned extension points**, each defined as a Python
`Protocol` (and a runtime-checkable ABC) under `src/mylonite/contracts/`:

| Extension point      | Purpose                                                            | Module                                  |
| -------------------- | ------------------------------------------------------------------ | --------------------------------------- |
| Attack module        | Generates app-specific attack payloads                             | `contracts/attack_module.py`            |
| Target adapter       | Speaks to a target system (MCP, RAG, HTTP, …)                      | `contracts/target_adapter.py`           |
| Test generator       | Emits a regression test (pytest today; the contract allows jest) from a confirmed exploit | `contracts/test_generator.py`           |
| Validator / scorer   | Decides whether a generated test is meaningful                     | `contracts/validator.py`                |
| Compliance mapper    | Tags a confirmed exploit with OWASP/ASI/ATLAS/NIST IDs             | `contracts/compliance_mapper.py`        |

Each contract module exports a `CONTRACT_VERSION` semver string. The plugin
loader in `src/mylonite/plugins/registry.py`:

- **refuses** to load a plugin whose declared `contract_version` differs in
  *major* version from the host,
- **warns** on minor mismatches,
- ignores patch differences.

To ship a plugin as its own pip-installable package, register it under one
of the entry-point groups in your own `pyproject.toml`:

```toml
[project.entry-points."mylonite.attack_modules"]
my_attack = "my_package.module:MyAttackModule"
```

The five entry-point groups are:

- `mylonite.attack_modules`
- `mylonite.target_adapters`
- `mylonite.test_generators`
- `mylonite.validators`
- `mylonite.compliance_mappers`

See `src/mylonite/plugins/_reference/` for minimal reference implementations
and `docs/plugin-authoring.md` for the long-form walkthrough.

## PR conventions

- **Conventional Commits.** Titles follow `type(scope): summary` — e.g.
  `feat(contracts): add async target adapter variant` or
  `fix(taxonomy): correct LLM06 cross-reference`. The CHANGELOG is **not**
  generated from these — it is hand-written, which is why the changelog entry is
  its own item below rather than a side effect of the title.
- **DCO sign-off.** Every commit must be signed off (`git commit -s`),
  asserting the contribution complies with the
  [Developer Certificate of Origin](https://developercertificate.org/).
- **Tests.** New code lands with tests. Bug fixes land with a regression test.
- **Docs.** Public API additions update `docs/` and the relevant module
  docstrings.
- **Changelog.** User-visible changes update `CHANGELOG.md` under
  `## [Unreleased]`.
- **Writing.** Docs, changelog entries, commit messages and pull requests
  follow [the writing style guide](docs/contributing/writing-style.md): lead
  with what changes for the reader, show the proof, state limits once.
- **Docs stay in sync.** The `Docs and writing` CI job fails when code changes
  without a changelog entry, when a user-facing module changes without its doc
  page, or when the title or description misses the required format. If a
  change needs no docs, say why in the description:
  `Docs-Impact: none - <reason>`. Run the same checks locally with
  `python scripts/check_docs_sync.py --base origin/main` and
  `python scripts/check_prose.py --diff-base origin/main`. `Docs and writing`
  is a required check, and maintainers do not use an admin merge to get past it
  while it is red: fix the cause, or add the opt-out line with a real reason.
- **Contract changes** (touching any file under `src/mylonite/contracts/`)
  need an issue tagged `contract-change` open for at least a week — see
  `GOVERNANCE.md`.

## Updating a frozen snapshot

A handful of public, stability-promised surfaces are pinned by a JSON
snapshot under `tests/fixtures/`, so a drift fails a test instead of shipping
unnoticed: reason codes (`reason_codes.snapshot.json`), the `mylonite.testkit`
function signatures and error types that emitted tests import by name
(`testkit_signatures.snapshot.json`), the CLI's process exit codes
(`exit_codes.snapshot.json`), and the checked-in JSON schemas together with
the five extension contracts' `CONTRACT_VERSION` values
(`schema_versions.snapshot.json`).

These are meant to change — that's how a reviewed, intentional addition or
break ships — just never by accident. When a test tells you a snapshot is
out of date:

1. Confirm the change is intentional (read the failing assertion; it names
   what moved).
2. Regenerate: `python scripts/update_snapshots.py`. It rewrites
   `testkit_signatures.snapshot.json`, `exit_codes.snapshot.json`, and
   `schema_versions.snapshot.json` from the live code — it never touches
   `reason_codes.snapshot.json`, which has its own regeneration path (see
   `tests/test_reason_codes.py`).
3. Review the diff. `git diff tests/fixtures/` should show exactly the
   surface you meant to change.
4. Add a `CHANGELOG.md` entry describing the change.
5. Ask a maintainer to add the `snapshot-change` label to the pull request.
   `scripts/check_snapshot_changes.py` (run in the `Docs and writing` CI job)
   fails a changed snapshot without both that label and a `CHANGELOG.md`
   entry in the same diff — the label is a maintainer's own action, so a
   contributor's commit message alone can't opt out.

## Fixing a docs-registry ratchet failure

`tests/test_docs_registry_ratchet.py` checks three registries against their
docs page, both ways: every live CLI flag, `mylonite.testkit` name, or
reason code has a mention in its page (`docs/cli-reference.md`,
`docs/validation.md`, `docs/reason-codes.md`), and every flag/name/code
those pages mention actually exists. A run that fails names the gap as
`undocumented:<thing>` (real, but not written down) or `stale-doc:<thing>`
(written down, but no longer real — a renamed or removed flag/name/code).

1. Fix the cause for real: add the missing flag/name/code to the page, or
   remove the stale mention. This is always the preferred outcome.
2. If the page genuinely can't say it yet (good reason required — "forgot"
   doesn't count), add an entry to `tests/fixtures/docs_ratchet_allowlist.json`
   under the named registry: `{"key": "<the gap string>", "reason": "..."}`.
3. Raise that registry's ceiling in `_CEILINGS` (same file as the test) by
   exactly the number of entries you added, in the same PR as the new
   entry. The ceiling may only shrink otherwise — this is the one deliberate
   exception, and it is reviewable in the diff.
4. If a doc edit fixed a gap that was previously allowlisted, delete that
   entry and lower the ceiling in the same PR — a stale entry fails its own
   test (`test_allowlist_entries_are_not_stale`).

## No-regression checks

The `nr-ci` job runs on every PR and push to main, docs-only changes
included — it has no path filter, so it is safe to treat as a required
check. It is the first layer of the no-regression gate; the second layer
is described under "Offline deep path, corpus and call counts" below.
`nr-ci` checks four things:

- **CLI goldens.** `pytest tests/cli_golden -q` pins the command tree
  (every flag, default and help string), the `scan --dry-run` seed
  listings, and the offline demo replay's output and exit code. A
  deliberate CLI change regenerates the matching file under
  `tests/cli_golden/goldens/` and explains the diff in the PR; see
  `test_cli_golden.py`'s module docstring for how the goldens are captured
  and why box-drawing glyphs and elapsed-time text are normalised out of
  the comparison.

  There is no `verdicts.json` golden here. That sidecar is written only
  when an attempt is decided by the trace rule or the target carries a
  calibration summary (`mylonite.scan.artefacts._has_class_summary`) — by
  design, a reference, REST or replayed scan (which is what the offline
  demo runs) has neither, so the demo replay never produces one. The only
  path in the repository that does produce one offline is the full
  scripted-session harness in `tests/integration/test_issue217.py`
  (a behavioural MCP session fake plus a scripted planner/judge, no network
  and no model call) — not a "cheap" path to turn into a second golden
  here, so this is recorded as a known gap rather than worked around with
  an invented shortcut.

- **No hardcoded provider model or credential env var.**
  `python scripts/check_no_hardcoded_models.py` greps every `*.py` file
  under `src/mylonite` for a provider-prefixed model literal (`claude-`,
  `gpt-`, `gemini-`, `ollama/`, `anthropic/`, `openai/`, `bedrock/`) or a
  provider credential env var (recognised the same way
  `mylonite.scan.providers.looks_like_provider_env_var` recognises one).
  `mylonite.scan.providers` is the one registry allowed to name either; a
  hit anywhere else fails unless it is listed in
  `scripts/hardcoded_models_allowlist.txt`, one line per entry:
  `<path> | <matched text or a stable regex> | <count> | <reason>`.

  Matching is by **file content, not line number** — a row says "this
  pattern is expected to appear `<count>` times somewhere in this file",
  never which line. An earlier, line-keyed version broke on any unrelated
  edit above a flagged line (it shifted every line number below it), which
  would fail this check on a change that never touched the flagged text —
  exactly the kind of failure a required check must not have. The check
  now fails only when a match has no covering entry at all, when a
  covered pattern matches *more* than its entry's count (a new,
  unreviewed occurrence alongside the excused ones), or when an entry's
  pattern no longer matches anything in its file (stale — delete or fix
  it). The list may only shrink — a unit test in
  `tests/test_check_no_hardcoded_models.py` pins today's row count and the
  sum of every row's count as ceilings; lower them whenever you remove or
  shrink an entry, and raise them only in the same PR that adds a new,
  reviewed, genuinely-necessary one. Most of today's entries are
  documentation and error-remedy text naming an example provider/key for a
  human reader; some are pre-existing hardcoded default models that
  predate this check and are flagged as follow-up debt rather than fixed
  here.

- **Demo replay wall time.** `mylonite demo` must finish within 10 seconds
  wall-clock on the CI runner (measured at 6.8 s locally when this bar was
  set; re-baseline to 20 s only at the demo's own gate). The step prints
  the measured time, and runs the demo a second time before failing, so
  one slow run on a busy runner doesn't fail the PR.

- **Test count floor.** `python scripts/check_test_count.py` compares
  `pytest --collect-only -q`'s count against the floor committed in
  `tests/test_count_floor.txt`. The count may grow freely; it can only
  drop if the PR carries the `tests-removed` label, in which case lower
  the floor in the same PR to lock in the new count.

### Offline deep path, corpus and call counts

Two more jobs, `nr-ci-e2e` (Linux) and `nr-ci-e2e-windows`, run on every PR
and push to main with no path filter and no provider key. Each runs:

```bash
MYLONITE_OFFLINE_E2E=1 pytest tests/e2e/test_offline_deep_path.py tests/corpus tests/test_llm_call_count.py -q
```

- **Offline deep path.** `tests/e2e/test_offline_deep_path.py` runs the
  reference scan of the vulnerable twin from the demo's recordings, sends
  its finding through the real generator and differential validator (which
  replay `examples/reference_validation/differential_fixtures/`), and runs
  the emitted test under pytest. It skips without `MYLONITE_OFFLINE_E2E=1`,
  so the main test jobs don't pay for it twice; the two jobs above always
  set it.
- **Labelled corpus.** `tests/corpus/labels.yaml` gives each recorded run a
  ground-truth label (`FINDING`, `NOT A FINDING` or `NOT TESTED`) and a
  one-line reason. Rows point at runs already in the repo, such as the
  recorded judge hallucination, the demo's reference scans and the #217
  target files; nothing is copied. `tests/corpus/test_labelled_corpus.py`
  replays each row and fails when its verdict stops matching the label.
  Change a label only when the ground truth was wrong, and say why in the PR.
- **LLM call counts.** `scripts/count_llm_calls.py` drives the reference
  `scan` and `gate` paths through a scripted fake model that counts every
  call: the planner replays recordings, the customiser and judge get
  scripted replies. `tests/fixtures/llm_call_baseline.json` holds the
  counts measured at the baseline commit (scan: 34 calls on the vulnerable
  twin, 36 on the guarded one; gate: 113). A path that makes more than 15%
  more calls fails `tests/test_llm_call_count.py` (scan) or the deep-path
  test (gate). If a change needs more calls on purpose, re-run
  `python scripts/count_llm_calls.py --gate`, update the baseline in the
  same PR and say why.

**CI wall time** is not enforced per PR — there is no stored history to
compare against inside a single workflow run. The current baseline is
noted here for reference: ~5 minutes total (the Linux test job ~55 s, the
Windows one ~297 s, the long pole). If a change is expected to move this
meaningfully, re-measure and update this paragraph in the same PR.

## What we can and can't accept

Mylonite reproduces working exploits, so a contribution here carries risks that
an ordinary library's does not. These rules are enforced by CI where they can
be, and by review where they can't. None of them is a judgement about you — we
apply them to every pull request, including the maintainer's.

**Never include a live credential.** Not in a test, a fixture, a recorded
transcript, or a comment — even an expired or free-tier one, even yours.
`detect-secrets` runs on every commit and push-protection runs on GitHub's side,
but neither is a substitute: a rotated-looking key still tells an attacker which
provider to try and which account to target. Use the recorded fixtures under
`src/mylonite/demo/fixtures/`, or a `sk-test-...`-style obvious fake.

**Only target things you control.** Attack payloads, target YAMLs, and test
fixtures must point at the in-repo reference targets or at hosts you personally
own. A pull request that scans a third party's server — however public, however
"just a demo" — will be closed regardless of intent. See
[SECURITY.md](./SECURITY.md#responsible-use--dual-use-policy).

**Payloads ship as inert data.** An attack module contributes a *seed body* and
a *predicate*, both data interpreted by the engine. Code that fetches a payload
at runtime, decodes one from an obfuscated blob, or reaches the network outside
the adapter layer will not be merged — that pattern is indistinguishable from a
dropper, and reviewers cannot tell the difference on a diff.

**The deliberately-vulnerable reference target has extra rules.**
`reference_targets/mcp_kitchen_sink/` is the differential oracle's ground truth,
so insecure code there is expected and a real backdoor would be cheap to hide
among it. `scripts/check_reference_target_inert.py` therefore enforces that the
package stays *inert*: no network, no subprocess, no filesystem, no
deserialisation, no dynamic execution. `web_fetch` does not fetch and
`send_email` does not send. Every tool it exposes must be named in
`seeds/seeds.yaml` and have a counterpart on the guarded twin. Widening that
script's allowlist is a security decision — open an issue first.

**Some files get a slower read.** Every pull request needs the maintainer's
approval — [`.github/CODEOWNERS`](.github/CODEOWNERS) is a catch-all today. But
workflows, `gate-action/`, `.pre-commit-config.yaml`, `pyproject.toml`,
`scripts/`, `.secrets.baseline` and `reference_targets/` are the **trust base**:
they control what the project's own checks do, so a change there can disable the
machinery that would catch the rest of the diff. Expect those to be reviewed as
a decision rather than waved through as an oversight. This is not a signal that
we distrust you — the same applies to the maintainer's own pull requests. Say in
the description why the change is needed and it will move faster.

**If you are touching CI**, two repository settings will bite you and neither is
visible in the tree. Actions must be **pinned to a commit SHA**, not a tag
(`uses: owner/action@<40-hex> # vX.Y.Z`), and only GitHub-owned actions plus a
short allowlist may run at all. A workflow using an unlisted third-party action
fails to start with a policy error you cannot fix from a pull request — propose
the action in an issue first and it can be added to the allowlist.

**Report vulnerabilities privately, including ones you find in Mylonite's own
guards.** If you spot a way around any of the above, that is a security report,
not a pull request — see [SECURITY.md](./SECURITY.md).

## Cutting a release

```bash
python scripts/prepare_release.py X.Y.Z   # bump + roll the CHANGELOG + refresh the baseline
git diff                                  # review
# commit, PR, merge to main
git tag vX.Y.Z && git push origin vX.Y.Z  # this is what publishes
```

Pushing the tag is the only irreversible step, and the only one not automated.
Before it, `python scripts/prepare_release.py --check X.Y.Z` runs exactly the
check the release gate will run.

You no longer have to remember the bump/CHANGELOG/tag choreography: the `gate`
job refuses to publish a tag that disagrees with `version.py`, `pyproject.toml`
or `CHANGELOG.md`, and the release now runs the full suite against the tagged
commit before building. Full policy — semver rules, the `CONTRACT_VERSION` axis,
1.0.0 criteria, the `.secrets.baseline` step, kitchen-sink releases — is in
[docs/contributing/releasing.md](./docs/contributing/releasing.md).

## Running live e2e tests before a release

Mylonite ships recorded integration tests under
`tests/integration/test_scan_mcp_*_recorded.py` that run in CI with mocked
subprocesses. The live counterparts (`test_scan_mcp_*_live.py`) spawn real
MCP server subprocesses and call a real LLM; they are gated behind
`MYLONITE_LIVE_E2E=1`. We run them **before each release** to validate that
the bundled-target wiring still matches the upstream servers.

Full instructions: [docs/contributing/live-e2e-tests.md](./docs/contributing/live-e2e-tests.md).

## Community attack-pattern registry (planned)

A versioned, CI-validated registry of contributed attack patterns is on the
roadmap (see `ROADMAP.md`) but not yet built — there is no registry
directory or CI job today. The **"Attack pattern submission"** issue
template is open for proposals in the meantime; the acceptance criteria in
`GOVERNANCE.md` describe the intended design and will apply once the
registry ships:

1. The pattern declares its OWASP/ASI/ATLAS/NIST mappings.
2. It comes with a seed vulnerable target it reliably exploits *and* a
   guarded variant it does not. (Differential proof.)
3. It does not target third-party services.

## Contributing a reference app scenario

A "reference app scenario" is a new seeded weakness for the bundled reference agent
(the reference app — `reference_targets/mcp_kitchen_sink/`) or for one of the real
MCP target families. This flow is live today, independent of the registry above:
open an issue with the **"Attack pattern submission"** template
(`.github/ISSUE_TEMPLATE/attack_pattern_submission.yml`), declaring the OWASP/ASI/ATLAS/NIST
mappings and confirming it does not target third-party services — the same criteria the
planned registry will formalize. This section spells out the differential gate, which is
the part people get wrong and which is already enforced today:

**The gate: every new scenario ships a differential proof.** The scenario
must *fire on the vulnerable variant and stay clean on the guarded variant*.
Model your proof on
`reference_targets/mcp_kitchen_sink/tests/test_differential.py`, which asserts
exactly that build behaviour and **runs in the main test suite** (it is on
`testpaths`, so a broken differential fails CI for everyone — not just an
opt-in job). A scenario without a green differential proof will not be merged.

## Reporting security issues

Do **not** open public issues for security-sensitive reports. See
[SECURITY.md](./SECURITY.md) for the private disclosure path and the
project's dual-use policy.
