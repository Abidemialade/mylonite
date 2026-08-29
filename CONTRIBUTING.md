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

- Python 3.11+ (3.11 / 3.12 / 3.13 are CI-tested; 3.14 should work)
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
pytest --cov=mylonite
```

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
- **Changelog.** User-visible changes update `CHANGELOG.md`.
- **Contract changes** (touching any file under `src/mylonite/contracts/`)
  need an issue tagged `contract-change` open for at least a week — see
  `GOVERNANCE.md`.

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

**Some files need code-owner review.** Workflows, `gate-action/`,
`.pre-commit-config.yaml`, `pyproject.toml`, `scripts/`, `.secrets.baseline`,
and `reference_targets/` control what the project's own checks do, so
[`.github/CODEOWNERS`](.github/CODEOWNERS) requires the maintainer's approval on
them. This is not a signal that we distrust you — a change there can disable the
machinery that would catch the rest of the diff, so it has to be a decision
rather than an oversight. Say in the PR description why the change is needed and
it will move faster.

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
