# Contributing to Mylonite

Thank you for considering a contribution. Mylonite is an Apache-2.0 open-source
project; see [GOVERNANCE.md](./GOVERNANCE.md) for how decisions are made and
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for the behaviour we expect.

This guide covers:

1. Setting up a dev environment
2. The five extension points and how to author a plugin
3. PR conventions (Conventional Commits, DCO)
4. The community attack-pattern registry flow
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
| Test generator       | Emits a regression test (pytest, jest, …) from a confirmed exploit | `contracts/test_generator.py`           |
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
  `fix(taxonomy): correct LLM06 cross-reference`. The CHANGELOG is generated
  from these.
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

## Community attack-pattern registry

The registry is how the project accumulates a body of validated, citable
attack patterns. To submit one, open an issue using the
**"Attack pattern submission"** template. Acceptance criteria are in
`GOVERNANCE.md`; in short:

1. The pattern declares its OWASP/ASI/ATLAS/NIST mappings.
2. It comes with a seed vulnerable target it reliably exploits *and* a
   guarded variant it does not. (Differential proof.)
3. It does not target third-party services.

## Reporting security issues

Do **not** open public issues for security-sensitive reports. See
[SECURITY.md](./SECURITY.md) for the private disclosure path and the
project's dual-use policy.
