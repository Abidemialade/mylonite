# Plugin authoring

Mylonite has five **versioned extension points**, each defined as a Python
Protocol + a runtime-checkable ABC under
[`src/mylonite/contracts/`](https://github.com/Abidemialade/mylonite/tree/main/src/mylonite/contracts).
Plugins register via standard PyPI entry points and are discovered by
[`mylonite.plugins.registry.discover`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/plugins/registry.py).
Run `mylonite plugins` to list every registered plugin across all five groups
(which also runs the version-compatibility check below).

**What runs today.** *Attack modules* are discovered **and run** on every
`scan`/`gate` — install one and it contributes payloads immediately. The other
four contracts (target adapter, test generator, validator, compliance mapper)
are discovered and version-checked, but Mylonite uses its bundled **reference
implementation** for each; selecting a third-party implementation of those four
on the CLI is not yet exposed (a roadmap item). Custom target adapters today
are reached through the target-file / `mcp:` family mechanism rather than the
entry-point registry.

## Versioning rules

Every contract module exports a `CONTRACT_VERSION` semver string. Every
plugin class declares its own `contract_version`. The loader:

- **refuses** to load a plugin whose declared `contract_version` differs in
  *major* version from the host,
- **warns** on minor mismatches,
- ignores patch differences.

This is enforced at discovery time so a `pip install` of a mismatched plugin
never fails silently mid-run.

## Entry-point groups

| Contract            | Entry-point group              | Reference impl                                         |
| ------------------- | ------------------------------ | ------------------------------------------------------ |
| Attack module       | `mylonite.attack_modules`      | `mylonite.plugins._reference.reference_attack_module`  |
| Target adapter      | `mylonite.target_adapters`     | `mylonite.plugins._reference.reference_target_adapter` |
| Test generator      | `mylonite.test_generators`     | `mylonite.plugins._reference.reference_pytest_generator` |
| Validator           | `mylonite.validators`          | `mylonite.plugins._reference.reference_validator`      |
| Compliance mapper   | `mylonite.compliance_mappers`  | `mylonite.plugins._reference.reference_compliance_mapper` |

## Registering a plugin

In your own package's `pyproject.toml`:

```toml
[project.entry-points."mylonite.attack_modules"]
my_attack = "my_package.module:MyAttackModule"
```

The class must:

- declare `contract_version: ClassVar[str]` matching `AttackModule.CONTRACT_VERSION`,
- be instantiable with no arguments (config flows via the contract's methods),
- implement the methods in the Protocol.

## Worked examples

Each reference plugin in
[`src/mylonite/plugins/_reference/`](https://github.com/Abidemialade/mylonite/tree/main/src/mylonite/plugins/_reference)
is intentionally minimal. Use them as starting points.

## JSON schemas

The wire-format JSON schemas for the Pydantic models passed between plugins
live under
[`src/mylonite/schemas/`](https://github.com/Abidemialade/mylonite/tree/main/src/mylonite/schemas)
and are regenerated via:

```bash
python scripts/regenerate_schemas.py
```

CI checks they are up to date after any contract change.
