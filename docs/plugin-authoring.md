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

!!! note "Target adapters may take construction arguments"

    The no-argument rule is what lets `discover()` hand back ready-to-use
    instances, and attack modules — the group that is actually *run* — must
    follow it.

    Target adapters are the exception by design: an adapter for a named server
    family is built by the target-file factory *with* that family, not
    discovered ready-made. Several of the adapters Mylonite itself ships work
    this way. `mylonite plugins` lists them normally and annotates them
    **configured per target**; it reads `contract_version` off the class rather
    than constructing anything, so needing configuration is never reported as a
    fault. `discover()` still skips them, because its callers need instances.

## Attack modules: opting yours into a scan

Registering an attack module makes it **discoverable**, not **active**. A scan runs
the families Mylonite ships plus anything you name explicitly:

```bash
export MYLONITE_ATTACK_MODULES=my-attack-id      # attack_metadata().id, comma-separated
mylonite scan reference:vulnerable
```

`mylonite plugins` lists what is installed and their ids. If selection comes back
empty the error names this variable, because "no usable attack modules" is exactly
what an author sees when their module is installed but not enabled.

This is opt-in by id rather than "run everything discovered", deliberately. Mylonite
drives real attacks against a real app, so which code gets to do that should be a
decision you made, not a consequence of what happens to be in the environment.

!!! warning "Your module must reuse an existing predicate — for now"

    Reaching the scan is necessary but not sufficient. `ScanEngine` discards any
    payload whose `metadata` lacks `seed_id`, `weakness`, `predicate`, `setup` and
    `drive`, and the `predicate` value must resolve in Mylonite's predicate
    registry or the judge reports it as not-registered.

    **There is no `mylonite.predicates` entry-point group yet**, so a module cannot
    ship a new deterministic oracle of its own. Until that contract change lands,
    compose an existing predicate. `mylonite.scan.predicates.registered_names()`
    returns the current set. Tracked in
    [`TODOS.md`](https://github.com/Abidemialade/mylonite/blob/main/TODOS.md); a
    test in `tests/plugins/test_third_party_attack_module.py` fails if the gap
    closes so the docs get updated with it.

## Target adapters: stamp your tool surface

If your target exposes tools, every `AdapterResponse` you return should carry
the tool names in `metadata["tool_surface"]`, as a JSON list of strings:

```python
return AdapterResponse(
    payload_pattern_id=payload.pattern_id,
    raw_response=reply_text,
    tool_calls=called_tool_names,
    metadata={"tool_surface": json.dumps([t.name for t in my_tools])},
)
```

This is what lets the engine tell **"the agent refused"** apart from **"the
agent never acted"**. An attempt with an empty `tool_calls` trace against a
known, non-empty tool surface is reported as `skipped_planner_no_engagement`
(NOT TESTED): the attack was delivered but never exercised, so it is not
evidence the target is defended. See
[Reading results](reading-results.md#the-terminal-trust-panel).

Omit the key and the check does not apply — your zero-tool-call attempts are
reported as clean passes. That default is deliberate: a black-box
`transport: rest` agent has no tools to call and is judged on its reply text,
so it must never be caught by this. But it means an adapter for a tool-using
target has to stamp the surface to get the honest reading.

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
