# House rules

These five conventions describe the target end state the plan is fixing
toward, drawn from the 2026-08-01 reviews under `docs/reviews/`. Each was
violated at multiple independent sites — in most cases across separate
files (and in one case across separate review-sweep scopes that both
independently caught the same bug), though convention 3 is two sites within
a single file. None of them are true of the codebase yet: `_cli_io` and
`_paths` are built in Phase 1 and Phase 2 respectively, and today `src/`
calls `typer.echo` directly 156 times, all in `cli.py`. Each convention gets
an enforcement test added in the phase that introduces the primitive (or,
for conventions 3-5 which are enforceable against code that exists today,
the phase that fixes their cited sites) — not before.

1. **Redact before it leaves the machine.** Anything printed, persisted, pushed,
   or published will go through `mylonite._cli_io.echo` or `_redaction.redact*`
   once Phase 1 lands. No call site should call `typer.echo` directly after
   that. (cli-config-review DCR-0006/DCR-0010/DCR-0011/DCR-0016,
   contracts-taxonomy-review DCR-0010, gate-report-demo-review DCR-0007)
2. **Containment, not shape.** A path from `target.yaml` will be resolved
   through `mylonite._paths.resolve_contained` once Phase 2 lands, before it
   reaches `open()` or an argv. `is_absolute()` is not a security check.
   (contracts-taxonomy-review DCR-0011/DCR-0012, gate-report-demo-review
   DCR-0013, plugins-adapters-review DCR-0017/DCR-0020)
3. **Never `.format()` untrusted data into source or a path.** Render it with
   `repr()` and validate it at ingestion. (plugins-adapters-review
   DCR-0001/DCR-0002 — both in `reference_pytest_generator.py`)
4. **Security controls fail closed.** An unrecognised tool is guarded, not passed
   through. A name-hint list is a convenience, never the gate.
   (scan-engine-review DCR-0032/DCR-0033/DCR-0034/DCR-0035)
5. **Absent evidence is inconclusive.** A predicate that cannot see the signal it
   needs should return `None`, never a confident verdict.
   (scan-engine-review DCR-0036/DCR-0038)
