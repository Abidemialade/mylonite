# House rules

These five conventions exist because the 2026-08-01 review found each of them
violated at three or more independent sites. Each is enforced by a test.

1. **Redact before it leaves the machine.** Anything printed, persisted, pushed,
   or published goes through `mylonite._cli_io.echo` or `_redaction.redact*`.
   Nothing in `src/` calls `typer.echo` directly. (DCR-0006/0007/0010/0011/0016)
2. **Containment, not shape.** A path from `target.yaml` is resolved through
   `mylonite._paths.resolve_contained` before it reaches `open()` or an argv.
   `is_absolute()` is not a security check. (DCR-0011/0012/0013/0017/0020)
3. **Never `.format()` untrusted data into source or a path.** Render it with
   `repr()` and validate it at ingestion. (DCR-0001/0002)
4. **Security controls fail closed.** An unrecognised tool is guarded, not passed
   through. A name-hint list is a convenience, never the gate. (DCR-0032/0033/0034/0035)
5. **Absent evidence is inconclusive.** A predicate that cannot see the signal it
   needs returns `None`, never a confident verdict. (DCR-0036/0038)
