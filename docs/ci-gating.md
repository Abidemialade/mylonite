# CI gating

`mylonite gate` runs the whole flow — find an exploit, write a regression test,
validate it against the differential oracle, and (opt-in) open a PR that gates
CI on it.

## The 60-second magic moment (local)

```bash
# against the bundled reference agent
mylonite gate reference:vulnerable

# against your own MCP app
mylonite init-target --command "python" --arg "-m" --arg "your.server" --output target.yaml
mylonite gate --target-file target.yaml --authorize your-scope --open-pr
```

Without `--open-pr`, `gate` writes `.mylonite/gate/` (the test, the exploit,
your `target.yaml`) and the `.github/workflows/` templates, commits them to a
branch, and prints the exact `gh pr create` command. With `--open-pr` it opens
the PR via `gh`.

The PR body is itself a result surface (see [Reading the results](reading-results.md#the-gating-pr)):

- **The differential proof** — the fires/resists numbers and the `kept` formula, so a
  reviewer sees *why the test is trustworthy*, not just that it exists.
- **Located at** — the exact locus to fix (which tool description / returned content /
  action handler / system-prompt line).
- **The proven fix** — a concrete, reviewable code **diff** implementing the boundary
  control the differential proved load-bearing — "here's the fix we proved works."
- **Compliance** — the OWASP-LLM/ASI · MITRE ATLAS · NIST tags.
- **Inline annotations** — a best-effort GitHub check-run annotation on the offending
  prompt line, when the AI layer is a committed file.

For a custom target the gate proves the finding **differentially by default** (the
control-efficacy oracle); `--fast` skips that leg for a faster, cheaper check that no
longer proves the safeguard carries the security — a deliberate trade-off, not the
recommended default.

## Adopting it in GitHub CI

Add one secret — `MYLONITE_API_KEY` (your provider key) — and the two
scaffolded workflows:

- **`mylonite-gate.yml`** runs on every PR. It re-drives your agent (bounded:
  deterministic effect-probe, small model, 1 iteration) and fails the check on
  a regression. Cheap — a few cents per PR.
- **`mylonite-discovery.yml`** runs nightly or on demand. It does the expensive
  full discovery and opens a fresh gating PR when it finds a new exploit.

### The reusable Action

```yaml
- uses: Abidemialade/mylonite/gate-action@v1
  with:
    target-file: .mylonite/gate/target.yaml
    authorize: your-scope
    open-pr: "true"
```

### Provider keys

The scaffolded workflows map the `MYLONITE_API_KEY` secret to
`ANTHROPIC_API_KEY` (Anthropic is the default provider). If you run a different
provider, set that provider's key env var in the workflow instead (e.g.
`OPENAI_API_KEY`) and pass `--provider`/`--model` — Mylonite routes through
LiteLLM.

### Surfacing findings in the Security tab

Emit SARIF from a scan or validation and upload it so AI-layer findings land in the
GitHub **Security tab** alongside every other code-scanning result:

```yaml
- run: mylonite report .mylonite/validated --sarif mylonite.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mylonite.sarif }
```

Behind a corporate network? See
[Enterprise & air-gapped networking](enterprise-networking.md).

## Where to go next

- [Quickstart](quickstart.md) — install, the commands that work today, and the
  scan → generate → validate flow.
- [The validation engine](validation.md) — why a validated test is worth
  committing, and why the CI gate runs offline.
- [Enterprise & air-gapped networking](enterprise-networking.md) — self-hosted
  runners, internal model gateways, and TLS-inspecting proxies.
