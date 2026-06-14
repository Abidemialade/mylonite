# CI gating

`mylonite gate` runs the whole flow — find an exploit, write a regression test,
validate it against the differential oracle, and (opt-in) open a PR that gates
CI on it.

## The 60-second magic moment (local)

```bash
# against the bundled reference agent
mylonite gate reference:vulnerable

# against your own MCP app
mylonite init-target --command "python" --arg "-m" --arg "your.server" > target.yaml
mylonite gate --target-file target.yaml --authorize your-scope --open-pr
```

Without `--open-pr`, `gate` writes `.mylonite/gate/` (the test, the exploit,
your `target.yaml`) and the `.github/workflows/` templates, commits them to a
branch, and prints the exact `gh pr create` command. With `--open-pr` it opens
the PR via `gh`. The PR body explains the finding, its OWASP/ASI/ATLAS/NIST
tags, the validation evidence, and a human-applied suggested mitigation.

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

Behind a corporate network? See
[Enterprise & air-gapped networking](enterprise-networking.md).

## Where to go next

- [Quickstart](quickstart.md) — install, the commands that work today, and the
  scan → generate → validate flow.
- [The validation engine](validation.md) — why a validated test is worth
  committing, and why the CI gate runs offline.
- [Enterprise & air-gapped networking](enterprise-networking.md) — self-hosted
  runners, internal model gateways, and TLS-inspecting proxies.
