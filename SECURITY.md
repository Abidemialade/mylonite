# Security policy

Mylonite is a defensive-security tool. Because it generates test artifacts that
reproduce AI-layer weaknesses (per [ROADMAP.md](./ROADMAP.md)), it is subject to a
formal dual-use policy. This document covers both **how to report a
vulnerability in Mylonite itself** and **the rules under which Mylonite may be
used**.

## Reporting a vulnerability

Please **do not** open public issues for security-sensitive reports.

- **Preferred:** open a private vulnerability report via GitHub Security
  Advisories: <https://github.com/Abidemialade/mylonite/security/advisories/new>
- **Email:** `hello.mylonite@gmail.com` (will move to a dedicated
  `security@` alias once the project owns a domain).

Please include:

- a clear description of the issue and its impact,
- a minimal reproducer if possible,
- the affected version (`mylonite --version`) and Python version,
- any suggested mitigation if you have one.

We aim to acknowledge reports within 5 business days and to ship a fix or
mitigation within 90 days for confirmed issues. We are happy to credit
reporters in the changelog and release notes (or to keep the report anonymous,
on request).

## Responsible-use / dual-use policy

Mylonite produces working reproductions of weaknesses in AI agents. Used
correctly, that is the entire point: the generated tests gate a developer's CI
so the same weakness cannot regress. Used incorrectly, it is an offensive
capability against systems the user does not own.

The project enforces the following non-negotiables:

1. **Targets-you-control by default.** The CLI refuses to run against a target
   the user has not explicitly authorized. Authorization is opt-in per scan
   via a required `--authorize` flag plus a target identifier (hostname,
   service URL, or local-path) the user is asserting they own or are
   contractually authorized to test.

   For **bundled MCP stdio targets** added in v0.2.2 (`mcp:filesystem:<sandbox>`,
   `mcp:fetch`, `mcp:github:<owner/repo>`), `--authorize` is scope-matched:
   - Scope-bearing families (`filesystem`, `github`) require
     `--authorize == <scope>` exactly. Mismatched values exit 2 with both
     the supplied authorize and the target's scope shown for diagnosis.
   - Stateless families (`fetch`) require `--authorize == <family>` (the
     literal `fetch`), making the user-intent assertion explicit even when
     no scope segment is supplied.

   **Custom targets** (`--target-file target.yaml` or `mcp:custom --command …`)
   follow the same rule keyed on the target file's `requires_scope`: with a
   `scope` declared, `--authorize == <scope>`; otherwise `--authorize == <family>`
   (for inline `mcp:custom`, the family is the literal `custom`). A custom target
   can never register over a bundled family name.

   **TLS / corporate proxies:** behind a TLS-inspecting proxy, provider calls
   can fail `CERTIFICATE_VERIFY_FAILED`. Install `pip install "mylonite[enterprise]"`
   (the CLI then uses the OS trust store via `truststore`; opt out with
   `MYLONITE_NO_TRUSTSTORE=1`) or set `SSL_CERT_FILE` to your corporate CA bundle.
   Run `mylonite doctor` to distinguish a TLS failure from an auth/network/rate
   problem. Mylonite never disables certificate verification.

   Each `invoke()` spawns a fresh subprocess of the bundled server. Users
   are advised to point `mcp:filesystem` at a throwaway sandbox directory
   they own, point `mcp:github` at a throwaway repository with a
   fine-grained PAT scoped only to that repo, and treat `mcp:fetch`'s
   targets as out-of-scope for live scans against shared infrastructure.
2. **No bundled targeting of public services.** Mylonite ships no built-in
   target list, allowlist of public agents, or convenience flags pointing at
   third-party production systems.
3. **No payload-logging of live secrets.** Mylonite does not log raw model
   payloads or responses. As defense-in-depth, when `redact_secrets` is on (the
   default) the `mylonite` logger tree masks secret-shaped tokens (provider key
   prefixes, AWS access-key ids, bearer tokens, PEM private-key blocks, and
   `key=value` credential assignments) out of every log record, and the
   rendered CLI scan/report strings are redacted before they are echoed.
   Redaction is intentionally NOT applied to persisted replay fixtures,
   `exploit_*.json` / `scan_report.json` artefacts, or generated test source —
   those are deterministic and contain no raw provider secrets by construction,
   and masking them would corrupt loadable/replayable data.
4. **No evasion features.** The project does not accept contributions that add
   detection-evasion, anti-forensics, or rate-limit-bypass capabilities. Any
   such PR will be closed.
5. **Vulnerable reference agents stay loopback-only.** The `mcp_kitchen_sink`
   reference target and any future deliberately-vulnerable test fixtures bind
   to loopback by default and refuse to start on non-loopback interfaces
   without an explicit override flag.

These rules apply to all official extensions and to anything shipped through
the community attack-pattern registry. Third-party plugins are out of our
direct control, but the registry's contribution guidelines forbid patterns
whose only use is offensive.

## Scope

In scope for security reports:

- the `mylonite` package and CLI,
- the bundled reference plugins under `src/mylonite/plugins/_reference/`,
- the deliberately-vulnerable reference targets under `reference_targets/`,
  **only** if a real-world risk arises from the way they ship (e.g. they
  could bind to a public interface despite the loopback default).

Out of scope:

- the *intentional* vulnerabilities in the reference targets — those are the
  point. See `reference_targets/mcp_kitchen_sink/README.md` for the list.
- the upstream OWASP / MITRE ATLAS / NIST data files: those are sourced from
  their canonical publishers; please report issues upstream.

## Supported versions

Pre-1.0, only the latest minor release receives security fixes. Once 1.0 ships,
this section will be updated with a longer support window.

## Security tooling (project CI)

Every push and pull request runs a permanent `security` job in CI
(`.github/workflows/ci.yml`) alongside lint / typecheck / test:

- **SAST — `bandit`** over `src/mylonite/` at medium-or-higher severity
  (blocking). The deliberately-vulnerable reference targets under
  `reference_targets/` are excluded by design (`[tool.bandit]` in
  `pyproject.toml`) — they are the ground-truth oracle and hardening them would
  defeat the tool's purpose.
- **Secret scan — `detect-secrets`** over the full tracked tree against the
  committed `.secrets.baseline` (blocking). The baseline allowlists the known
  test fakes and the LLM-recorded demo fixtures (verified to contain no real
  secrets); any *new* secret-shaped token fails the job. Regenerate with
  `detect-secrets scan --baseline .secrets.baseline` and review with
  `detect-secrets audit .secrets.baseline`.
- **Dependency CVEs — `pip-audit`** over the installed environment
  (informational: it surfaces advisories without blocking unrelated PRs on
  transient upstream CVEs). Genuine advisories are remediated by raising the
  affected dependency floor in `pyproject.toml`.
