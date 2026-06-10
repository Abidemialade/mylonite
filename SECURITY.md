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

   Each `invoke()` spawns a fresh subprocess of the bundled server. Users
   are advised to point `mcp:filesystem` at a throwaway sandbox directory
   they own, point `mcp:github` at a throwaway repository with a
   fine-grained PAT scoped only to that repo, and treat `mcp:fetch`'s
   targets as out-of-scope for live scans against shared infrastructure.
2. **No bundled targeting of public services.** Mylonite ships no built-in
   target list, allowlist of public agents, or convenience flags pointing at
   third-party production systems.
3. **No payload-logging of live secrets.** When the tool encounters something
   that looks like a secret (API key, bearer token, password) in a payload or
   response, it redacts before any log, report, or test artifact is written.
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
