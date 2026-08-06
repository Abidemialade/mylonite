# Security and responsible use

The canonical version of this policy is
[`SECURITY.md`](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md)
in the repository root. This page mirrors it for the docs site.

## Reporting vulnerabilities in Mylonite

Use GitHub's private security-advisory channel:
<https://github.com/Abidemialade/mylonite/security/advisories/new>.

## Dual-use policy

Mylonite reproduces working weaknesses in AI agents. The project's
non-negotiables:

1. **Targets-you-control by default.** The CLI refuses to run against an
   unauthorized target. Authorization is opt-in per scan via an explicit
   `--authorize` flag, and `--authorize` must **equal** the value the target
   itself requires — never an arbitrary non-empty string. One rule, applied
   by every command that live-drives a real target (`scan`, `gate`,
   `validate`, `ablate`): a target that declares a **scope**
   (`mcp:filesystem:<sandbox>`, `mcp:github:<owner/repo>`, or a custom
   [target file](target-file.md) with `scope:` set) requires
   `--authorize == <scope>` exactly; a **stateless** target (`mcp:fetch`, or a
   custom target with no scope) requires `--authorize == <family>` — for
   inline `mcp:custom` with no `--scope`, the family is the literal `custom`.
   The required value is derived from the target's own data, never from a
   self-asserted flag like `requires_scope`. See the full rule in
   [`SECURITY.md`](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md).
2. **No bundled targeting of public services.**
3. **Secret-redaction in logs.** Anything that looks like a secret is
   redacted before any log line, report, or generated test is written.
4. **No evasion features.** PRs that add detection-evasion or anti-forensics
   are closed.
5. **Vulnerable reference agents stay loopback-only.** The bundled
   `mcp_kitchen_sink` reference target and any future deliberately-insecure
   fixtures refuse to bind to non-loopback interfaces by default.

These rules apply to bundled extensions and to anything accepted into the
community attack-pattern registry.
