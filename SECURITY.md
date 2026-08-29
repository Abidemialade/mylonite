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
   the user has not explicitly authorized. Authorization is opt-in per run
   via a required `--authorize` flag plus a target identifier (hostname,
   service URL, or local-path) the user is asserting they own or are
   contractually authorized to test.

   **One rule, applied by every command that live-drives a real target** —
   `scan`, `gate`, `validate`, and `ablate`. The required value is derived
   from the target's own data, never from a self-asserted flag:
   - A target that declares a **scope** (`mcp:filesystem:<sandbox>`,
     `mcp:github:<owner/repo>`, or a custom target file with `scope:` set)
     requires `--authorize == <scope>` exactly. For a custom target, this
     applies regardless of whatever the target file's own `requires_scope`
     field says — a target that names a scope IS asserting that scope is the
     sensitive resource, and cannot downgrade the check by also setting
     `requires_scope: false`.
   - A **stateless** target (`mcp:fetch`, or a custom target/target file
     with no `scope`) requires `--authorize == <family>` — for inline
     `mcp:custom`, the family is the literal `custom`.

   Mismatched or missing values exit 2 (config error) naming what
   `--authorize` needed to equal. `mylonite validate` and `mylonite ablate`
   re-drive the real target — including sending live attack payloads (e.g.
   exfil) — exactly like `scan`/`gate`, so they are gated identically; this
   was not always true (`validate` previously ran a custom target with no
   authorization check at all, and `ablate` previously accepted any non-empty
   value). A custom target can never register over a bundled family name.

   That's one RULE, but two separate implementations, by design:
   - **Custom targets** (`--target-file` / `mcp:custom`) — the document being
     authorized (a target YAML, or CLI flags assembled into one) is
     user-editable, which is exactly what let a target declare a sensitive
     `scope` while also setting `requires_scope: false` to downgrade its own
     gate (DCR-0008). `src/mylonite/_authz.py`
     (`required_authorization` / `check_authorization`) is the single
     implementation of the rule for this path, shared by `scan`, `gate`,
     `validate`, and `ablate` — there is exactly one place that decides what
     `--authorize` must equal for a custom target.
   - **Bundled targets** (`mcp:filesystem`, `mcp:fetch`, `mcp:github`) — driven
     only by `scan`/`gate`, via a separate inline check in
     `_build_adapter_for_mcp` (`cli.py`) against `target_registry.BUNDLED_TARGETS`,
     a hardcoded dict defined in source, not a user-editable document. The
     DCR-0008 vulnerability class — a target smuggling a downgrade instruction
     into the very document being authorized — does not apply to data the
     operator cannot edit, so this path is intentionally left as its own
     (smaller, equally-enforced) implementation of the same rule rather than
     folded into `_authz.py`.

   **TLS / corporate proxies:** behind a TLS-inspecting proxy, provider calls
   can fail `CERTIFICATE_VERIFY_FAILED`. Install `pip install "mylonite[enterprise]"`
   (the CLI then uses the OS trust store via `truststore`; opt out with
   `MYLONITE_NO_TRUSTSTORE=1`) or set `SSL_CERT_FILE` to your corporate CA bundle.
   A live `scan`/`gate`/`validate` run classifies a provider-call failure as
   TLS vs. auth vs. network vs. rate-limit, each with a concrete remedy, rather
   than a raw traceback. Mylonite never disables certificate verification.

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
   prefixes, AWS access-key ids, bearer tokens, PEM private-key blocks,
   `scheme://user:pass@host` URL credentials, and `key=value` credential
   assignments) out of every log record, and every human-facing CLI string is
   redacted before it is printed (see "What Mylonite does with your
   credentials" below). Redaction is intentionally NOT applied to persisted
   replay fixtures or generated test source — those are deterministic and
   contain no raw provider secrets by construction, and masking them would
   corrupt loadable/replayable data.
4. **No evasion features.** The project does not accept contributions that add
   detection-evasion, anti-forensics, or rate-limit-bypass capabilities. Any
   such PR will be closed.
5. **Vulnerable reference agents stay loopback-only.** The `mcp_kitchen_sink`
   reference target and any future deliberately-vulnerable test fixtures bind
   to loopback by default and refuse to start on non-loopback interfaces
   without an explicit override flag.

These rules apply to all official extensions and — once the planned
community attack-pattern registry ships (it does not exist yet) — to
anything distributed through it. Third-party plugins are out of our direct
control, but the registry's contribution guidelines will forbid patterns
whose only use is offensive.

## What Mylonite does with your credentials

A `target.yaml` (or `mcp:custom` `--env`) can legitimately carry a live
credential — a bearer token in `headers` / `request.headers`, a secret in
`env` (a DB password, a provider API key for the app under test), or one
embedded in a `--target-file` argument the probed planner echoes back. Every
place that value could otherwise leave the machine unmasked is routed through
`mylonite._redaction`:

- **Console / CI output.** `src/` never calls `typer.echo`, `console.print`,
  or bare `print` directly — every human-facing string leaves through
  `mylonite._cli_io` (`echo` / `echo_err` / `echo_exc` / `console_print`),
  which redact secret-shaped tokens first. This is enforced by a test
  (`tests/test_cli_output_boundary.py`), not just convention. A Rich `Table`'s
  free-text cells (e.g. a validation leg's `detail`, a scan attempt's
  `verdict_reason`) are redacted at the point they're inserted, before Rich's
  column-width wrapping can split a secret-shaped token across a line break.
- **A pydantic validation error.** A malformed `--target-file` or `--env`
  raises a `ValidationError` whose default `str()` embeds the offending raw
  field value (`input_value`). `echo_exc` renders it via `redact_exception`,
  which drops `input_value` and prints only the field path + message.
- **Any `target.yaml` Mylonite writes or copies.** The scan-dir copy
  (`mylonite scan`), the co-located copy (`mylonite generate`), the gate PR
  copy (`mylonite gate`), and the `scan --scaffold` starter
  all go through the same `redact_env` / `redact_target_yaml` masking: every
  `headers` / `request.headers` value is replaced unconditionally, and every
  credential-shaped `env` value — by key name (`password`, `api_key`,
  `token`, ...) OR value shape — is replaced, with a `${VAR}` reference
  (`mylonite._redaction.target_yaml_env_ref_name`) deterministically derived
  from the field's key, leaving key names and structure intact so the file
  still documents the target. This is genuinely operational, not just
  structurally parseable: `load_target_file` expands `${VAR}` references from
  the process environment on every load (also honouring an operator's own
  hand-written `${VAR}` reference, e.g. `docs/http-agent.md`'s
  `Authorization: Bearer ${MY_TOKEN}`), and raises a loud, actionable error
  naming the missing variable if it is unset — never a silent empty-string
  substitution. The same masking is `dump_target_file`'s default for an
  inline `mcp:custom` target. `${VAR}` expansion is deliberately scoped to
  ONLY these three credential-bearing locations (`headers`, `request.headers`,
  `env`) — never the rest of the document (`system_prompt`, `purpose`, `args`,
  `url`, `request.body`, ...). Those are exactly the fields an operator
  legitimately uses for SSTI/template-injection attack payloads containing
  literal `${IDENTIFIER}`-shaped text, and a CI gate runner has real secrets
  (`ANTHROPIC_API_KEY`, `GH_TOKEN`, ...) set in its own environment — scanning
  the whole document for `${VAR}` would risk silently substituting a live
  secret into an unrelated string headed for the target under test.
  **`command`/`args` are NOT masked or `${VAR}`-indirected** — see the next
  section; put a credential in `env` or `headers` instead, never bake it into
  `args`.
- **The SARIF upload and the JSON finding bundle.** Both are written to disk
  unconditionally (`mylonite gate`, `mylonite report --json`) and the SARIF
  one is uploaded to GitHub code scanning — a persistent, often
  broadly-visible surface. A real exfiltration finding's narration
  (`success_reason`) is redacted before it rides into either artefact.
- **The retained attack-evidence trace.** A probed tool's schema can
  legitimately accept a credential-bearing parameter, and a planner steered by
  injected content may pass a real one. Recorded tool-call arguments
  (`mcp_trace_planner`, persisted into `exploit_*.json` / `scan_report.json`)
  mask a credential-shaped argument *value* — by key name OR shape — but not
  every value and not the keys, so the oracle predicates that inspect those
  same values (e.g. did `fetch` target the attacker host, did `write_file`
  carry the attacker marker) keep working; a URL or prose body never matches
  the credential rules and passes through unchanged.

The one place a credential is used unmasked is the live subprocess/HTTP call
to the target itself — that is the whole point of testing it. Redaction never
runs on demo replay fixtures or the emitted test source, because those are
deterministic and must round-trip byte-for-byte; masking them would corrupt
the generate → validate → replay pipeline (see the module docstring in
`src/mylonite/_redaction.py`).

## What a `target.yaml` you received from someone else can and cannot do

`target.yaml` is a shareable, PR-editable document: a teammate mails you one, or a
pull request edits the one already in your repo. Every path-shaped field in it
(`system_prompt_file`, the `mcp:filesystem` sandbox scope) is containment-checked, not
just shape-checked (`is_absolute()` is not a security check) — it cannot read a file
outside the target YAML's own directory, and it cannot point the filesystem sandbox at
your whole disk, your home directory, or a nonexistent path. It CAN still launch an
arbitrary `command`/`args` as a subprocess (that is the point of a custom target) —
gated by `--authorize`, but the operator is still trusting the launch command itself,
the same way they'd trust any script a PR asks them to run.

**A credential embedded directly in `command`/`args` (e.g.
`args: [--api-key, sk-live-...]`) is NOT masked.** Unlike `headers` /
`request.headers` / `env` — which are always replaced with a `${VAR}` reference
wherever Mylonite persists or prints a target.yaml, per "What Mylonite does with
your credentials" above — `args` is an unstructured string list with no key name
to mask by, so a value embedded there survives byte-for-byte into every copy
Mylonite writes (scan dir, `generate`'s co-located copy, the `gate` PR). If a
target's launch needs a credential, pass it via `env` (most subprocess CLIs
also accept the value from an environment variable) or, for an MCP server
reachable at a URL, `headers` — never as a literal `args` entry.

See `docs/target-file.md#path-containment` for the full field-level detail, including
`MYLONITE_FS_SCOPE_ROOT`.

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
- **Dependency CVEs — `pip-audit`** over the installed environment (blocking).
  This step was informational until it was found to be swallowing real
  advisories rather than only the editable-install skip its exemption was
  written for. Genuine advisories are remediated by raising the affected
  dependency floor in `pyproject.toml`; an advisory with no fix yet available
  gets a scoped, commented `--ignore-vuln <ID>`, so every exception is visible
  and attributable instead of blanket.
- **Taint analysis — CodeQL** (`security-extended`) on every push and pull
  request, plus weekly (`.github/workflows/codeql.yml`). Complements `bandit`,
  which matches patterns inside a single file: CodeQL follows data from an
  untrusted source to a dangerous sink across files, which is the shape of most
  real findings in a tool that parses attacker-supplied target descriptions,
  tool schemas, and model output.
- **Workflow lint — `zizmor` + `actionlint`** via pre-commit. Workflows are the
  one class of file that can disable every other check here, and until recently
  nothing checked them.
- **Supply-chain posture — OpenSSF Scorecard**, published weekly
  (`.github/workflows/scorecard.yml`) and linked from the README badge. It
  independently re-checks action pinning, token scopes, and branch protection,
  so a change that quietly weakens one shows up as a score drop.

Two project-specific guards run alongside the general tooling:

- **`scripts/check_reference_target_inert.py`** asserts that the deliberately
  vulnerable reference target stays incapable of real I/O — no network,
  subprocess, filesystem, deserialisation, or dynamic execution — and that every
  tool it exposes is catalogued and has a guarded counterpart. Insecure code is
  *expected* there, which is what would make a genuine backdoor cheap to
  disguise; this keeps the two separable by construction rather than by review.
- **`scripts/check_sensitive_paths.py`** requires an explicit maintainer
  sign-off on pull requests that modify the checks themselves. See
  [GOVERNANCE.md](./GOVERNANCE.md#required-reviews).
