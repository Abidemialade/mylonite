# Threat model for automated scanning of Mylonite

Mylonite is a security testing tool for the AI layer of an application: an agent's
system prompt, its tools (usually an MCP server), its retrieval and its memory. It
attacks an agent the operator controls, keeps a finding only when the attack lands
with the agent's safeguard switched off and is stopped with it switched on, and emits
a pytest regression test that gates CI. It runs on developer machines and in CI,
where it holds model-provider API keys and, for `mylonite gate --open-pr`, a GitHub
token.

That makes two things true at once. Mylonite deliberately reads hostile input, because
the target under test is assumed malicious. And its output is a security verdict that
people act on, so a wrong "resisted" is a vulnerability in its own right.

The public version of this model is `docs/threat-model.md`; `SECURITY.md` is the
reporting and responsible-use policy. Read both. Every control below names the file
that enforces it.

## What this project does and where untrusted input enters

Treat each of these as attacker-controlled:

1. **Everything a target returns.** Tool names, descriptions, input schemas, MCP
   annotations (`readOnlyHint` and the rest), tool results, error messages,
   server-initiated messages (notifications, and any request a server sends to the
   client), HTTP status lines and bodies, and for a stdio target the process's stdout
   and stderr.
   Entry points: `src/mylonite/plugins/_mcp/` (`stdio_adapter.py`,
   `remote_adapter.py`, `_session_adapter.py`, `tool_surface.py`) and
   `src/mylonite/plugins/_http/`.
2. **A target file (`target.yaml`) from someone else.** It is a shareable document
   that a pull request can edit. Parsing, path containment, `${VAR}` expansion and
   header rules live in `src/mylonite/plugins/_mcp/target_file.py`,
   `target_registry.py` and `src/mylonite/_paths.py`. The `command` a stdio target
   launches is chosen by the file by design (see "Anything to leave alone").
3. **Model output.** The planner, the attack customiser and the LLM judge all read
   target-controlled text, so their replies are attacker-influenced. Replies must only
   ever be parsed into typed values (`src/mylonite/scan/llm_parse.py`,
   `scan/judge.py`), never executed or used to choose a path, a command or a host.
4. **Committed or shared artefacts read back in.** Replay fixtures and gate
   directories (`src/mylonite/_replay.py`, `src/mylonite/gate/`), saved scan reports
   and evidence bundles (`src/mylonite/report/`), and `validation_report.json`. A
   pull request can change any of these in the repository that commits them.
**Trusted:** the operator, their shell, flags and environment, `--env-file`, provider
settings such as `api_base` (`cli.py`, `scan/llm_policy.py`), and third-party plugins
the operator opted in through `MYLONITE_ATTACK_MODULES`. The LLM provider is trusted for
availability, not for the content of its replies.

Data leaves Mylonite through the terminal and CI logs (`src/mylonite/_cli_io.py`),
log records, files it writes (`exploit_*.json`, `scan_report.json`, SARIF, the JSON
bundle, generated tests), and the pull request body `mylonite gate --open-pr` opens
(`src/mylonite/gate/recommend.py`, `localize.py`, `mitigation.py`).

### Security properties we rely on

- **No false clean.** An attack that landed must never be reported as RESISTED or as
  a pass. A check that could not run reads NOT TESTED and never counts as a pass.
  Code: `src/mylonite/scan/effect_verdict.py`, `class_verdict.py`,
  `src/mylonite/_verdict.py`, `scan/judge.py`, `plugins/_mcp/calibration.py`.
- **A target does not inherit the operator's credentials by accident.** A stdio
  server's environment is a fixed allowlist of OS variables plus what the target file's
  `env:` declares (`plugins/_mcp/stdio_adapter.py`, `_INHERITED_ENV_KEYS`). This is not
  a sandbox: the server runs as the operator, and `env:` may name any variable by
  design. A remote target file (`sse`, `http`, `rest`) may not reference Mylonite's own
  provider, GitHub or Actions credentials in `headers` or `request.headers`
  (`target_file.py`, `RESERVED_CREDENTIAL_ENV_VARS`). A path that sends one of those
  values to a URL the file names is a bug.
- **Secrets never reach output.** Logs, files, SARIF, bundles and PR bodies pass
  through `src/mylonite/_redaction.py`.
- **Target text cannot become code or markup.** Values in generated tests are escaped
  Python literals (`plugins/_reference/reference_pytest_generator.py`); target text in
  PR bodies goes through `src/mylonite/_markdown.py`; terminal output strips control
  sequences (`_cli_io.py`); Rich markup is escaped (`scan/artefacts.py`).
- **Mylonite only attacks what the operator authorised.** `--authorize` must match
  the target's own scope or family (`src/mylonite/_authz.py`).
- **Probes never reach a destination a third party controls.** Exfiltration probes use
  reserved documentation domains (RFC 2606) that no one can register (`scan/exfil.py`).
- **The gate never weakens the caller's repository or CI.** It does not persist write
  credentials, and the workflows it scaffolds pin actions to SHAs and pass inputs
  through `env` (`src/mylonite/gate/`, `gate-action/`).

## Components that matter most / least

Highest priority:

- the verdict path: `src/mylonite/scan/` (`effect_verdict.py`, `class_verdict.py`,
  `judge.py`, `engine.py`, `llm_parse.py`), `src/mylonite/_verdict.py`,
  `src/mylonite/plugins/_mcp/calibration.py` and `predicates/`;
- the adapters that talk to targets: `src/mylonite/plugins/_mcp/`,
  `src/mylonite/plugins/_http/`;
- credential handling and redaction: `_redaction.py`, `_target_env.py`, `_authz.py`,
  `plugins/_mcp/target_file.py`, `src/mylonite/providers/`, and `gate/pr.py`, which
  runs `git` and `gh` with the token;
- the CI gate and everything it writes or commits: `src/mylonite/gate/`,
  `gate-action/`, `_replay.py`, `src/mylonite/report/`;
- the release path: `.github/workflows/release.yml`, `release-kitchen-sink.yml`, and
  any workflow that reads a repository secret. No workflow uses `pull_request_target`,
  `workflow_run` or `issue_comment` triggers.

Each control above is one shared helper (`_redaction.py`, `_markdown.py`, `_cli_io.py`,
the reserved-header check, the verdict's read-tool rule). Target text that reaches the
terminal, a log, the PR body, SARIF, the bundle or a generated test without passing
through its helper is a real bug, even when the main path is guarded. So is a second
verdict path that skips a check the main path applies.

Lower priority but in scope: `src/mylonite/generate/`, `testkit/`, `mitigations/`,
`corpus/`, `demo/`, `cli.py` and `commands/`. Commands behind
`MYLONITE_EXPERIMENTAL=1` are in scope one severity level lower.

Out of scope (see "Anything to leave alone"): `reference_targets/`, `verification/`,
`tests/`, `docs/`, `examples/` and `scripts/`.

## How to exercise it

The image has Mylonite installed in editable mode at `/src`, with the reference
target. No network and no API key are needed for any of these:

- `python -m pytest -n auto -q` runs the whole suite (about 5,700 tests; a few
  minutes on two CPUs). Tests that need a live model or the network skip themselves.
  For one area, run its directory, for example `python -m pytest tests/scan -q`.
- `mylonite demo` replays a recorded run against the reference app, vulnerable then
  guarded, and prints the trust panel.
- `MYLONITE_OFFLINE_E2E=1 python -m pytest tests/e2e/test_offline_deep_path.py -q`
  runs the deepest offline path end to end on recordings: a reference scan, its
  finding through the real generator and differential validator, then the emitted
  test under pytest.
- `python scripts/measure_precision_recall.py --out /tmp/corpus.json` checks every
  recorded verdict in the labelled corpus against its ground truth.
- Good harness patterns to copy: `tests/mcp_plugin/test_effect_attribution.py` (a
  scripted hostile MCP target feeding the verdict), `tests/scan/` (verdict units),
  `tests/test_redaction.py`, `tests/mcp_plugin/test_target_file.py`,
  `tests/gate/test_recommend.py` (PR-body rendering).

A live `mylonite scan` needs a model provider, which the offline scan cannot reach.
Reproduce through the adapter and verdict layers with a scripted target, as the tests
above do.

## How you rate severity

We rate by what the operator or their CI loses, assuming the attacker controls a
target or a file the operator was asked to use.

- **Critical:** code execution on the operator's machine or CI runner from target
  output, model output, or a shared evidence bundle or report, without the operator
  choosing to run attacker code. An operator credential (provider key, `MYLONITE_*`,
  GitHub token) sent to an attacker with no operator action beyond a normal scan of
  their own target. A way for an outside contributor's pull request to publish to PyPI
  or read a repository secret.
- **High:** a false clean that a target can cause reliably, where an attack that
  landed reads RESISTED or a CI gate passes. Also: an operator credential written
  unmasked into a committed file or a PR body; bypassing `--authorize`; the gate
  leaving a write credential or an unpinned action in the caller's repository.
- **Medium:** the same leaks, but needing the operator to run a target file someone
  else wrote, or limited to one credential format; a false clean that needs several
  unusual conditions together; Markdown or link injection into the gate's PR body;
  path traversal out of a target file's directory.
- **Low:** terminal escape sequences, Rich markup injection, a scan the target can
  hang or crash (it is the operator's own target), or a misleading but non-verdict
  message.
- A **false positive** (Mylonite reports a finding that is not real) is a quality
  bug, not a vulnerability, unless a target can use it to hide a real finding.

Rate an artefact or a target file by the boundary it crosses. A target file matters
most for remote transports (`sse`, `http`, `rest`), which run no local code; for a
stdio file, only what it can do beyond launching its command counts. A committed
fixture, gate directory or report matters where it reaches someone who would not run
that repository's code: a shared or downloaded evidence bundle, a report opened with
`mylonite report`, or a privileged workflow that reads it. Code execution from those is
Critical. The same result through a pull request to a repository whose CI already runs
that pull request's code is Low, unless it makes the gate pass silently, which is High
as a false clean.

## Report and patch preferences

- Show the trust boundary that was crossed and a reproducer that runs offline in this
  image, ideally as a pytest test in the style of the files listed above.
- Patch at the last trusted decision point, with a regression test that fails before
  the fix and passes after.
- Do not change public API in `src/mylonite/contracts/` or the generated JSON schemas
  in `src/mylonite/schemas/`; say if a fix seems to need that.
- Keep Mylonite's capabilities: a fix should never turn a real finding into NOT
  TESTED, or drop a check, to make a report go away.

## Anything to leave alone

- **Already fixed.** `CHANGELOG.md` lists past security fixes (see 0.12.1 and 0.12.0).
  Report one of those again only as an unguarded variant.
- **`reference_targets/mcp_kitchen_sink/` is deliberately vulnerable.** In particular
  `server_vulnerable.py` and `stdio_vulnerable.py` are the ground truth for
  Mylonite's differential test; their weaknesses are catalogued in
  `reference_targets/mcp_kitchen_sink/seeds/seeds.yaml`. Report something there only
  if it is not in that catalogue, or if the reference app can reach the network,
  spawn a process or execute constructed code (the invariant
  `scripts/check_reference_target_inert.py` enforces).
- **Attack content is the product.** Prompt-injection payloads, seeds and corpora
  under `src/mylonite/corpus/`, `src/mylonite/plugins/_reference/`, `verification/`
  and `tests/` exist to attack the operator's own target. That a payload works is not
  a finding.
- **A target file's `command` runs by design.** A stdio target is a program the
  operator chose to launch; a target file that names a hostile command is equivalent
  to being asked to run a script. Report what a file can do *beyond* launching its
  command.
- **Third-party plugins are trusted once opted in.** Attack modules load only when
  named in `MYLONITE_ATTACK_MODULES`; a malicious plugin the operator enabled is out
  of scope.
- **Not vulnerabilities:** model non-determinism, a provider refusing a request,
  `RESISTED (server-reported)` itself (an error from the target is read as resistance
  by design and never becomes a kept finding; `docs/limitations.md` §9), fake secrets
  in tests and docs, and anything in `verification/`, `docs/`, `examples/` or
  `scripts/` that only maintainers run.
