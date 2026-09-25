# Threat model

Mylonite runs code it did not write and talks to servers it does not trust: that is what
testing an agent's AI layer means. This page sets out who could attack a Mylonite run,
what each of them can reach, and the control that stands in the way. It is the
consolidated view; [`SECURITY.md`](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md)
remains the canonical policy for reporting a vulnerability and for responsible use.

## What is trusted

| Component | Trusted? | Why |
|---|---|---|
| The operator and their shell | Yes | They choose the target and hold the provider key. |
| The Mylonite package and its bundled plugins | Yes | Versioned, CI-checked, SHA-pinned in its own workflows. |
| The LLM provider | For availability, not content | Its output is parsed as data, never executed. |
| The target server and everything it returns | **No** | It is the thing under test. |
| A `target.yaml` you received from someone else | **No** | It is a shareable, PR-editable document. |
| A third-party plugin | Only if you opt it in | Attack modules run only when named in `MYLONITE_ATTACK_MODULES`. |

## Three adversaries

### 1. A hostile target server

The server under test may be malicious, compromised, or simply wrong. It controls its tool
descriptions, every tool result, and — for a stdio target — a process on your machine.

| It could try to… | What stops it | Where |
|---|---|---|
| Read your provider key or other credentials from its environment | A spawned server inherits a fixed allowlist of OS variables (`PATH`, `HOME`, `TEMP`, …) plus only what `env:` declares — never Mylonite's own environment | `plugins/_mcp/stdio_adapter.py` (`_INHERITED_ENV_KEYS`) |
| Learn a remote target's bearer token from Mylonite's output | `headers` / `request.headers` go to the transport and are never logged; the descriptor carries only the URL host | `plugins/_mcp/remote_adapter.py`, `plugins/_http/http_adapter.py` |
| Steer a probe to a real destination | Probe destinations are RFC 2606 reserved names (`.example.net`, `.test`), which do not route | `scan/exfil.py` |
| Inject Rich markup into the terminal report | Every target-influenced table cell is markup-escaped before rendering | `scan/artefacts.py` |
| Turn a field value into code in the emitted test | Values are rendered as escaped Python literals, and the test's docstring is closed against embedded quotes | `plugins/_reference/reference_pytest_generator.py` |
| Hang the run | Per-call provider timeouts, a per-scan wall-clock bound (`--iteration-timeout`) and the call budget (`--max-llm-calls`) | `scan/_llm.py`, `scan/engine.py` |

Two properties are worth stating plainly, because they follow from what the tool does:

- **Mylonite's own planner and judge read attacker-controlled text.** That is the attack
  surface being measured. Their output is only ever parsed into typed values
  (`scan/llm_parse.py`) — never executed, never used to choose a file path or a command —
  and the verdict prefers a deterministic predicate over the judge wherever one can see
  the signal.
- **Target content can reach a committed artefact.** A finding's `exploit_*.json` records
  what the agent did, and a gating PR commits it. Credential-shaped values are masked on
  the way in (see [What Mylonite does with your credentials](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md#what-mylonite-does-with-your-credentials)),
  and the gating PR is a pull request: it is reviewed before it merges.

### 2. A hostile `target.yaml`

Someone sends you a target file, or a pull request edits yours.

| It could try to… | What stops it | Where |
|---|---|---|
| Read a file outside its own directory | Every path field is resolved (symlinks included) and containment-checked | `_paths.py` (`resolve_contained`) |
| Point the filesystem sandbox at your home directory or whole disk | The scope is validated before any process starts | `plugins/_mcp/target_registry.py` |
| Run against a target you have not authorised | `--authorize` must equal the value derived from the target's own data (its `scope`, else its `family`) | `_authz.py` |
| Carry a secret into a file Mylonite writes | `headers`, `request.headers` and credential-shaped `env` values become `${VAR}` references in every copy | `_redaction.py` |
| Send a key or proxy base URL to an attacker via the env file | `--env-file` loads only known provider-key names, and a credentialed `api_base` is refused | `cli.py`, `scan/llm_policy.py` |

A target file still chooses the `command` a stdio target launches — that is what a custom
target is. Treat a changed `command` in a pull request the way you would treat any script
that pull request asks you to run.

### 3. A leak through Mylonite's own output

Nothing adversarial is needed for a secret to escape: a log line or a report is enough.

| Surface | Control | Where |
|---|---|---|
| Console and CI logs | Every human-facing string leaves through one redacting boundary, enforced by a test | `_cli_io.py`, `tests/test_cli_output_boundary.py` |
| Log records | A redacting log filter is installed at start-up | `_redaction.py` |
| `validation_report.json` | Per-leg detail and notes are redacted before they are persisted | `cli.py` (`validate`) |
| `exploit_*.json` metadata | The execution context written into an exploit is a closed allowlist of model and file names — nothing credential-shaped | `contracts/exec_context.py` |
| SARIF and the JSON bundle | A finding's narration is redacted before it is written | `report/sarif.py`, `report/bundle.py` |

## Supply chain

- Every GitHub Action in Mylonite's own workflows, and in the published `gate-action`, is
  pinned to a commit SHA; action inputs reach the shell through `env`, never through
  `${{ }}` interpolation.
- The deliberately-vulnerable reference target is checked on every commit to stay inert:
  it cannot reach the network, spawn a process, or execute constructed code
  (`scripts/check_reference_target_inert.py`).
- `bandit`, `detect-secrets` and `pip-audit` are required checks on `main`.

## Reporting

If you find a way past any control on this page, report it privately — see
[Security and responsible use](security.md).
