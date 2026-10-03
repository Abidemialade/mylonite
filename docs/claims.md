# Claims register

Every factual or numeric claim in `README.md` carries an inline
`<!-- claim:ID -->` marker immediately above the sentence it covers. This
page is the other half: each id, the claim in short, and where the evidence
for it lives — a file, a test, or a result path you can open yourself.

`scripts/check_claims_register.py` keeps the two in sync: it fails if a
marker in `README.md` (or a `docs/journey/*.md` page) has no row here, and
it fails if a row here no longer matches a marker anywhere, so the list
can't rot into claiming things nothing in the docs actually asserts anymore.
Run it with `python scripts/check_claims_register.py`, or as
`pytest tests/test_claims_register.py`.

**What isn't here on purpose.** A line stated as a *target being measured*
rather than an already-proven result — for example the journey's "under 10
minutes" first-proof bar — carries no marker and no row. Marking it would
claim it's proven; it isn't yet. Once the rehearsal (`verification/rehearsal/`)
has a timed run, that becomes a real claim with real evidence, and gets both.

| Id | Claim | Evidence |
|---|---|---|
| `readme-email-server-kept` | A finding on `mcp-server-email` (a third-party MCP server) fired 5/5 against the server as shipped and 0/5 with the safeguard in place. | [`verification/CAPABILITY_MATRIX.md` — "Run log — 2026-07-04"](https://github.com/Abidemialade/mylonite/blob/main/verification/CAPABILITY_MATRIX.md), line ~128 ("raw fired 5/5, guarded build resisted 5/5, differential gap 1.00"); the reproduction recipe is [`verification/EXTERNAL_DIFFERENTIAL.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/EXTERNAL_DIFFERENTIAL.md). |
| `readme-echo-mcp-no-false-alarms` | No false positives against Enkrypt's `echo_mcp`, a third-party server with nothing wrong with it. | [`verification/CAPABILITY_MATRIX.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/CAPABILITY_MATRIX.md) — "Run log — 2026-06-25 (Enkrypt — bad_mcps + the gateway...)"; [`verification.md`](./verification.md#layer-3-precision-false-positives-on-known-good-targets). |
| `readme-mcpsecbench-discarded-flaky` | A finding from the MCPSecBench corpus failed to reproduce on re-run (0/3) and was discarded rather than kept as a flaky test. | [`verification/CAPABILITY_MATRIX.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/CAPABILITY_MATRIX.md) — the MCPSecBench run log; [`verification/FINDINGS.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/FINDINGS.md). |
| `readme-judge-checked-agentdojo-transcripts` | The judge was scored against real AgentDojo transcripts of models that fell for attacks, not self-authored examples. | [`verification/results/0.10.0/layer2-agentdojo.json`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/layer2-agentdojo.json); [`verification/campaign.py`](https://github.com/Abidemialade/mylonite/blob/main/verification/campaign.py) (layer 2 runner). |
| `readme-dvmcp-unmeasured` | The published DVMCP 0.9.0 figure (0/8) is unmeasured, not a result, because of two scorer/campaign defects. | [`verification/results/0.9.0/layer1-recall.json`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.9.0/layer1-recall.json); issue #136 (the "folded into missed" scorer fix); [`docs/limitations.md`](./limitations.md#3-published-negatives). |
| `readme-injecagent-f1` | InjecAgent (100 cases/split, local `llama3.2:3b`): F1 1.000 on direct-harm, F1 0.833 at 0.714 recall on data-stealing, in 0.10.0 (0.9.0: 0.400 at 0.25 recall). | [`verification/results/0.10.0/layer2-injecagent-dh.json`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/layer2-injecagent-dh.json), [`layer2-injecagent-ds.json`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/layer2-injecagent-ds.json); 0.9.0 figures in [`verification/results/0.9.0/`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.9.0). |
| `readme-agentdojo-judge-agreement` | Judge agreement against AgentDojo's own labels: F1 0.81 (precision 0.68, recall 1.00); the judge over-flags on 7 of 27 runs relative to AgentDojo's exact-goal check. | [`verification/results/0.10.0/layer2-agentdojo.json`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/layer2-agentdojo.json). |
| `readme-single-model-evidence` | The published evidence rests largely on one model, Claude Haiku 4.5, at small, cost-capped sample sizes. | `meta.json`'s `model` field in [`verification/results/0.9.0/`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.9.0/meta.json) ("anthropic/claude-haiku-4-5-20251001 (layer1/3)") and [`verification/results/0.10.0/`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/meta.json) (same model, plus `ollama/llama3.2:3b` for the InjecAgent cells only). |
| `readme-measurement-window` | The published verification figures were measured between 25 June and 14 September 2026. | `meta.json` timestamps in [`verification/results/0.9.0/`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.9.0/meta.json) and [`verification/results/0.10.0/`](https://github.com/Abidemialade/mylonite/blob/main/verification/results/0.10.0/meta.json). |
| `readme-project-status` | Beta, essentially a single maintainer (one outside contribution to date), over 2,300 tests, CI (ruff/mypy/pytest/pre-commit) enforced on every pull request. | `pytest -q -n auto`'s own collected-test count; `git log --format='%an' \| sort -u` for contributor history; [`.github/workflows/ci.yml`](https://github.com/Abidemialade/mylonite/blob/main/.github/workflows/ci.yml) for the enforced checks. |
| `readme-demo-ci-matrix` | On every pull request, CI builds Mylonite from source and runs `mylonite demo` against that build on Python 3.14, on Linux and Windows, in an 80-column terminal. | [`.github/workflows/ci.yml`](https://github.com/Abidemialade/mylonite/blob/main/.github/workflows/ci.yml) — the `demo` job; `tests/test_docs_consistency.py::test_readme_has_uvx_one_liner`. |
| `readme-compliance-frameworks` | Every test and finding carries tags from OWASP LLM Top 10 2025, OWASP ASI 2026, MITRE ATLAS, and NIST AI RMF. | `src/mylonite/taxonomy/data/` (the bundled taxonomy, one file per framework, each with a `SOURCE.md` citation); [`docs/standards-mapping.md`](./standards-mapping.md). |
| `readme-sarif-version` | `mylonite report`'s `--sarif` output is SARIF 2.1.0. | `src/mylonite/report/sarif.py` (`_SCHEMA`, `"version": "2.1.0"`); `tests/test_report_sarif.py` (`assert doc["version"] == "2.1.0"`). |
| `readme-extension-points` | The five extension points (attack modules, test generators, validators, target adapters, compliance mappers) are versioned public API with reference implementations in this repository. | `src/mylonite/contracts/_types.py` (the versioned `Protocol`/ABC definitions); `src/mylonite/plugins/_reference/` (one reference implementation per extension point); `CONTRIBUTING.md`. |

## What's deliberately not here

The CLI's exit codes and the `mylonite report`/`mylonite demo`/etc. commands
table are factual claims too, but they're kept in sync by a different,
narrower mechanism than this register: `tests/cli_golden` pins the exit-code
enum and `command_tree.json`, and `scripts/check_fenced_commands.py` checks
every fenced-command example in the docs against that same golden. Giving
them a second, separately-maintained row here would risk the two mechanisms
drifting from each other instead of from the code.

## Adding a claim

1. State the claim in `README.md` (or a `docs/journey/*.md` page), with an
   `<!-- claim:your-id -->` comment on its own line immediately above the
   sentence.
2. Add a row here: the id, the claim in one line, and a real file, test or
   result path — not a restatement of the claim itself — as the evidence.
3. Run `python scripts/check_claims_register.py` before you commit.
