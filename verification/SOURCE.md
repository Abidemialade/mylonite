# Verification source provenance

Every external input to the verification harness is third-party ground truth,
fetched at a pinned commit and verified against a recorded sha256 before use
(see `fetch.py`). Nothing here is vendored into the repo. This mirrors the
provenance discipline of `src/mylonite/taxonomy/data/SOURCE.md`.

The one **Mylonite-authored** artefact is `crosswalk.yaml` (external label →
W-class). It is isolated and reviewable; it is the only place subjectivity
enters the harness.

## Layer 2 — academic benchmarks

| Source | Upstream | License | Pinned commit | Verified files |
| --- | --- | --- | --- | --- |
| InjecAgent | https://github.com/uiuc-kang-lab/InjecAgent | MIT | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | `test_cases_{dh,ds}_{base,enhanced}.json`, `tools.json` — sha256 in `fetch.py` |
| AgentDojo | https://github.com/ethz-spylab/agentdojo | MIT | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | **released runs** (`runs/gpt-3.5-turbo-0125/banking/…`) — scored as real third-party transcripts; commit-pinned (no `pip install` of the package needed). See `fetch.fetch_agentdojo_runs`. |

**Committed fixture (the exception to "nothing here is vendored").**
`verification/layer2_datasets/fixtures/agentdojo_real_run_user_task_0_injection_task_3.json`
is one real, small (4.4 KB) AgentDojo run, fetched with `gh api` at the pinned commit
above: `runs/gpt-3.5-turbo-0125/banking/user_task_0/important_instructions/injection_task_3.json`,
blob sha `af2947451d1ef8cf1e4deb75dab9e3bc9101079e`, recorded 2026-10-02. `security: true`
(the agent sent money to the attacker's IBAN) — used by
`tests/verification/test_layer2_agentdojo.py` to pin the adapter's polarity against a
genuine upstream record, not only the synthetic in-file fixture helper.

InjecAgent sha256 digests (recorded 2026-06-22, commit `f19c9f2`):

```
test_cases_dh_base.json      0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305
test_cases_dh_enhanced.json  885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50
test_cases_ds_base.json      4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9
test_cases_ds_enhanced.json  7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce
tools.json                   e21a8f70b1d5de4677d6d52642936a322655d79b17a72c84f600550384083a1e
```

## Layer 1 — runnable vulnerable MCP targets

| Source | Upstream | License | Pinned commit | Status |
| --- | --- | --- | --- | --- |
| DVMCP | https://github.com/harishsg993010/damn-vulnerable-MCP-server | README claims MIT, **no LICENSE file in repo** | `79734c19f5104cd11486c90926d245560f53befa` | built — fetch-at-runtime (`fetch.fetch_dvmcp`, gated `--include-unlicensed`), never vendored |
| **MCPSecBench** | https://github.com/AIS2Lab/MCPSecBench | **MIT** (clean OSI license — no opt-in gate) | _TBD — pin at first fetch_ | planned (capability-matrix workhorse) — runnable vulnerable servers + **toggleable defense modes** (none / MCIP / AIM-MCP); peer-reviewed arXiv:2508.13220; per-server → W-class catalogue authored in `layer1_runnable/mcpsecbench.py` at fetch time |

## Layer 3 — defended targets (precision / false-positive control)

| Source | Upstream | License | Pinned commit | Status |
| --- | --- | --- | --- | --- |
| **Enkrypt AI Secure MCP Gateway** | https://github.com/enkryptai/secure-mcp-gateway | **Apache-2.0** | _TBD — pin at first fetch_ | planned — hardened/defended MCP gateway with toggleable guardrails; the external **0-FP precision baseline** (closes the Layer-3 external-defended gap) |

## Compliance-tag + SARIF canonical references (offline checks)

| Source | Upstream | License | Use |
| --- | --- | --- | --- |
| MITRE ATLAS data | https://github.com/mitre-atlas/atlas-data (`dist/ATLAS-latest.yaml`, STIX) | Apache-2.0 | diff emitted ATLAS technique IDs (`atlas-navigator-data` is **deprecated** — use this) |
| NIST AI RMF 1.0 | https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf (NIST.AI.100-1) | NIST public | validate NIST function tags (GOVERN / MAP / MEASURE / MANAGE) |
| OWASP GenAI (LLM Top 10 2025 / ASI Threats & Mitigations v1.0) | https://genai.owasp.org | CC-BY-SA-4.0 | validate OWASP LLM / ASI IDs (numbered IDs live on genai.owasp.org, not the repo landing page) |
| OASIS SARIF spec | https://github.com/oasis-tcs/sarif-spec (2.1.0 schema) | OASIS | canonical SARIF 2.1.0 schema |
| Microsoft SARIF SDK | https://github.com/microsoft/sarif-sdk (`Sarif.Multitool validate`) | MIT | smart SARIF validator (beyond JSON-schema) for `report --sarif` output |

Both MCPSecBench and Enkrypt are clean OSI licenses, so (unlike DVMCP) they need **no
`--include-unlicensed` gate**. Commits are pinned on first fetch and recorded here with their
sha256, mirroring the DVMCP discipline.

**DVAA rejected (verified 2026-06-22).** An earlier research pass named DVAA
(`opena2a-org/damn-vulnerable-ai-agent`) as "Apache-2.0, MCP servers on ports
7010-7013". Verified against the repo, this is wrong on every point: DVAA is an
**A2A / AI-infrastructure** playground (40+ heterogeneous Docker scenarios,
`expected-checks` are IDs for DVAA's own verifier), it exposes **no MCP endpoint**
Mylonite's adapter can drive, and it has **no LICENSE file** (GitHub detects
none). It is therefore unusable as a Layer-1 MCP target. DVMCP is the correct fit.

The DVMCP challenge → W-class mapping (the Mylonite-authored judgement) lives in
`verification/layer1_runnable/dvmcp.py::CATALOGUE`, with per-row notes; ground
truth is each challenge's `solutions/challengeN_solution.md`. Challenges 8 and 9
(RCE / command injection) are recorded as **out of Mylonite's AI-layer scope**.

## Third-party campaign targets (`verification/third_party/`)

Six systems Mylonite has never run against before, each with every LLM call made in
CI (`.github/workflows/third-party-campaign.yml`), pre-registered in
[`PREREG_L2_THIRD_PARTY.md`](PREREG_L2_THIRD_PARTY.md). "No prior live run" was
checked by grepping `verification/`, `docs/` and `CHANGELOG.md` for each target's
name before it was added here; none had ever appeared in a run log, a results
directory, or a changelog entry.

| # | Target | Upstream | License | Pinned commit (or tag) | No prior live run |
| --- | --- | --- | --- | --- | --- |
| 1 | `@modelcontextprotocol/server-memory` | github.com/modelcontextprotocol/servers | repo-wide MIT/Apache-2.0 relicensing split (MIT for unconsented contributions, Apache-2.0 for the rest) | npm `2026.8.31`; repo tag `typescript-servers-0.6.2` (commit `94a36286d2ea49d095704167846283f0c2c2d5d1`) | **confirmed** — named in `PREREG_SECOND_EXTERNAL_PROOF.md`/`EXTERNAL_DIFFERENTIAL.md` as a planned second-proof target, but no run log in `CAPABILITY_MATRIX.md`/`FINDINGS.md`/`TRENDS.md` ever executed it |
| 2 | `redis/mcp-redis` | github.com/redis/mcp-redis | MIT | tag `v0.5.1` (commit `11e67e44358cd6410d5a7e615a29539ccd71a045`) | confirmed — no mention anywhere in `verification/`, `docs/`, `CHANGELOG.md` |
| 3 | `modelcontextprotocol/python-sdk`, `examples/servers/simple-streamablehttp` | github.com/modelcontextprotocol/python-sdk | repo-wide MIT/Apache-2.0 relicensing split | tag `v2.2.0` (commit `9972c21aa42054fb1450c5fc614761ed11847ec6`) | confirmed — no mention anywhere |
| 4 | `@modelcontextprotocol/server-everything` | github.com/modelcontextprotocol/servers | repo-wide MIT/Apache-2.0 relicensing split | npm `2026.8.31`; repo tag `typescript-servers-0.6.2` (commit `94a36286d2ea49d095704167846283f0c2c2d5d1`) | confirmed — no mention anywhere |
| 5 | `modelcontextprotocol/go-sdk`, `examples/server/memory` | github.com/modelcontextprotocol/go-sdk | repo-wide MIT/Apache-2.0 relicensing split | tag `v1.8.0` (commit `3f3b699b2b67e1ed033a63d6651671dab53c2d32`) | confirmed — no mention anywhere |
| 6 | `openai/openai-agents-python`, `examples/model_providers/litellm_auto.py` pattern | github.com/openai/openai-agents-python | MIT | tag `v0.22.3` (commit `fdf21db62c303a3db54b0dfbee82de2141fa2799`); PyPI `openai-agents[litellm]==0.22.3` | confirmed — no mention anywhere |

Notes on the choices (plan asked for a documented pick for targets 5 and 6):

- **Target 5 (runtime diversity, no external writes).** The Go SDK's own
  `examples/server/memory` is a line-for-line port of target 1's knowledge-graph
  server (same tool names: `create_entities`, `add_observations`, `delete_entities`,
  `search_nodes`, …) onto the official MCP Go SDK, with an **in-memory-only** store
  by default (the `-memory` flag, which would persist to a file, is left unset) — so
  it writes nothing outside the process, satisfying "no external writes" without
  needing a fallback target.
- **Target 6 (an agent that runs its own inference on Ollama, at zero cost).** The
  OpenAI Agents SDK accepts a `litellm/<model>` model string
  (`examples/model_providers/litellm_auto.py` demonstrates this against OpenRouter).
  LiteLLM's local-Ollama route is `ollama_chat/<model>` (the same route Mylonite
  itself uses — see `scan/providers.py`), so `model="litellm/ollama_chat/llama3.2:3b"`
  runs the example agent's own planning loop entirely against the in-runner Ollama
  model, no provider key and no cost. The disclosed shim that exposes this agent over
  the `rest` transport is `verification/third_party/shims/openai_agents_ollama_shim.py`
  — it is Mylonite-authored glue (a thin FastAPI wrapper), not the system under test;
  the agent loop itself (`Agent`/`Runner`, tool dispatch, the litellm model routing)
  is the external code the campaign exercises. `openai-agents[litellm]==0.22.3` is
  installed from PyPI rather than built from the GitHub tag, since the pinned PyPI
  release is what a real adopter would install.
- **Target 3's weakness surface.** `simple-streamablehttp` exists to prove the
  `transport: http` path on code we didn't write, not to showcase a rich surface: its
  one tool (`start-notification-stream`) has no store-and-recall pair, so its only
  usable weakness-class hook is the `caller` argument it reflects back into the
  tool's result text — a content-processing tool in Mylonite's coverage sense. See
  `verification/third_party/streamablehttp.yaml`'s header comment and the prereg's
  per-target table for what is, and isn't, claimed there.

## Mylonite-authored

| Artefact | What | Why it's here |
| --- | --- | --- |
| `crosswalk.yaml` | external benchmark label → Mylonite W1–W4 | the single subjective mapping; isolated for audit |
| `third_party/shims/openai_agents_ollama_shim.py` | thin, disclosed HTTP wrapper around the OpenAI Agents SDK example pattern, target 6 | makes an SDK agent reachable over `transport: rest`; the agent loop itself is unmodified third-party code |
