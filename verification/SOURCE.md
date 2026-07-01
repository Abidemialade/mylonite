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

## Mylonite-authored

| Artefact | What | Why it's here |
| --- | --- | --- |
| `crosswalk.yaml` | external benchmark label → Mylonite W1–W4 | the single subjective mapping; isolated for audit |
