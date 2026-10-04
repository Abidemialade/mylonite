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
[`PREREG_THIRD_PARTY_2026_10.md`](PREREG_THIRD_PARTY_2026_10.md). "No prior live run" was
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
  per-target table for what is, and isn't, claimed there. Its `weakness_classes:
  [W2]` means W1/W3/W4 are never declared, never attempted, and never produce a
  NOT TESTED entry — an absence, not a run-and-skip (an earlier draft of the prereg
  said otherwise; fixed there).

## E2E precision-cell targets (`verification/third_party/e2e_*.yaml`)

Three more targets, added for the end-to-end verification campaign's
precision cells (`verification/PREREG_E2E_2026_10.md`): benign configurations
where "0 kept" is the pass bar, because no finding on any of them is ever a
real vulnerability.

| # | Target | Upstream | License | Pinned commit (or tag) | No prior live run |
| --- | --- | --- | --- | --- | --- |
| 1 | `mcp-kitchen-sink-guarded` (the kitchen-sink guarded twin, launched as a REAL stdio server via its own console script) | `reference_targets/mcp_kitchen_sink` (this repo) | Apache-2.0 | in-repo, `mcp-kitchen-sink` package version `0.2.1` | n/a -- in-repo, not a third-party fetch; the in-process `reference:guarded` adapter runs elsewhere, but this is the first time it is scanned as a real stdio server through Mylonite's own stdio adapter |
| 2 | `@modelcontextprotocol/time` (`mcp-server-time`) | github.com/modelcontextprotocol/servers | MIT | PyPI `mcp-server-time==0.6.2`, installed with `mcp==1.30.0` pinned alongside it in its own venv (see "Notes on the choices" below); repo tag `python-servers-0.6.2` (commit `e7e1c85058e029ca1102efe6b2797f0ed608221b`) | confirmed -- no mention anywhere in `verification/`, `docs/`, `CHANGELOG.md` |
| 3 | `@modelcontextprotocol/server-everything` (reused from target 4 above, under a separate family/target file) | github.com/modelcontextprotocol/servers | repo-wide MIT/Apache-2.0 relicensing split | npm `2026.8.31`; repo tag `typescript-servers-0.6.2` (commit `94a36286d2ea49d095704167846283f0c2c2d5d1`) | the pin itself was already vetted for `tpv-server-everything`; the precision measurement under `e2e-readonly-b` is new -- that cell has never run |

Notes on the choices:

- **Target 1 (the guarded precision cell).** `reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/server_guarded.py`'s
  mitigations (M1 tool-description constraints, M5 the taint gate, M3 the
  `web_fetch` hostname allowlist, M4 `send_email`'s two-step stage/confirm)
  are real, server-side guards covering all four weakness classes -- not
  Mylonite's own synthetic boundary shim -- so a KEPT result against it is a
  false positive to triage, never a real finding. Launched as the real
  `mcp-kitchen-sink-guarded` console script (stdio), matching how every
  other third-party target in this campaign is launched, rather than the
  in-process `reference:guarded` adapter other Mylonite scans already use.
- **Target 2 (read-only server A).** `get_current_time`/`convert_time` are
  pure local timezone arithmetic -- no state, no network, no write/send/
  delete/exec tool. Confirmed from the pinned tag's own
  `src/time/README.md` tool list. `mcp-server-time==0.6.2` declares
  `mcp>=1.0.0` with no upper bound and imports `McpError` from
  `mcp.shared.exceptions`; `mcp` `2.0.0` (released 2026-07-28, confirmed
  from its own PyPI-published wheel) renamed that to `MCPError` and
  restructured its other imports, so letting pip resolve `mcp` freely
  crashes this server on import against any `mcp>=2.0.0` released after
  this pin was set. `mcp==1.30.0` (the newest 1.x release as of this pin,
  confirmed to still export `McpError` from the same module by reading its
  published wheel) is pinned explicitly, installed into this target's own
  venv -- the same per-target isolation `tpv-agents-sdk-ollama`'s Agents-SDK
  shim already uses -- so the installed `mcp` version here never depends on
  whatever version the campaign venv or the runner's system Python
  resolves.
- **Target 3 (read-only server B).** Picked from `server-everything`'s own
  tool list, verified from the actual TypeScript source
  (`src/everything/everything.ts`) at the exact pinned commit, not just its
  README: `echo`, `add`, `longRunningOperation`, `sampleLLM`,
  `getTinyImage` -- an arithmetic/demo surface, none of which write, send,
  delete, execute or fetch outbound. Also checked: its resource pair
  (`ListResourcesRequestSchema`/`ReadResourceRequestSchema`) serves only
  100 in-memory-generated, static demo strings/blobs, and an exhaustive
  text search of the same file for `printEnv`, `process.env`, `readFile`,
  `fetch(` and `http` returns no matches -- this exact pinned version has
  no environment-, file-, secret- or network-exposing tool at all. See
  `verification/PREREG_E2E_2026_10.md`'s "Read-only server B: verified tool
  list" for the full table. Cross-checked against Mylonite's own tool-role
  code too, not just the upstream source: none of the five tool names
  match `mylonite.scan.tool_roles._SINK_NAME_HINTS` (the W4/
  consequential-tool vocabulary) or `mylonite.scan.tool_classifier`'s
  egress-name hints, so no synthesised W3/W4 seed ever targets a tool here.
  Reused rather than picking a different package specifically so this
  precision measurement rides a pin already vetted end-to-end in this
  file, under its own `family` (`e2e-readonly-b`) so its result is never
  conflated with `tpv-server-everything`'s own N=1 connectivity smoke cell.

**Known, accepted pinning gaps (not full supply-chain pins):**

- **Target 3's own dependency on the MCP Python SDK (`mcp[cli]`) is resolved from
  PyPI at install time, not built from the pinned `python-sdk` commit above** — the
  example package's `pyproject.toml` declares `mcp` as a normal PyPI dependency, and
  installing the example (`pip install -e examples/servers/simple-streamablehttp`)
  pulls whatever `mcp` version PyPI resolves at run time, independent of which commit
  of the `python-sdk` monorepo the example file itself came from.
- **The two npm packages (targets 1 and 4) are pinned by published package version
  (`2026.8.31`), not by a lockfile** — their own transitive dependencies are
  resolved fresh by `npx` at install time and are not individually pinned.

These are accepted, documented gaps, not fixed in this pass: a hermetic multi-language
dependency pin (a `package-lock.json`/`uv.lock` committed per target) is more
infrastructure than this campaign's scope justifies, and both gaps are visible —
nothing here silently claims a fully pinned dependency tree.

## CI infrastructure (service containers, digest-pinned)

| Image | Pinned tag + digest (amd64) | Use |
| --- | --- | --- |
| `redis:7` | `redis:7@sha256:95acc00495ddacfec75111ba47021f903121a890311d49264c723b4423ac9601` | target 2's store |
| `ollama/ollama` | `ollama/ollama:0.35.0@sha256:9c1dc45ea758396139ec0adfa52947714c61f8d1e4537a6e2daef8138e7a64a9` | target 1's Ollama cell and target 6's own-agent inference, both run as a service container rather than an unpinned `curl \| sh` install script |

Both digests were read from the Docker Hub registry API on 2026-10-02 and are used as
the `services:` image reference in `.github/workflows/third-party-campaign.yml`.

## Mylonite-authored

| Artefact | What | Why it's here |
| --- | --- | --- |
| `crosswalk.yaml` | external benchmark label → Mylonite W1–W4 | the single subjective mapping; isolated for audit |
| `third_party/shims/openai_agents_ollama_shim.py` | thin, disclosed HTTP wrapper around the OpenAI Agents SDK example pattern, target 6 | makes an SDK agent reachable over `transport: rest`; the agent loop itself is unmodified third-party code. The shim's own docstring enumerates every change relative to the upstream example (model string, instructions, `tool_choice`, dropped `output_type`, dropped API-key check) — an earlier version of this row said "changed only the model string", which undercounted the diff |
