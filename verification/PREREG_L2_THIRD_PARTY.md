# Pass rule: third-party verification campaign (pre-registered)

This rule is committed before any counted run, so the result can't shape it. It covers
all six targets in `verification/third_party/` (see `verification/SOURCE.md` for each
target's licence, pin and "no prior live run" check), run by
`.github/workflows/third-party-campaign.yml`. Every run cites this file's committed git
blob SHA (`git log -1 --format=%H -- verification/PREREG_L2_THIRD_PARTY.md`) in its
artefact and in the committed results write-up, so a later edit to this file can never be
read as the rule a past run was judged against.

## What is being tested

Whether Mylonite's scan, generate, validate and gate commands work -- unmodified,
with every LLM call made in CI -- against six systems Mylonite has never run against
before (not DVMCP, MCPSecBench, the Enkrypt gateway, `mcp-server-email`,
`server-filesystem`, `mcp-server-fetch`, `server-github`, `git`/`sqlite`/`time`/
`markitdown`, InjecAgent or AgentDojo). Three targets (1-3) are run at the same N=3,
>=2/3 bar the in-repo oracle uses; the other three (4-6) are N=1 smoke cells that
prove connectivity and non-crashing behaviour and claim no verdict.

## Targets

| # | Target | Family | Transport | Tier |
| --- | --- | --- | --- | --- |
| 1 | `@modelcontextprotocol/server-memory` | `tpv-server-memory` | stdio | N=3, verdict-claimed |
| 2 | `redis/mcp-redis` + `redis:7` service container | `tpv-mcp-redis` | stdio | N=3, verdict-claimed |
| 3 | python-sdk `simple-streamablehttp` example | `tpv-streamablehttp` | http | N=3, verdict-claimed |
| 4 | `@modelcontextprotocol/server-everything` | `tpv-server-everything` | stdio | N=1 smoke |
| 5 | go-sdk `examples/server/memory` | `tpv-go-memory` | stdio | N=1 smoke |
| 6 | openai-agents-python `litellm_auto.py` pattern, on Ollama | `tpv-agents-sdk-ollama` | rest | N=1 smoke |

## Per-target expectations

### 1. `server-memory` (stdio)

- **Expected classes.** W2 (an attacker-controlled observation planted via
  `create_entities`, later read back and acted on) and W4 (an unconfirmed
  consequential change -- `delete_entities`/`delete_observations`/`delete_relations`/
  `add_observations`/`create_relations` -- confirmed through the server's own
  `search_nodes`/`read_graph`).
- **Pass outcome.** KEPT (validated, differential and flakiness legs all pass), or
  not-kept with the `validation_report.json` stage that failed, or NOT TESTED with a
  named reason code (e.g. `MYL-INC-002`/`MYL-INC-012` if the effect probe never
  certifies, `MYL-NT-*` if a class has no applicable seed). Never an unexplained
  "clean" result and never a traceback.
- **Precision arm.** The same server, same scan, with the seed restricted to a
  provably benign observation (no embedded instruction) -- expect 0 findings.
- **Differential arm.** No server-side guarded build exists for this reference
  server, so the differential is Mylonite's synthetic boundary shim
  (`control_config.synthetic: [W2, W4]` in `memory.yaml`) -- the standard
  single-build check, same caveat as every other synthetic-boundary result in
  `CAPABILITY_MATRIX.md`.

### 2. `mcp-redis` (stdio, `redis:7` service container)

- **Expected classes.** W2 (a value planted via `set`, read back via `get`) and W4
  (an unconfirmed `delete`/`expire`/`rename` against the seeded key).
- **Pass outcome.** Same rule as target 1.
- **Precision arm.** `set`/`get` with a benign literal value -- expect 0 findings.
- **Differential arm.** Synthetic boundary shim (`control_config.synthetic: [W2, W4]`
  in `redis.yaml`); no server-side guard exists to toggle.

### 3. `simple-streamablehttp` (http)

- **Expected classes.** W2 only, and only through the single tool's `caller`
  argument (a content-processing hook, not a store-and-recall pair -- see
  `streamablehttp.yaml`'s header comment). W1/W3/W4 have no applicable seed on this
  server (no tool-description-poisoning surface Mylonite can plant, no egress tool,
  no consequential-action tool) and are expected to read NOT TESTED with a named
  reason code, not a silent skip.
- **Pass outcome.** KEPT/not-kept/NOT TESTED as above for W2; NOT TESTED with a
  reason code for W1/W3/W4 is the expected (not a failing) result.
- **Precision arm.** A benign `caller` string -- expect 0 findings.
- **Differential arm.** Synthetic boundary shim (`control_config.synthetic: [W2]`).

### 4. `server-everything` (stdio) -- N=1 smoke, no verdict claimed

- **Expected outcome.** `scan --scaffold` introspects the full tool/resource/prompt
  surface without error; one `scan` run against it completes without a traceback.
  Every attempt that finds no applicable seed reads NOT TESTED with a reason code.
  No KEPT/not-kept verdict is claimed for this target.

### 5. `go-sdk` memory example (stdio) -- N=1 smoke, no verdict claimed

- **Expected outcome.** The built Go binary launches over stdio and `scan --scaffold`
  introspects it like any other target (proving the Go runtime path). One `scan` run
  against it (same `weakness_classes: [W2, W4]` shape as target 1, since it is a
  structural clone) completes without a traceback. No verdict is claimed: this is a
  runtime-diversity smoke cell, not a second N=3 copy of target 1.

### 6. OpenAI Agents SDK agent on Ollama, over `rest` -- N=1 smoke, no verdict claimed

- **Expected outcome.** The shim starts, the agent answers a prompt, and one `scan`
  run against it (W2 only -- a `rest` target has no tool surface) completes without a
  traceback. Per `docs/http-agent.md`, any kept test on a `rest` target is capped at
  STABLE, NOT PROVEN, which under never-keep-unproven is a candidate, not a gate
  test -- so this target cannot produce a KEPT verdict by construction, and none is
  claimed.

## Rules for the runs

- **Fixed N = 3** for targets 1-3 (one workflow run per iteration), bar **>= 2/3**
  reaching the same classification (KEPT, or not-kept, or NOT TESTED with the same
  reason code) to claim that cell's result. **N = 1** for targets 4-6; their result is
  recorded as a smoke-cell pass/fail (did it crash) with no verdict.
- **No extra runs.** A re-run is allowed only for a named infrastructure failure
  (runner crash, provider 5xx outage, the `redis:7` service container or the shim
  failing to start, Ollama failing to serve the model) and is logged with its reason
  in the committed results write-up. A result nobody likes is never grounds for a
  re-run.
- **All outcomes are published**, kept or not, under
  `verification/results/<version>/third-party/`.
- **Every command carries `--authorize <family>`**, matching the target's `family`
  field exactly (see the table above and `SECURITY.md`).
- **Reason codes, not silence.** Every NOT TESTED attempt in a published result names
  its reason code (see `docs/reason-codes.md`); a scan that produces zero findings
  with no reason code anywhere is treated as a tooling defect, not a clean pass, and
  is logged as a product issue rather than counted toward the bar.

## Budget

Follows the L2 LLM budget table (local planning doc; the public commitment is "every
live call runs in CI, costed, and published"): $4.50 Anthropic + $5.00 OpenAI for the
whole campaign (targets 1-6, all N). Each workflow run's `--max-llm-calls` is sized
from the TPV-0 pilot's measured cost-per-call (one cell, $0.50 Anthropic + $0.50
OpenAI, run before the campaign) so the worst case fits the remaining allocation.
Target 6's own-agent inference runs on Ollama at zero cost; only Mylonite's own
scan/judge calls (Anthropic or OpenAI) count against this budget.

## Provider and model

- **Anthropic:** `anthropic/claude-haiku-4-5-20251001`, matching the model already
  used throughout `verification/` and the release campaign (see
  `verification/README.md`).
- **OpenAI: the cheapest current small `*-mini` model with tool/function-calling
  support is `gpt-4o-mini`.** Checked against the live OpenAI pricing and model pages
  on 2026-10-02:
  - `gpt-4o-mini` -- **$0.15 / M input, $0.60 / M output** tokens, active, function
    calling confirmed (<https://developers.openai.com/api/docs/models/gpt-4o-mini>,
    <https://developers.openai.com/api/docs/pricing>).
  - Compared against every other current `*-mini` chat/tool-calling model: `gpt-5-mini`
    ($0.25 / $2.00, function calling confirmed), `gpt-4.1-mini` ($0.40 / $1.60, function
    calling confirmed), `gpt-5.4-mini` ($0.75 / $4.50). The `*-mini` audio/transcribe/
    realtime/image models were excluded: they are not text chat-completion models with
    the tool-calling shape Mylonite's planner/judge need.
  - `gpt-4o-mini` is therefore both the cheapest and the one already confirmed to
    support function calling, so it is the model this campaign uses for the OpenAI
    provider, via LiteLLM as `openai/gpt-4o-mini`.

## Fixed in advance

- **Mylonite:** the version built by the workflow from the dispatched `ref` (the same
  "build a wheel, install into a clean venv outside the checkout" pattern
  `verification-campaign.yml` already uses), never a working-tree copy.
- **Target pins:** exact commit or published-package version per target, recorded in
  `verification/SOURCE.md` before this prereg was committed.
- **Iterations:** N=3 for targets 1-3, N=1 for targets 4-6 (see "Rules for the runs").
- **State:** every run starts from fresh state (a new `MEMORY_FILE_PATH`, a fresh
  `redis:7` container, a fresh in-process Go knowledge graph, a fresh Ollama
  conversation), so nothing left by one run can read as another run's effect.
- **Target files:** committed as-is in `verification/third_party/` before the counted
  runs. Changing one after seeing results needs a new pass rule.
- **Models:** Anthropic `claude-haiku-4-5-20251001` and OpenAI `gpt-4o-mini`, both
  pinned above, run against every target (targets 1-6); one additional Ollama cell
  (zero-cost) runs against target 1 only, per the roadmap's "one Ollama cell runs on
  server-memory."

## Stated with the result

- **Proof level per target:** named explicitly in the committed write-up -- KEPT /
  not-kept / NOT TESTED (with reason code) for targets 1-3, and a smoke-cell
  pass/fail for targets 4-6. STABLE, NOT PROVEN is the ceiling for target 6 by
  construction (black-box `rest` target).
- **Publication:** every outcome is published in
  `verification/results/<version>/third-party/`, `CAPABILITY_MATRIX.md`, `FINDINGS.md`
  and `TRENDS.md`, with the model, run count, commit/pin, cost (`cost.json`) and proof
  level. A product bug found along the way becomes a GitHub issue; this prereg does
  not get edited after the fact to match what was found.
