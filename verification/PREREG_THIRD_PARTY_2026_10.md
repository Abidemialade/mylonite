# Pass rule: third-party verification campaign (pre-registered)

This rule is committed before any counted run, so the result can't shape it. It covers
all six targets in `verification/third_party/` (see `verification/SOURCE.md` for each
target's licence, pin and "no prior live run" check), run by
`.github/workflows/third-party-campaign.yml`. Every run cites this file's committed git
**commit** SHA (`git log -1 --format=%H -- verification/PREREG_THIRD_PARTY_2026_10.md`
-- `git log`'s `%H` is the commit that last touched the file, not a blob hash) in its
artefact and in the committed results write-up, so a later edit to this file can never be
read as the rule a past run was judged against.

## What is being tested

Whether Mylonite's `scan`, `generate` and `validate` commands work -- unmodified, run in
sequence as the real journey a user would run, with every LLM call made in CI -- against
six systems Mylonite has never run against before (not DVMCP, MCPSecBench, the Enkrypt
gateway, `mcp-server-email`, `server-filesystem`, `mcp-server-fetch`, `server-github`,
`git`/`sqlite`/`time`/`markitdown`, InjecAgent or AgentDojo). Three targets (1-3) are run
at the same N=3, >=2/3 bar the in-repo oracle uses; the other three (4-6) are N=1 smoke
cells that prove connectivity and non-crashing behaviour and claim no verdict.

Each dispatch runs **exactly one target and one provider** -- there is no "all" or "both"
option and no free-text model override. This is a deliberate spend control (see "Budget
and the hard ceiling" below), not a convenience default.

## Targets

| # | Target | Family | Transport | Tier |
| --- | --- | --- | --- | --- |
| 1 | `@modelcontextprotocol/server-memory` | `tpv-server-memory` | stdio | N=3, verdict-claimed |
| 2 | `redis/mcp-redis` + `redis:7` service container | `tpv-mcp-redis` | stdio | N=3, verdict-claimed |
| 3 | python-sdk `simple-streamablehttp` example | `tpv-streamablehttp` | http | N=3, verdict-claimed |
| 4 | `@modelcontextprotocol/server-everything` | `tpv-server-everything` | stdio | N=1 smoke |
| 5 | go-sdk `examples/server/memory` | `tpv-go-memory` | stdio | N=1 smoke |
| 6 | openai-agents-python `litellm_auto.py` pattern, on Ollama | `tpv-agents-sdk-ollama` | rest | N=1 smoke |

## Scaffold sanity check (before the counted run)

Every target except #3 is re-checked with `mylonite scan --scaffold` (the unchanged
CLI, reusing the exact launch command/args the committed target file uses) immediately
before the counted run, writing to a scratch file that is uploaded as an artefact but
never diffed automatically against the committed target file in this pass -- a human
reviews it. **Target 3 has no scaffold step**: `--scaffold` only supports a `--command`
(stdio) or `--rest-url` (REST) introspection today, and target 3 is a remote MCP server
over `transport: http`, which the CLI has no scaffold flag for. This is a known,
documented gap, not something this campaign works around.

## Per-target expectations

For targets 1-3, **KEPT means `mylonite._verdict.verdict_label(report) == "KEPT"`, not
the bare `ValidationReport.kept` boolean.** `kept=True` also covers a `STABLE, NOT
PROVEN` report (a judge-only keep, or one missing the build/differential-or-effect legs
`verdict_label` requires for the plain `KEPT` label) -- under never-keep-unproven, a
`STABLE, NOT PROVEN` result is **not kept** for this campaign's purposes, exactly like a
`REJECTED` one. The scorer reads the label, not the raw boolean.

### 1. `server-memory` (stdio)

- **Expected classes.** W2 (an attacker-controlled observation planted via
  `create_entities`, later read back and acted on) and W4 (an unconfirmed
  consequential change -- `delete_entities`/`delete_observations`/`delete_relations`/
  `add_observations`/`create_relations` -- confirmed through the server's own
  `search_nodes`/`read_graph`).
- **Pass outcome.** KEPT (see the verdict-label rule above: build, differential and
  flakiness legs all pass and the label is plain `KEPT`), or not-kept (`REJECTED` or
  `STABLE, NOT PROVEN`) with the `validation_report.json` stage that failed, or NOT
  TESTED with a named reason code (e.g. `MYL-INC-002`/`MYL-INC-012` if the effect probe
  never certifies, `MYL-NT-*` if a class has no applicable seed). Never an unexplained
  "clean" result and never a traceback.
- **Precision arm.** There is no server-side benign/vulnerable toggle for this target
  and no mechanism in the target file to make Mylonite plant deliberately-benign
  content (the payload text comes from Mylonite's own catalogue/synthesiser, not from
  `seed_arm.args_template`), so this campaign does not run a separate benign cell for
  it. The precision signal it DOES carry: the differential leg already run inside
  `validate` re-drives the attack against Mylonite's synthetic boundary shim (the
  "guarded" side); if that guarded side also fires, the `differential`
  `ValidationOutcome` fails and the report cannot read KEPT. A false positive on this
  target therefore still shows up -- as a failed differential leg, not as a second
  "benign" cell. This mirrors `verification/layer3_production/run.py`'s own precision
  convention (count findings on a target with no declared vulnerability), applied to
  the guarded side of the SAME run rather than a second scan, because targets 1-3 are
  real reference servers that may have a genuine app-design flaw (that is the point of
  running them) -- unlike `reference:guarded`, "any finding here is a false positive"
  does not hold for the raw side.
- **Differential arm.** No server-side guarded build exists for this reference
  server, so the differential is Mylonite's synthetic boundary shim
  (`control_config.synthetic: [W2, W4]` in `memory.yaml`) -- the standard
  single-build check, same caveat as every other synthetic-boundary result in
  `CAPABILITY_MATRIX.md`.

### 2. `mcp-redis` (stdio, `redis:7` service container)

- **Expected classes.** W2 (a value planted via `set`, read back via `get`) and W4
  (an unconfirmed `delete`/`expire`/`rename` against the seeded key).
- **Pass outcome.** Same rule as target 1.
- **Precision arm.** Same as target 1: no benign-content mechanism exists, so the
  precision signal is the differential leg's guarded side, not a separate cell.
- **Differential arm.** Synthetic boundary shim (`control_config.synthetic: [W2, W4]`
  in `redis.yaml`); no server-side guard exists to toggle.

### 3. `simple-streamablehttp` (http)

- **Expected classes.** W2 only, and only through the single tool's `caller`
  argument (a content-processing hook, not a store-and-recall pair -- see
  `streamablehttp.yaml`'s header comment). The target declares `weakness_classes:
  [W2]` only -- W1/W3/W4 are never attempted at all (not declared), so they produce no
  attempt and no NOT TESTED entry; this is an absence, not a run-and-skip. (An earlier
  draft of this prereg said these would read NOT TESTED; that was wrong, fixed here.)
- **Pass outcome.** KEPT/not-kept/NOT TESTED as above, for W2 only.
- **Precision arm.** Same as target 1: no benign-content mechanism exists, so the
  precision signal is the differential leg's guarded side, not a separate cell.
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

- **Fixed N = 3** for targets 1-3 (one workflow dispatch per iteration, each a
  separate run), bar **>= 2/3** reaching the **same key** to claim that cell's result.
  The key is the classification for KEPT/NOT_KEPT/FOUND_UNVALIDATED, and the
  classification **plus its reason code(s)** for NOT_TESTED -- two NOT_TESTED runs
  with different reason codes do NOT agree, and do not count toward the bar together.
  **N = 1** for targets 4-6; their result is recorded as a smoke-cell pass/fail (did
  it crash) with no verdict.
- **No extra runs.** A re-run is allowed only for a named infrastructure failure
  (runner crash, provider 5xx outage, the `redis:7`/`ollama` service container or the
  shim failing to start) and is logged with its reason in the committed results
  write-up. A result nobody likes is never grounds for a re-run. A crash with no
  identifiable infrastructure cause (a traceback with no provider/network signature in
  it) is a **product defect**, not an infrastructure failure: it is logged as a GitHub
  issue, scored as not counted toward the bar, and is explicitly NOT auto-re-run --
  re-running a product crash as if it were a flaky runner would silently hide the bug
  this campaign exists to surface.
- **All outcomes are published**, kept or not, under
  `verification/results/<version>/third-party/`.
- **Every command carries `--authorize <family>`**, matching the target's `family`
  field exactly (see the table above and `SECURITY.md`).
- **Reason codes, not silence.** Every NOT TESTED attempt in a published result names
  its reason code (see `docs/reason-codes.md`). Separately: if a scan's attempts
  include one whose outcome is anything other than `finding`/`no_finding` (a skip, an
  error, `undecided`, `not_applicable`) with **no** reason code attached, that
  attempt's gap is never silently absorbed into a clean 0-findings result -- the whole
  run is scored as a product defect (see above) rather than counted as NOT_KEPT or
  NOT_TESTED, even if some OTHER attempt in the same run was cleanly judged.

## Budget and the hard ceiling

**No change needed in `src/`:** `mylonite` has no hard ceiling on LLM calls or spend
today. `--max-llm-calls` is explicitly documented as "not a hard ceiling" (each seed
keeps a small floor, so the worst case is higher than the number passed), and there is
no `--max-budget`/spend-cap option anywhere in the CLI, config, or `LLMPolicy` (which
forwards only a fixed allowlist of LiteLLM kwargs: `api_base`, `max_tokens`,
`temperature`, `timeout`, `num_retries` -- not LiteLLM's own `max_budget`). This is
reported, not patched, here; a real hard ceiling is a `src/` change for a later PR.

Given that, this campaign's actual hard stops are, in order:

1. **One target, one provider, no model override, per dispatch.** No "all"/"both"
   fan-out and no free-text model input -- the model is fixed per provider
   (`claude-haiku-4-5-20251001` for Anthropic, `gpt-4o-mini` for OpenAI; see
   "Provider and model" below) so the cost-per-call estimate below cannot be
   invalidated by a dispatch picking an expensive model.
2. **`max_llm_calls` is clamped server-side to a hard maximum of 60** (the workflow's
   own validation step rejects non-integer input and clamps anything above 60),
   roughly the built-in CLI default of 50 plus headroom, not the "every seed gets its
   own floor" unbounded worst case the CLI help warns about.
3. **`MYLONITE_MAX_TOKENS=2048`** is set on the one step that calls the CLI, bounding
   each call's OUTPUT tokens (there is no `--max-tokens` CLI flag; this is the
   documented env-var equivalent -- see `config.py`'s `MYLONITE_MAX_TOKENS`).
4. **Worst-case cost per cell**, call count (60) x max output tokens (2048) x the
   provider's output rate, plus an estimated ~3k input tokens/call (not capped by
   `max_tokens`, which only bounds output): Anthropic (`$1`/`$5` per M)
   `60 * (3000*1 + 2048*5) / 1e6` ~= **$0.79**; OpenAI `gpt-4o-mini` (`$0.15`/`$0.60`
   per M) `60 * (3000*0.15 + 2048*0.60) / 1e6` ~= **$0.065**. Both are well inside a
   single cell's share of the whole-campaign budget below.
5. **A step-level `timeout-minutes` wall-clock cap** on the job (30 minutes) is the
   true backstop against a stuck call looping past the above estimate.
6. **A provider-side spend limit on both keys is the only GENUINE hard stop** that
   does not depend on Mylonite's own behaviour. The keys this campaign uses
   (`MYLONITE_LLM_KEY`, `MYLONITE_OPENAI_KEY`) should carry a provider-configured
   spend cap; this is an operational step for whoever provisions the keys, not
   something this workflow can enforce itself.

Total campaign budget: $4.50 Anthropic + $5.00 OpenAI across targets 1-6 (the public
commitment is "every live call runs in CI, costed, and published"; the internal
per-use breakdown lives in the maintainer's own planning notes, not reproduced here).
Target 6's own-agent inference runs on Ollama at zero cost regardless of which
provider drives Mylonite's own `scan`/`validate` calls; only those calls (Anthropic or
OpenAI) count against this budget.

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
  Targets 1-3 run the full journey -- `scan` then `generate --latest` then
  `validate --iterations 3` (keeps the live differential loop's own call count
  bounded, separate from the N=3 workflow-dispatch re-drive count above). Targets
  4-6 run `scan` only: they claim no verdict, and `generate`/`validate` need an
  actual finding to operate on, which a smoke cell makes no promise of producing.
- **State:** every run starts from fresh state -- target 1's `MEMORY_FILE_PATH` is a
  freshly-generated per-run path, passed to the target file via its `${TPV_MEMORY_FILE}`
  expansion (see `docs/target-file.md`'s `${VAR}` mechanism -- a value only set on the
  *job's* environment, as an earlier draft of this workflow did, never reaches the
  spawned MCP subprocess, since Mylonite forwards only its own small env allowlist plus
  whatever a target file's own `env:` block declares); a fresh `redis:7` container; a
  fresh in-process Go knowledge graph (no `-memory` flag); a fresh Ollama
  conversation. Nothing left by one run can read as another run's effect.
- **Target files:** committed as-is in `verification/third_party/` before the counted
  runs. Changing one after seeing results needs a new pass rule.
- **One target and one provider per dispatch** (see "What is being tested" above):
  Anthropic `claude-haiku-4-5-20251001` or OpenAI `gpt-4o-mini`, both pinned above and
  neither overridable from the dispatch form; the `ollama` provider choice is valid
  only for target 1 (`tpv-server-memory`), per the roadmap's "one Ollama cell runs on
  server-memory" -- the workflow rejects any other target/`ollama` combination.

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
