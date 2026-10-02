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
- **No extra runs.** A re-run is allowed only for a named infrastructure failure,
  positively evidenced by an anchored signature in the captured log (a specific
  provider/network exception class name, or a specific line such as a DNS-resolution
  failure or a GitHub Actions runner-shutdown notice -- never a bare word or number
  like "timeout" or "503", which can appear in ordinary log text, e.g. a token count),
  and is logged with its reason in the committed results write-up. A result nobody
  likes is never grounds for a re-run. **Any Python traceback anywhere in the
  captured log is a product defect, full stop** -- this check runs BEFORE the infra
  signature check and overrides it: Mylonite's own code is designed to catch and
  cleanly report provider/config errors, so a raw traceback means something it did
  not anticipate, whatever the traceback's own text says. A product defect is logged
  as a GitHub issue, scored as not counted toward the bar, and is explicitly NOT
  auto-re-run -- re-running a product crash as if it were a flaky runner would
  silently hide the bug this campaign exists to surface.
- **All outcomes are published**, kept or not, under
  `verification/results/<version>/third-party/`.
- **Every command carries `--authorize <family>`**, matching the target's `family`
  field exactly (see the table above and `SECURITY.md`).
- **Reason codes, not silence.** NOT_TESTED REQUIRES a reason code (see
  `docs/reason-codes.md`) -- an aborted scan or one that was never exercised, with no
  reason code found anywhere (an attempt's own text, or the abort's own code printed
  to the log; `scan_report.json` itself never carries the abort's `MYL-ABT-*` code),
  is a **product defect**, never a silent, code-free NOT_TESTED. Separately: if a
  scan's attempts include one whose outcome is anything other than `finding`/
  `no_finding` (a skip, an error, `undecided`, `not_applicable`) with **no** reason
  code attached, that attempt's gap is never silently absorbed into a clean
  0-findings result -- the whole run is scored as a product defect rather than
  counted as NOT_KEPT or NOT_TESTED, even if some OTHER attempt in the same run was
  cleanly judged.
- **Multiple findings in one scan: only the first is validated and scored.** `generate`
  writes each finding into its own `generated/<slug>/` subdirectory once there are
  two or more, and pointing `validate` at the parent directory in that case finds no
  `exploit_*.json` and fails -- so the workflow passes one explicit `exploit_*.json`
  path (sorted first by pattern_id) rather than `--latest`/a bare scan directory. This
  is a known, documented scope limit for this round, not a crash: a cell with more
  than one finding reports a verdict for the first finding only.

## Budget and the hard ceiling

**Today, with no hard ceiling landed, the real worst case is far above the naive
"60 calls" estimate an earlier draft of this section used.** `--max-llm-calls` bounds
only the scan phase's planner loop, and even there "not a hard ceiling": each seed
keeps its own floor (`60 + (S-1)*max(2, 60/S)`, about 258 calls at 100 seeds).
`validate` runs with **no budget at all** -- 6 re-drives (3 iterations x 2 twins) each
against the default `ScanConfig` cap of 50, plus up to 3 consensus-judge calls per
firing run, roughly 310 more calls -- and LiteLLM's own `num_retries=2` is not counted
in any of the above, so a billed-retry run can cost up to 3x again. **Worst case today
is on the order of 570 counted calls per cell**, which at 2048 output tokens and
3k-8k input tokens per call is roughly **$7.5-10.4 on Haiku 4.5** and **$0.96-1.39 on
gpt-4o-mini** -- up to 3x either figure with billed retries. One Haiku cell can
therefore use the whole $4.50 Anthropic allocation and most of the $10 total. This is
reported here, not hidden; it is the reason Critical B of the fix-round-1 re-review
exists.

**No change needed in `src/` for this PR.** `mylonite` has no hard ceiling on LLM
calls or spend today: there is no `--max-budget`/spend-cap option anywhere in the
CLI, config, or `LLMPolicy` (which forwards only a fixed allowlist of LiteLLM kwargs
-- `api_base`, `max_tokens`, `temperature`, `timeout`, `num_retries` -- not LiteLLM's
own `max_budget`). **BUDGET-1, a separate PR, is adding a hard LLM-call ceiling,
applied per process** (including retries). `generate` makes no LLM call at all
(`cli.py:1566` -- it is offline and deterministic), so the two processes that matter
are `scan` and `validate`, run one after the other, each its own process with its
own ceiling -- a per-cell bound is therefore **ceiling x 2**, not a single shared
counter across all three commands (an earlier draft of this section wrongly said
"counted across scan + generate + validate"; fixed here). This workflow already
wires a placeholder for the env var name: `MYLONITE_MAX_LLM_REQUESTS`, set
identically on both processes (they share the run step's `env:`) from a single
hardcoded value (not the dispatch's own `max_llm_calls` input -- see why below), in
exactly one place in the workflow file, so the controller can correct the name to
whatever BUDGET-1 actually lands with. Until that PR lands, the env var is a
harmless no-op -- nothing in `src/` reads it yet -- and today's only two REAL stops
are:

1. **A 30-minute job `timeout-minutes`.** Given the worst case above, this is the one
   backstop that does not depend on any of Mylonite's own budget flags landing or
   working as documented.
2. **A provider-side spend limit on both keys.** The keys this campaign uses
   (`MYLONITE_LLM_KEY`, `MYLONITE_OPENAI_KEY`) should carry a provider-configured
   spend cap; this is an operational step for whoever provisions the keys, not
   something this workflow can enforce itself, and it is the only stop that is
   genuinely independent of a bug anywhere in this chain.

**The per-cell worst case, once BUDGET-1 lands, restates as**

```
ceiling x processes x (max_input_tokens x input_price + max_output_tokens x output_price)
```

with **processes = 2** (`scan`, `validate` -- `generate` makes none), **max_input_tokens
= 8,000** (the top of this section's own 3k-8k/call estimate; `max_tokens` bounds only
the OUTPUT leg, so input is NOT capped by it -- an earlier draft of this section
wrongly claimed `max_tokens` "overstates input but never understates the total",
which is false whenever actual input exceeds `max_tokens`, as it does here) and
**max_output_tokens = 2,048** (`MYLONITE_MAX_TOKENS`).

**`MYLONITE_MAX_LLM_REQUESTS` is set to a hardcoded `30` (half the dispatch's own
clamped `max_llm_calls`, and NOT driven by that input)** specifically so the
2-process total lands back near the single-process ballpark an earlier draft of
this section assumed, keeping the whole cell inside a sensible share of the totals
below -- no single cell's hard-ceiling exposure should be able to consume more than
roughly a quarter of the whole campaign's allocation for one provider, even in the
genuine worst case (every call maxed out on every retry, which the typical ~$0.005/
call figure elsewhere in this repo says is far from the expected case):

| Model | `30 x 2 x (8000 x in + 2048 x out) / 1e6` | Worst case per cell |
|---|---|---|
| Haiku 4.5 (`$1`/`$5` per M) | `30 * 2 * (8000*1 + 2048*5) / 1e6` | **~$1.09** |
| gpt-4o-mini (`$0.15`/`$0.60` per M) | `30 * 2 * (8000*0.15 + 2048*0.60) / 1e6` | **~$0.15** |

Both are well inside a single cell's share of the campaign budget below -- but
neither number is **real** until BUDGET-1 actually lands and enforces the ceiling;
until then, see the worst case stated above (570 calls, no per-process ceiling) and
rely on the job timeout.

**Other spend controls already in place, independent of BUDGET-1:**

- **One target, one provider, no model override, per dispatch.** No "all"/"both"
  fan-out and no free-text model input -- the model is fixed per provider
  (`claude-haiku-4-5-20251001` for Anthropic, `gpt-4o-mini` for OpenAI; see
  "Provider and model" below) so neither worst-case estimate above can be invalidated
  by a dispatch picking an expensive model.
- **`MYLONITE_MAX_TOKENS=2048`** is set on the one step that calls the CLI, bounding
  each call's OUTPUT tokens (there is no `--max-tokens` CLI flag; this is the
  documented env-var equivalent -- see `config.py`'s `MYLONITE_MAX_TOKENS`). It does
  NOT bound input tokens, which is why the restated formula above prices the input
  leg separately at 8k rather than reusing this same figure.
- **`scan --max-llm-calls` stays driven by the (separately clamped-to-60) dispatch
  input**, representing the user's intended scan budget; `MYLONITE_MAX_LLM_REQUESTS`
  is a stricter, independently-sized hard backstop underneath it, not the same
  number re-used for two different purposes.

Total campaign budget: $4.50 Anthropic + $5.00 OpenAI across targets 1-6. Target 6's
own-agent inference runs on Ollama at zero cost regardless of which provider drives
Mylonite's own `scan`/`validate` calls; only those calls (Anthropic or OpenAI) count
against this budget.

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
