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
  "clean" result and never a traceback from Mylonite's own code.
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
  likes is never grounds for a re-run. **A Python traceback with a Mylonite stack
  frame anywhere in the captured log is a product defect, full stop.** A Mylonite
  stack frame is a quoted `File "...mylonite/....py"` line, with `mylonite` as a
  path segment; the word "mylonite" appearing elsewhere in the traceback's text
  does not count. This check runs BEFORE the infra signature check and overrides
  it: Mylonite's own code is designed to catch and cleanly report provider/config
  errors, so a raw traceback from its own code means something it did not
  anticipate, whatever the traceback's own text says. A product defect is logged as
  a GitHub issue, scored as not counted toward the bar, and is explicitly NOT
  auto-re-run -- re-running a product crash as if it were a flaky runner would
  silently hide the bug this campaign exists to surface. **A traceback with no
  Mylonite stack frame is target noise, not a product defect.** The stdio adapter
  does not separate a spawned target server's stderr from Mylonite's own output,
  so the server's own crash lands in the same log. Such a traceback is recorded
  (`target_noise_traceback: true` in the score) and the run is scored as usual.
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
- **A reason code counts only for the stage that printed it.** `scan`, `generate`
  and `validate` each write their own log (`scan.log`, `generate.log`,
  `validate.log`) beside the combined `run.log`. A result scored from the scan
  directory takes its reason codes from `scan.log`; a result scored from
  `validate`'s directory takes them from `validate.log`. So the N=3 agreement key
  for a `validate` result never depends on which seeds that run's `scan` happened
  to skip.
- **A `validate` that stops at its ceiling is NOT_TESTED, keyed on `MYL-ABT-001`.**
  When `validate` reaches its request ceiling it prints one `[MYL-ABT-001]` line,
  exits 3 and writes no `validation_report.json`. The cell then reads NOT_TESTED
  with exactly the abort code(s) in `validate.log` (`MYL-ABT-001` for the ceiling),
  whether or not `generate`'s trimmed `scan_report.json` sits in the same
  directory. A `validate` that writes no report and prints no abort code is
  INVALID if `validate.log` carries an infrastructure signature, otherwise a
  product defect.
- **A scan that stopped at its ceiling but still recorded a finding goes on to
  `validate`, and the cell is scored on the `validate` outcome.** The finding is
  real evidence, whatever cut the scan short, so `generate` and `validate` run on
  it as usual, and the scan's abort code plays no part in the cell's key. A scan
  that stopped with no finding is scored from the scan directory: NOT_TESTED with
  the scan's abort code.
- **Multiple findings in one scan: only the first is validated and scored.** `generate`
  writes each finding into its own `generated/<slug>/` subdirectory once there are
  two or more, and pointing `validate` at the parent directory in that case finds no
  `exploit_*.json` and fails -- so the workflow passes one explicit `exploit_*.json`
  path (sorted first by pattern_id) rather than `--latest`/a bare scan directory. This
  is a known, documented scope limit for this round, not a crash: a cell with more
  than one finding reports a verdict for the first finding only.

## Budget and the hard ceiling

**The hard ceiling is Mylonite's own request ceiling (#282).** Setting
`MYLONITE_MAX_LLM_REQUESTS` (or the global `--max-llm-requests` flag) caps the LLM
requests one process may send, retries included. The request past the ceiling is
refused before it is sent; the process prints one `[MYL-ABT-001]` line, exits 3, and
the result is NOT TESTED. The ceiling counts requests, not dollars: there is still
no spend cap in the CLI, config or `LLMPolicy`, so the dollar bound below is
ceiling x price per request.

`generate` makes no LLM call at all (`cli.py:1566`; it is offline and
deterministic), so the two processes that spend are `scan` and `validate`. They run
one after the other, each its own process with its own ceiling, so a cell's bound
is **the sum of the two ceilings**, not one counter shared by all three commands.
The workflow sets each as a one-off override on its own command
(`MYLONITE_MAX_LLM_REQUESTS=$X "$MYLONITE" scan ...`, and again for `validate` with
its own value), from the `scan_ceiling` and `validate_ceiling` dispatch inputs. A
trip never fails the workflow step: the exit code is captured like any other, and
the scorer reads `MYL-ABT-001` from that stage's own log (see "Rules for the
runs").

**Sizing the two ceilings, from `src/` (not yet from a live measurement -- see
"Pilot procedure" below for how the real values get set).** A seed's live cost is
roughly: 1 customiser call, 1-8 planner calls (`DEFAULT_ITERATION_CAP=8`, about 3
typical), 0-1 judge call -- call it **4 calls/seed realistic, 10 at worst**. Scan's
own seed count, from synthesis (`seed_synth.py:303-405`, `seeds.py:860+`): kitchen W2
(3) + kitchen W4 (<=2) + synthesised W4 (cap 8) gives roughly 10-13 seeds for targets
1, 2 and 5 (memory, redis, go-memory); target 3 likely has few or none; target 6 has
1. So **scan needs about 1 preflight + 12 x 4 ~= 50 calls realistically, and ~110 at
worst.** `validate` (custom-target path, `reference_validator.py:692-870`, with
`--prove-control`, `--iterations 3`) runs 3 raw + 3 guarded single-seed scans at
about 5 calls each, plus up to 9 consensus-judge calls (3 x 3) and 1 preflight --
**about 40 calls realistically, 70 at worst.** `--iterations` stays at 3 (not
dropped to 2): a lower `--iterations` also lowers `vuln_threshold` to 1, a weaker
bar than this campaign wants.

**The two ceilings, chosen with headroom over those estimates:**

- **scan: `MYLONITE_MAX_LLM_REQUESTS=120`**, with `--max-llm-calls` fixed at `60`
  (no longer dispatch-driven).
- **validate: `MYLONITE_MAX_LLM_REQUESTS=80`**, at `--iterations` fixed at `3`.

Exposed as two clamped `workflow_dispatch` inputs, `scan_ceiling` (default 120, hard
cap 150) and `validate_ceiling` (default 80, hard cap 100), so the pilot result
below can be applied by re-dispatching with different input values -- no code
change needed. **A ceiling of 30 for both processes (an earlier draft of this
section) starves targets 1-2 and 5: every realistic scan or validate run would hit
the ceiling and read NOT TESTED while still spending the money to get there.**

**Realistic and worst-case cost per cell, per-call cost `$1`/`$5` per M (Haiku 4.5)
and `$0.15`/`$0.60` per M (gpt-4o-mini), assuming ~1,500 input / ~250 output tokens
per call on average (cheaper than the 8k/2048 ceiling-based bound further down,
which prices the theoretical maximum, not the typical call):**

| Cell | Calls (realistic / cap) | Realistic cost (Haiku / mini) | Worst-case cost (Haiku / mini) |
|---|---|---|---|
| Full journey (scan + validate, targets 1-2) | ~90 / 200 | $0.41 / $0.06 | $3.65 / $0.49 |
| Scan only (smoke targets) | ~50 / 120 | $0.23 / $0.03 | $2.19 / $0.29 |

**Campaign fit, for one provider (N=3 for targets 1-3, N=1 for targets 4-6, ~800
calls total):**

- **Realistically, about $3.6 on Haiku 4.5** -- fits the $4.50 allocation with
  roughly 20% headroom and no re-runs. gpt-4o-mini comes to about $0.50 and fits
  easily.
- **At the worst case (every call maxed on every retry), Haiku comes to about $39
  and gpt-4o-mini to about $5.2** -- both over their allocations. This is why the
  worst-case figures above are never described as "well inside a cell's share" (an
  earlier draft of this section said so, which 12 cells x ~$1 contradicts): **the
  provider-side spend cap on both keys is the real stop for the worst case**, not
  this workflow's own ceilings, which are sized for the realistic case.
- **A 30-minute job `timeout-minutes`** is the outer backstop, independent of
  Mylonite's own ceiling.

**These estimates are uncertain** (redis's larger tool schemas, for one, may push
real input above the ~1,500-token assumption) -- see "Pilot procedure" below for how
the real ceilings get set before any counted run.

## Pilot procedure (run before any counted run, and never itself counted)

Before targets 1-3's N=3 runs or targets 4-6's N=1 runs begin, dispatch **one
uncounted pilot cell**: `target=tpv-mcp-redis`, `provider=openai` (gpt-4o-mini, the
cheaper provider, for the pilot's own cost), with the `scan_ceiling`/
`validate_ceiling` defaults above (120/80). This result does not count toward any
bar and is not one of the N re-drives for target 2.

1. **Read scan's and validate's spend separately.** Each prints its own `llm: N
   calls | P in / C out tokens` line: read scan's from `scan.log` and validate's
   from `validate.log`. Do not use `cost.json`'s `calls`, which is the two added
   together.
2. **Set each process's real ceiling to about 1.5x what it actually used**, capped
   at the hard clamps (150 for scan, 100 for validate) -- e.g. if the pilot's scan
   used 65 calls, set `scan_ceiling` to 98 for the counted runs (65 x 1.5), not
   above 150 regardless of the multiple.
   - **If the pilot trips a ceiling** (that stage's log has `[MYL-ABT-001]` and it
     exited 3), its count is the ceiling, not what the stage needed. Raise that
     ceiling (scan to 150, validate to 100 at most) and re-run the pilot once.
     Record both pilot runs. If the re-run trips again at the clamp, the clamp
     stands and the prereg says so; the clamp is not raised for the counted runs.
   - **If the scan finds nothing on target 2**, `validate` never runs and cannot be
     measured. Keep validate's ceiling at the estimate from `src/` above (80) and
     say so in the recorded result.
3. **Commit the pilot's result and the chosen ceilings to this file, before
   dispatching the first counted run.** Record: the pilot's dispatch (run URL),
   the measured calls and input/output tokens for scan and for validate (each
   from its own log), whether either stage tripped its ceiling and was re-run,
   the computed 1.5x ceilings (or the estimate kept for an unmeasured validate),
   and the commit SHA of that update. A
   counted run dispatched before this commit exists is invalid for this prereg's
   purposes -- re-dispatch it after the ceilings are committed.

### Pilot result (recorded before the first counted run)

The pilot ran once, uncounted, before any N=3 or N=1 dispatch against targets
1-6.

- **Dispatch.** https://github.com/Abidemialade/mylonite/actions/runs/37050385269
  -- `target=tpv-mcp-redis`, `provider=openai` (gpt-4o-mini),
  `scan_ceiling=120`, `validate_ceiling=80`, ref
  `f32906b0604869a4363b8383bd3f5b174c5699d9`. This result does not count
  toward target 2's N=3 bar.
- **Spend.** `scan`: 14 calls (1 customiser, 13 planner), 74,822 input / 411
  output tokens. `validate`: 13 calls (13 planner), 64,862 input / 280 output
  tokens. Total: 27 calls, $0.021. Neither stage tripped its ceiling.
- **Outcome (not counted toward any bar).** KEPT, W4, on the unconfirmed-delete
  seed -- but the effect probe's calibration failed (`MYL-INC-005`), so the
  keep rests on the differential leg against Mylonite's synthetic boundary
  shim, not on a state read-back confirming the delete actually happened. W2
  read NOT TESTED (`MYL-NT-006`). No traceback anywhere in the captured log;
  `scan`, `generate` and `validate` all exited 0.
- **Ceilings for the counted runs: `scan_ceiling=60`, `validate_ceiling=40`.**
  This is not the mechanical "about 1.5x" step above -- 1.5x of the pilot's
  measured calls is 21 (scan) and 20 (validate, 19.5 rounded up). The pilot
  ran on target 2 only, and the "Sizing the two ceilings" estimate earlier in
  this file puts redis's seed count at the low end: targets 1 and 5 carry
  roughly 10-13 seeds against redis's smaller count. Applying 21/20 to targets
  1 and 5 would predictably trip the ceiling there, turning counted runs into
  NOT TESTED before they produced a verdict -- the thing this pilot exists to
  prevent. 60 and 40 instead track that section's own realistic estimate for a
  full journey (~50 scan calls, ~40 validate calls), with headroom on scan.
  Both stay under the hard clamps (150 / 100):
  - **Realistic cost per cell at 60/40** (the file's own ~1,500 input / ~250
    output tokens per call): Haiku 4.5 (`$1`/`$5` per M) $0.28; gpt-4o-mini
    (`$0.15`/`$0.60` per M) $0.04.
  - **Worst-case cost per cell at 60/40** (all 100 calls maxed at 8k input /
    2048 output tokens): Haiku 4.5 $1.82; gpt-4o-mini $0.24.

  60/40 is a hard bound for the counted runs regardless of the figures above:
  a run that still trips it reads NOT TESTED on `MYL-ABT-001`, per "Rules for
  the runs."

## Other spend controls

- **One target, one provider, no model override, per dispatch.** No "all"/"both"
  fan-out and no free-text model input -- the model is fixed per provider
  (`claude-haiku-4-5-20251001` for Anthropic, `gpt-4o-mini` for OpenAI; see
  "Provider and model" below) so neither cost estimate above can be invalidated by
  a dispatch picking an expensive model.
- **`MYLONITE_MAX_TOKENS=2048`** is set on the one step that calls the CLI, bounding
  each call's OUTPUT tokens (there is no `--max-tokens` CLI flag; this is the
  documented env-var equivalent -- see `config.py`'s `MYLONITE_MAX_TOKENS`). It does
  NOT bound input tokens.

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
  Targets 1-3 run the full journey -- `scan` then `generate` (on one explicit
  `exploit_*.json` path, not `--latest`/a bare scan dir -- see "Rules for the runs"'
  multi-finding note) then `validate --iterations 3` (keeps the live differential
  loop's own call count bounded, separate from the N=3 workflow-dispatch re-drive
  count above). Targets 4-6 run `scan` only: they claim no verdict, and
  `generate`/`validate` need an actual finding to operate on, which a smoke cell
  makes no promise of producing.
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

## Amendments during the counted runs

Recorded before the affected cells were re-run; neither changes a pass rule.

- **2026-10-03, Anthropic credential (infrastructure).** The first three counted Anthropic
  dispatches (targets 1-3, run 1) stopped at the key check before any target launched:
  the CI secret held an expired key (HTTP 401). No request was billed and no outcome was
  produced. This is a named infrastructure failure under "No extra runs"; the key was
  rotated and those cells were re-dispatched on the same commit.
- **2026-10-03, target 3 harness flag (configuration).** Target 3 declares W2 with no
  `seed_arm` (its only W2 route is a tool argument, see "3. `simple-streamablehttp`").
  `scan` refuses that combination unless `--allow-no-seed-arm` is passed, so the first
  counted dispatch stopped before any request, with no outcome. The workflow now passes
  `--allow-no-seed-arm` for target 3 only, which makes W2 read NOT TESTED as this prereg
  already expects. The cell was re-run after this change.
- **2026-10-03, target 6 shim install (infrastructure).** Both smoke dispatches for
  target 6 stopped while installing the agent shim, before Mylonite ran: the shim's
  `openai-agents` pin needs `openai>=3`, and the LiteLLM pin needed `openai<3`, so pip
  refused both. No request was billed. The shim now installs in its own virtualenv,
  since it is the target and not Mylonite, and both cells were re-run.
