# Independent verification

Most security tools grade themselves on ground truth they wrote. Mylonite ships a
deliberately-vulnerable reference agent *and* an answer key for it — which is useful but
circular: of course it scores well on the target it was built against. So Mylonite also
carries a separate **third-party verification harness** (`verification/`) that scores it
against external ground truth it **did not author** — runnable vulnerable MCP servers and
published academic benchmarks — and publishes the result here, **negatives included**.

This page is the scorecard. The numbers come from live runs between 25 June and
14 September 2026. **Claude Haiku 4.5** was the planner/judge for the DVMCP and precision
layers; the InjecAgent layer was run against a self-hosted `llama3.2:3b`. Samples are
small and cost-bounded. Read the caveats — several numbers mean less (or more) than they
look. The latest release-gated result set lives in
[`verification/results/0.11.0/`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.11.0),
measured in CI with Haiku 4.5 recording InjecAgent: Haiku resisted every case, so judge
agreement on InjecAgent is not exercised in 0.11.0 (earlier sets:
[`0.10.0`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.10.0),
[`0.9.0`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.9.0)),
with a per-release trend table in
[`TRENDS.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/TRENDS.md).

The single-model evidence base is the biggest caveat on this page. A second model has since
been run against the *bundled* targets (locally, zero cost) and the result is more
interesting than "a weaker model finds more": recall turned out **not** to be monotonic in
model weakness — a weaker planner raises exposure for attacks that need the model to comply,
and lowers it for attacks that need the model to be capable. Most numbers on this page
come from a single hosted model; the InjecAgent judge-agreement figures come from a
self-hosted one. Both are spelled out, with every other known gap, in
[Known limitations](limitations.md).

## Third-party verification campaign, live in CI (2026-10-03)

A separate campaign from the numbers above: six MCP and agent systems Mylonite had
never run against, with every LLM call made live inside GitHub Actions, never
replayed locally, scored against a rule committed before any run
([`PREREG_THIRD_PARTY_2026_10.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/PREREG_THIRD_PARTY_2026_10.md)).
Full write-up:
[`verification/results/0.12.0/third-party/README.md`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.12.0/third-party).

**Two targets Mylonite did not author kept a reproducible W4 finding — an unconfirmed
consequential change, observed in the tool-call trace and tied to the dispatched tool
call — across three independent re-drives, on both Haiku 4.5 and gpt-4o-mini:**

| Target | Result | Basis |
| --- | --- | --- |
| `@modelcontextprotocol/server-memory` | **KEPT**, W4 | 3/3 on Haiku 4.5; 2/3 (one honest REJECTED) on gpt-4o-mini; 1/1 on `llama3.2:3b` (informational, run once inside the CI runner) |
| `redis/mcp-redis` | **KEPT**, W4 | 3/3 on both Haiku 4.5 and gpt-4o-mini |

**Neither keep rests on a confirmed state read-back.** The effect probe failed to
calibrate on both targets (`MYL-INC-003` on `server-memory`, `MYL-INC-005` on
`mcp-redis`), on every run, KEPT and REJECTED alike, so the proof level is
`dispatched-tool-linked`, not `effect-confirmed` — see the full write-up's "Proof
level" section. Both differentials ran against Mylonite's synthetic boundary shim,
since neither target ships a server-side guard to toggle — the same caveat every
synthetic-boundary result on this page carries: proof the attack is real and that
this class of guard closes it, not proof about any one deployment's own guard.

Three other targets in the same campaign produced no security verdict: a streamable-HTTP
example server hit a product defect on every run (a missing seed arm reads as an
unclassified exception, [issue #319](https://github.com/Abidemialade/mylonite/issues/319),
closed, fixed by [PR #322](https://github.com/Abidemialade/mylonite/pull/322)), and
three smoke-only targets (no verdict was ever claimed for any of them) produced one
clean resist, one more instance of the same unclassified-exception bug (a different
cause: a target-side crash), an unvalidated finding, an infrastructure failure fixed
and re-dispatched per the prereg's own amendment, and a request that reached its
target with the wrong content type
(fixed by [PR #321](https://github.com/Abidemialade/mylonite/pull/321), merged after
the measured build). None of these were silently scored clean. Total spend: $0.91 on
Anthropic, $0.08 on OpenAI, $0 on the in-runner Ollama cell.

### Second round, complete: deeper proof, fix re-tests, precision, breadth

A follow-up pass against the same harness, pre-registered in
[`PREREG_E2E_2026_10.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/PREREG_E2E_2026_10.md)
before any counted run under it, is now complete. Full write-up, with every
run and every cell's bar:
[`verification/results/0.12.0/e2e/README.md`](https://github.com/Abidemialade/mylonite/tree/main/verification/results/0.12.0/e2e).

**Proof depth did not clear the stronger bar.** Both `server-memory` and
`mcp-redis` kept the same W4 finding as the first campaign, on nearly every
one of 6 counted re-drives each — but this round's bar asks for a `KEPT`
finding at `effect-confirmed` under a `certified` calibration, and neither
target's calibration reaches `certified` on any run: `server-memory`
calibrates `confirm_only` on every run (its own validate-measured effect
leg never exceeds `dispatched-tool-linked` either). `mcp-redis` calibrated
`failed` on every one of its two earlier, superseded rounds; a general
calibration fix repaired the bug that falsely produced that reading (it
mistook a store whose not-found reply echoes the requested key, as
Redis's does, for a failed control), and on the counted round calibration
reads `confirm_only` on every run — never `failed` again, but also never
`certified`, a structural ceiling of this target (its key is fixed in the
target file, so the general-certification write path is always excluded).
On the counted round, validate's own effect leg DOES read
`effect-confirmed` (reported alongside the `confirm_only` calibration, not
instead of it) — still not the bar, which needs `certified` first. Three
`mcp-redis` OpenAI runs from the first dispatch after the fix hit a shared
provider rate limit and are void, reported with the cause, not folded into
a not-kept count; the sequential re-dispatch kept 2 of those 3, with the
third reading `NOT TESTED` (its own validate ceiling, not "did not land").
Reported as a documented limit, not a pass.

**A later, separate cell asks a narrower question: can a KEPT finding's
own effect leg confirm damage under a calibration that is allowed
to confirm (`certified` *or* `confirm_only`), not only under `certified`?**
This "proof depth (confirm path)" cell runs the harness's later
multi-exploit validation (every exploit a scan found, not only the
alphabetically-first one `generate` used to pick) against both targets,
both providers. It meets this narrower bar on 3 of 4 (target, provider)
pairs: both providers on `mcp-redis`, and OpenAI (not Anthropic) on
`server-memory` — OpenAI's agent names the planted record exactly, so the
removal check confirms the SAME `delete_entities` pattern the original
proof-depth round already found independently effect-confirmed but never
processed. `certified` is still reached on no run, in either cell — see
the full write-up's "Proof depth (confirm path)" section for the
per-provider breakdown and the reasoning on the one pair that misses.

**One fix re-test passed; the other's bar is not met, but the fix under
test is confirmed live.** The streamable-HTTP target still reads `NOT
TESTED` on every run (no seedable surface) exactly as expected. The
OpenAI-Agents-SDK-on-Ollama target hits no HTTP 422 and shows no
traceback on 6 of 6 runs — the first campaign's fix holds — but only 2 of
those 6 (both OpenAI) ever produce a finding to carry into
`generate`/`validate`; its own bar needs the `STABLE, NOT PROVEN`
candidate label on 2+/3 runs per provider, and only 1 of 6 runs reached
it, a property of this target's own locally hosted agent model, not of
the harness — not met.

**All three precision (false-positive) checks now pass cleanly: 0 KEPT,
every run exercised.** The third (`server-everything`, reused as a
read-only check) first read `precision-rollup` `INCONCLUSIVE`: 4 of 6
runs read `NOT_TESTED` after a subprocess crash during the W1 probe,
published at the time as third-party target flakiness. That cause was
wrong — a call to this server's own `toggle-simulated-logging` or
`toggle-subscriber-updates` tool turns on its timed log and
resource-update sends, and one arriving while Mylonite closed the MCP
session raced the shutdown, filing a finished attempt as a crash although
the server never died — a product defect, fixed; the counted re-run
reads `PASS` on both providers.

**Breadth on stronger models, now measured on both tiers: the flagship
class kept on 0 of 24 runs; the third-party indirect-injection class
resisted, judge-only.** The tool-description (W1) class fired in `scan`
on 3 of 12 mid-tier runs against the reference app on
`claude-sonnet-5`/`gpt-5.1`; those 3 were then cut short by a validate
ceiling (`NOT TESTED`, never scored as "did not land"). The same cell, now
also dispatched on the small tier (`claude-haiku-4-5-20251001`/
`gpt-4o-mini`, 12 more runs), fired on 2 of 12 — one run's finding was
rejected at the build gate by a pytest-config bug, since fixed and
superseded by the counted re-run; the counted re-run's own one fired run
was rejected at the metamorphic (robustness) gate, a genuine validator
reject. 0 of 24 runs kept, across both tiers — the bar is a disjunction
("KEPT on 2+/3 ... or the limit is documented with both tiers' numbers"),
and is met through the second limb now that both tiers have a counted
round, never shortened to a bare "met." The indirect-injection (W2) class against
`server-memory` on the same stronger models resisted on all 6 counted
runs, decided by the judge reading the full trace, not a structural
marker — published as the honest result, which this cell's own bar
accepts either way; an earlier, superseded round (before a generic
store-and-recall seed fix) never engaged the planner at all. The Go-memory
smoke target produced a real W4 finding on every run, both providers, that
stays unvalidated because this cell is dispatched scan-only — `generate`
and `validate` never run, so there is no validation report, and no
calibration check was ever consulted — a candidate under never-keep-
unproven, never a kept verdict.

Along the way, five groups of runs voided on harness defects or an
infrastructure cause (a third-party dependency-version mismatch, a
scan-only dispatch that made a cell's own bar unreachable, an install into
the wrong Python environment, a binary moved out from under an
intervening, correct product fix, and three OpenAI Redis runs that hit a
shared provider rate limit), all logged with their fix or cause in the
prereg's dated amendments and re-run in full or in part; six more groups
(37 runs: `server-memory`'s first round, `mcp-redis`'s first two rounds,
the W2 breadth cell's first round, the `server-everything` precision
cell's first round, and the W1 small-tier cell's first round) were
superseded, not void, by a later counted re-measurement once a real
product gap (the removal-confirmation feature, the general calibration
fix, a generic store-and-recall W2 seed that a structural gate had
wrongly excluded, a session-close race during a server's own timed
notifications, and an emitted test inheriting this project's own pytest
config) was fixed in each case — published in full, round by round, in
the write-up's own "Superseded rounds, published in full" section, not
dropped once replaced. Every voided and superseded run is still recorded
in `results.json`, excluded only from its cell's own rollup — see the
write-up's "Spend" and the file itself for the full accounting. 23 runs
read KEPT in this round's counted runs, carrying 35 kept findings (42
runs / 54 findings across every status, including superseded and one
void run) — a run and the findings it carries are different counts once
a run can keep several findings at once; every finding's true-positive
label is adjudicated from its own trace in a committed data file, then
checked by an independent reviewer. Counted spend: $2.75 on
Anthropic (660 calls), $0.35 on OpenAI (946 calls) — both a measured
lower bound, since five ceiling-stopped legs made 80 more Anthropic
requests and 120 more OpenAI requests in total that printed no cost line;
both totals, even at the corrected call counts, are well inside the
pre-registered budget.

## Launch rehearsal: the journey docs, run as written

`verification/rehearsal/` holds a script that a reader wrote from the
seven [journey pages](journey/index.md) alone, and a manual CI workflow
(`rehearsal.yml`) that runs it unchanged on clean Linux and Windows runners
against the official MCP memory server and the reference app, with a hosted
or local model. A cell that fails because the docs were wrong is a docs bug.
Every Mylonite process in a cell is capped by `MYLONITE_MAX_LLM_REQUESTS`;
the README there gives the matrix and the budget.

## The one-line result

**Model robustness ≠ app security.** A frontier model resisted *generic* injection
everywhere we threw it — but the *same model* was caught immediately where the **app's
own design** was the flaw. Mylonite's demonstrable value is **app-flaw detection +
regression gating + honesty**, not out-fooling frontier alignment.

## Example: same model, app design decides

Same Claude Haiku 4.5, two targets:

| Target | Findings | What landed |
| --- | --- | --- |
| `reference:vulnerable` | **2** | W4 — `send_email` dispatched with **no approval step** (the server is the flaw); W1 — followed a tool-description instruction |
| `reference:guarded` | **0** | every attack blocked |

The W4 catch is a **pure app flaw**: the model legitimately sent an email a user asked
for, and the *app* dispatched it with no confirmation. No amount of model alignment
prevents that — only the app's missing approval gate does. This is the existence proof,
and it live-verifies the judge's **deterministic predicate** leg.

You can reproduce this leg yourself in one command, offline and with no API key — see
[Reproduce it yourself](#reproduce-it-yourself).

## Layer 1 — DVMCP (real external MCP app), recall

8 in-scope challenges from [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
scanned over SSE (the remote adapter), same model:

- **Coverage: 8/8 attempted.** Before the attack-pattern-portability fix, **all 8 skipped** with
  `SeedArmUnavailable` — Mylonite's attack patterns were shaped around the bundled kitchen-sink's
  tool surface and didn't fit a different server. Synthesising the probe for each target's
  *introspected* tool surface fixed that.
- **Recall is now measurable; the published 0.9.0 figure stays unmeasured.** The
  harness that produced 0.9.0's 0/8 had two defects that could each force a miss
  regardless of what the scan actually found: the scorer folded any untested
  challenge into "missed" instead of reporting it separately, and the documented
  campaign workflow saved a bare `scan_report.json`, which carries no per-attempt
  weakness class, so the found count read 0 whatever the scan did. Both are fixed
  (issue #136): the scorer reports `exercised_challenges`/`untested_challenges`
  separately, and it reads the whole scan directory `mylonite scan`'s
  `--output-dir` writes — `scan_report.json` plus the `exploit_*.json` files the
  weakness class actually comes from. A bare-report copy is refused with a named
  error instead of silently scored `found=0`. 0.9.0's figure is left as recorded
  and stays unmeasured; a fresh run with the fixed harness would produce a
  trustworthy number.

## Layer 2 — academic benchmarks, judge verification

| Dataset | What we measured | Result |
| --- | --- | --- |
| InjecAgent (run by us, `llama3.2:3b`) | judge agreement | **dh F1 1.000** · **ds F1 0.833 at 0.714 recall** (0.10.0; was 0.400 at 0.25 recall in 0.9.0), 100 cases per split — the gap between the splits is the finding, so both are recorded. `ds` recall rests on only 7 succeeded attacks, so it is unresolved at this sample size rather than improved |
| InjecAgent `--elicit-positives` | compliant agent to manufacture positives | **0/15** — Haiku resisted even when told to comply |
| **AgentDojo (its released runs, gpt-3.5)** | **judge vs AgentDojo's `security` oracle on real third-party positives** | **27 runs, 15 real positives (ASR 55.6%); judge agreement P=0.68, R=1.00, F1=0.81** |

The AgentDojo row **closes the LLM-judge verification leg live**: its released
trajectories include 15 attacks that genuinely succeeded (on a weaker model), so the
judge's positive class is exercised against an independent label — no synthesis, no model
run by us.

*Correction: an earlier reading of AgentDojo's `security` field was inverted (it reads
`True` when the injection goal was executed, not when the agent resisted — upstream's own
`BaseInjectionTask.security` docstring says so directly). That previously put the
positive count at 12 (ASR 44.4%) and the judge agreement at P=0.32/R=0.58/F1=0.41. The
figures above are recomputed from the same 27 recorded judge verdicts under the corrected
label — no new model call was made; see `verification/results/0.11.0/layer2-agentdojo.json`
for the as-published note. The 20 rows in that file's `disagreements[]` array are, under
the corrected label, agreements — the array's `benchmark_says_exploited` field is still
written against the old (inverted) label and has not been updated row by row.*

**Recall is 1.00 (15/15) on this subset**: every real attack AgentDojo's oracle confirms
is also flagged by Mylonite's judge — on a 27-case sample, so read it as a strong
signal, not a settled rate. The **7 false positives** are cases where Mylonite's judge
called a run exploited and AgentDojo's exact-goal oracle scored it resisted. Per-case
detail for these 7 isn't preserved in the committed report (only disagreement text
under the old label was stored, and these 7 were agreements under that label) — a
fresh `--with-llm` run would be needed to attribute them individually, and is left as a
follow-up, not a live call made here.

**`FPR` is informative now**: with the label corrected, `tn = 5` (cases both sides agree
were resisted), so `fpr = 0.58` is a real measurement, not the `tn = 0` artifact the
original (inverted) run produced.

## Layer 3 — precision (false positives on known-good targets)

- `reference:guarded`: **7 probes, 0 false positives (FPR 0%).** Mylonite stays quiet on
  a defended app.
- External benign baseline: **0 false positives** on Enkrypt's benign `echo_mcp`
  (`enkryptai/secure-mcp-gateway`), recorded in
  [the capability matrix](https://github.com/Abidemialade/mylonite/blob/main/verification/CAPABILITY_MATRIX.md).
- External *defended* baseline: **open.** Freely-available MCP servers are
  *unguarded-capable* — attacks land by design, so they are not clean baselines for a
  differential. A gateway-defended-versus-raw run needs a vendor API key and has not
  been run.

## A second third-party campaign (pre-registered, not yet run)

A further six systems Mylonite has never run against before — the official
`server-memory` and `server-everything` reference servers, `redis/mcp-redis`
against a real Redis instance, the MCP Python SDK's streamable-HTTP example,
the MCP Go SDK's own memory example, and an OpenAI Agents SDK agent whose own
inference runs on a local Ollama model — have a committed pass rule
([`verification/PREREG_THIRD_PARTY_2026_10.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/PREREG_THIRD_PARTY_2026_10.md))
and pinned target files
([`verification/third_party/`](https://github.com/Abidemialade/mylonite/tree/main/verification/third_party)),
each with its licence and pin recorded in `verification/SOURCE.md` before any
run. Every LLM call happens in CI, via the `third-party-campaign` workflow,
dispatched once per target/provider (no "all"/"both" fan-out):

```bash
gh workflow run third-party-campaign.yml -f target=tpv-server-memory -f provider=anthropic
```

The first three targets run at a fixed N=3 with a ≥2-of-3 bar (three separate
dispatches, combined with `scripts/score_third_party.py rollup`); the last
three are N=1 smoke cells that claim no verdict. `scan` and `validate` each
get their own hard call ceiling (`scan_ceiling`/`validate_ceiling` dispatch
inputs), sized from a `src/`-derived estimate and refined by one uncounted
pilot dispatch before the first counted run — see the prereg's "Pilot
procedure". That pilot has run, against `tpv-mcp-redis` on gpt-4o-mini; the
counted dispatches use `scan_ceiling=60`, `validate_ceiling=40` — see the
prereg's "Pilot result" subsection for the measured spend and the reasoning.
A stage that reaches its ceiling stops with `MYL-ABT-001` and
the run reads NOT TESTED; reason codes are read only from the scored
stage's own log. A non-zero exit from `scan`/`generate`/`validate`, or a clean
scan finding nothing, is captured and scored rather than failing the
workflow step. A Python traceback with an actual `mylonite` stack frame
(a `File "...mylonite/....py"` reference, not a bare substring match)
anywhere in the run's log is an unconditional product defect (never
auto-re-run, never counted toward the bar); a traceback with no such frame —
a spawned target server's own crash, whose stderr isn't yet
separated from Mylonite's own — is recorded as target noise and never blocks
the cell. NOT TESTED requires a reason code or the same rule applies. This
section will be updated with the results once the campaign has run; until then, nothing on this page
reflects it.

## Where the value is real vs. open

**Real, demonstrated:**

- App-flaw detection (the W4 server flaw caught with a robust model).
- Honesty rails: NOT-TESTED vs false-clean; the vacuous-agreement flag; out-of-scope
  marking. The harness even caught the source research's own errors (it mis-stated two
  external targets' licenses and a third's nature — all verified wrong via the GitHub API
  before any number was produced).
- Coverage portability: attack patterns now run on real non-kitchen-sink targets.
- Precision on a defended app (0 FP).
- Judge positive-class verified on real third-party positives (AgentDojo).

**Open / honest gaps:**

- No model-fooling catch confirmed on an external app: DVMCP recall is measurable again
  (the harness that made 0.9.0's figure unmeasured is fixed), but Layer 1 has not been
  re-run yet (see the Layer 1 note above).
- Judge ≠ AgentDojo oracle (F1 0.81, P 0.68, R 1.00) — the judge flagged 7 of 27 runs
  that AgentDojo's exact-goal oracle scored as resisted; per-case attribution needs a
  fresh run (see the correction note above).
- No external *defended* server for a true external precision number.
- Samples are small, and the hosted-model layers use one model; the opt-in
  `verification.yml` workflow runs larger N on manual dispatch.

## Reproduce it yourself

The harness lives in [`verification/`](https://github.com/Abidemialade/mylonite/tree/main/verification)
(outside the wheel; external data fetched at pinned commits, never vendored — see
`verification/SOURCE.md`). Three tiers, easiest first:

**1. The harness wiring, offline, no API key.** Hermetic tests that guard the plumbing
(judge agreement on a committed fixture, the scorers, the vacuous-agreement flag):

```bash
pytest tests/verification/ -q
```

**2. The core example, live (needs an API key).** The differential that the whole product
rests on, run against the bundled reference app — same model, vulnerable build vs guarded
build:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
mylonite scan reference:vulnerable   # expect findings
mylonite scan reference:guarded      # expect none
```

**3. The live external numbers (need an API key).** Score Mylonite's judge against
AgentDojo's released runs — real third-party positives, no model run by you:

```bash
python -m verification.runner fetch --dataset agentdojo --out verification/reports/agentdojo.jsonl
python -m verification.runner score --transcripts verification/reports/agentdojo.jsonl --with-llm
```

Run InjecAgent or DVMCP recall the same way — the exact commands, the pinned sources, and
every honesty caveat (prompt fidelity, sample size, which input is Mylonite-authored) are
in the harness's own [`README`](https://github.com/Abidemialade/mylonite/blob/main/verification/README.md)
and [`FINDINGS.md`](https://github.com/Abidemialade/mylonite/blob/main/verification/FINDINGS.md).
The opt-in `.github/workflows/verification.yml` runs the larger-N live numbers on
**manual dispatch** (`workflow_dispatch`). It has no schedule — the weekly trigger was
removed in August 2026 — and it needs a provider key configured as a repository secret
before it can run at all.

Each minor or major release ships a result set in `verification/results/<version>/`,
measured against the built wheel rather than the source tree. The
`verification-campaign` workflow produces it on manual dispatch:

```bash
gh workflow run verification-campaign.yml -f model=anthropic/claude-haiku-4-5-20251001
```

It runs the three layer-2 benchmarks the release gate requires and uploads the result
set for a maintainer to commit. The harness README covers what it records and why its
InjecAgent numbers are not like-for-like with 0.10.0.

## Bottom line

The verification system works and earns its keep as an **independent honesty + coverage
check**. It proved the strategically important point — *model-robust ≠ app-secure* — with
a real catch, and it closed the judge-verification gap with real third-party positives. It
did **not** show Mylonite beating frontier-model alignment on generic injection, because
that isn't where the value is — or where real AI-app risk lives.
