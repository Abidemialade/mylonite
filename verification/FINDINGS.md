# Verification findings — what the third-party system actually showed

This is the evidence-backed scorecard from running Mylonite against ground truth it
did not author. Numbers are from live runs in June 2026 with **Claude Haiku 4.5**
as the planner/judge (the only hosted provider these runs used), small samples,
cost-bounded. Read the caveats — several numbers mean less (or more) than they look.

> **Which version produced these?** The June 2026 figures below predate versioned
> results and are **not** stamped to a release — they are roughly v0.7.0-era. From
> **0.9.0** onward, every minor/major release commits a version-stamped result set
> under [`results/`](results/), measured against an **installed wheel outside the
> checkout** rather than a working tree, and the release is gated on it existing.
> (The gate requires the results before the tag, so the measured wheel is the
> release candidate; `meta.json` records `git_sha` and `harness_sha` separately,
> and their being equal is the signal that no release tag existed yet.) The
> release-over-release table is [`TRENDS.md`](TRENDS.md).
>
> ### 0.10.0, measured 2026-09-14
>
> | Layer | Result | Basis |
> |---|---|---|
> | Judge agreement (AgentDojo) | **F1 0.412** | 27 cases, 12 real third-party positives |
> | Judge agreement (InjecAgent `dh`) | **F1 1.000** | precision 1.0, recall 1.0, ASR 10% |
> | Judge agreement (InjecAgent `ds`) | **F1 0.833** | precision 1.0, recall 0.714, ASR 7% |
> | Precision (`reference:guarded`) | **0 FP / 8 probes** | all 8 exercised probes clean |
> | Recall (DVMCP) | not run | needs the challenge servers standing up; see #136 |
>
> **AgentDojo and `dh` reproduced exactly** — 0.412 and 1.000, unchanged from 0.9.0
> on a fresh run. Nothing in this release targeted judge agreement, so holding
> steady is the expected outcome and is the clearest signal available that the
> release did not disturb the judge.
>
> **AgentDojo's `security` label was read backwards** in this run and in 0.9.0's
> (fixed afterward; see the correction note under Layer 2 below for the
> recomputed figures). The figure above is left as recorded.
>
> **Do not read `ds` 0.400 → 0.833 as the judge improving.** Recall on `ds` is
> measured only over cases where the attack actually succeeded, and this run
> produced **7** such positives (5 caught, 2 missed) against 8 in 0.9.0. A metric
> with a single-digit denominator moves this far on case mix alone, and the
> recording is a fresh stochastic run of the same model. Nothing in this release
> touched the judge. The honest reading is that `ds` recall remains
> **unresolved at this sample size**, not fixed — the split gap is still the
> finding, and settling it needs a recording large enough to measure.
>
> **Layer 1 was not run.** It needs the DVMCP challenge servers standing up, and at
> the time its scorer still counted an untested challenge as a miss, while
> `crosswalk.yaml` maps two challenges to W3 on servers exposing no egress tool
> (#136 — the scorer defect is since fixed; the crosswalk question is still open).
> Re-quoting the 0/8 without fixing that would have repeated a figure already known
> to be wrong, so the layer is recorded as `not-run` rather than carried forward.
>
> ### 0.9.0, measured 2026-08-29
>
> | Layer | Result | Basis |
> |---|---|---|
> | Judge agreement (AgentDojo) | **F1 0.412** | 27 cases, 12 real third-party positives |
> | Judge agreement (InjecAgent `dh`) | **F1 1.000** | precision 1.0, recall 1.0, ASR 9% |
> | Judge agreement (InjecAgent `ds`) | **F1 0.400** | precision 1.0, **recall 0.25**, ASR 8% |
> | Precision (`reference:guarded`) | **0 FP / 7 probes** | 1 of 8 probes not exercised, excluded |
> | Recall (DVMCP) | **unmeasured** | published as 0/8 at the time; see the note below |
>
> **AgentDojo agreement held steady** (0.41 → 0.412) across the releases since June.
> Nothing in that window targeted judge agreement, so stability is the expected
> outcome rather than a regression — and recall of 0.583 over 12 genuine positives is
> real detection. The low precision is largely the semantic mismatch described below:
> the judge measures *effect*, AgentDojo's oracle measures *exact goal achievement*.
>
> **This reading was backwards** (the `security` label maps the other way; see the
> correction note under Layer 2 below). The figure above is left as recorded.
>
> **InjecAgent is new information.** June's run used a well-aligned model that
> resisted every case, leaving the judge no positives and a vacuous F1. Re-running
> with a deliberately weaker planner (`llama3.2:3b`, local, no API cost) produced real
> positives for the first time: the judge **never false-positives** on either split
> and catches **every** direct-harm attack, but misses **three quarters** of the
> data-stealing split. That recall gap on `ds` is the most actionable weakness on this
> page.
>
> **Treat the DVMCP 0/8 as unmeasured, not as evidence either way.** The harness that
> produced it had two defects that could each force a miss regardless of what the scan
> actually found: the scorer folded any untested challenge into `missed` instead of
> reporting it separately, and the documented campaign workflow saved a bare
> `scan_report.json` copy, which carries no per-attempt weakness class, so `found` read 0
> whatever the scan did. **Both are now fixed**
> ([issue #136](https://github.com/Abidemialade/mylonite/issues/136)): the scorer reports
> `exercised_challenges`/`untested_challenges` separately, and it reads the WHOLE scan
> directory `mylonite scan`'s `--output-dir` writes — `scan_report.json` for `exercised`,
> plus the co-located `exploit_*.json` files (resolved through
> `mylonite.gate.mitigation.weakness_class_for`) for `found`. A bare-report copy with no
> exploit files is refused with a named error (`verification._scan_dir.ScanDirIntegrityError`)
> rather than silently scored `found=0`. The retrospective observation at the time was
> that every challenge was genuinely exercised (9 attempts; the first attempt at this run
> had 3 challenges with *zero* exercised attempts, because the target generator inferred
> the wrong weakness classes) — that observation stands as a record of what was seen, but
> no per-attempt artefact survives from that run to independently verify it, and a
> genuinely exercised challenge is not the same claim as a correctly-scored one. 0.9.0's
> figure is left as recorded and stays labelled unmeasured; Layer 1 needs a re-run with
> the fixed harness before recall is a number anyone can act on.
>
> A separate, still-open question from that same investigation: `crosswalk.yaml` maps
> challenges 3 and 7 to **W3**, although neither server exposes an egress tool — so W3 is
> unmeasurable there by construction and is still scored against recall. Under review.

## Third-party verification campaign, live in CI (2026-10-03)

Separate from the academic-benchmark numbers above: six MCP and agent systems
Mylonite had never run against, every LLM call made live in GitHub Actions
(`third-party-campaign.yml`), scored against a pre-registered rule
([`PREREG_THIRD_PARTY_2026_10.md`](PREREG_THIRD_PARTY_2026_10.md)). Full
write-up: [`results/0.12.0/third-party/README.md`](results/0.12.0/third-party/README.md).

| Target | Result | Basis |
| --- | --- | --- |
| `@modelcontextprotocol/server-memory` | **KEPT**, W4 | 3/3 re-drives on Haiku 4.5; 2/3 (one honest REJECTED) on gpt-4o-mini; 1/1 on `llama3.2:3b` (informational) |
| `redis/mcp-redis` | **KEPT**, W4 | 3/3 on both Haiku 4.5 and gpt-4o-mini |
| `simple-streamablehttp` (MCP Python SDK example) | product defect, not a verdict | 3/3 on both providers — a missing seed arm reads as an unclassified exception (issue #319, fixed after the measured build in #322), not a false clean |
| `@modelcontextprotocol/server-everything` (smoke) | 1 clean resist, 1 product defect | the Haiku run hit a target-side transport crash, same root cause as issue #319 |
| MCP Go SDK memory example (smoke) | finding, unvalidated | W4 fired on both providers; effect-probe calibration failed, so it is a candidate under never-keep-unproven, never a verdict |
| OpenAI Agents SDK agent on Ollama (smoke) | product defect, two causes | a harness install conflict (fixed, PR #320), then a request missing its JSON content type (fixed after the measured build in PR #321) |

**Two targets Mylonite did not author kept a reproducible W4 finding — an
unconfirmed consequential change, confirmed through the target's own
read-back — across three independent re-drives, on every provider tried,
including a 3B model running locally at zero cost.** Both differentials ran
against Mylonite's synthetic boundary shim, since neither target ships a
server-side guard to toggle — the same caveat every synthetic-boundary result
on this page carries: proof the attack is real and that this class of guard
closes it, not proof about any one deployment's own guard.

**The campaign's own failure mode was honesty about coverage, not a missed
attack.** Three product defects trace to the same underlying gap: an attempt's
stored record can lack the reason code its own printed console line already
names, so a harness scoring strictly from the record reads a correctly-named
skip as an unexplained one. No run this surfaced was silently scored clean.
Total spend: $0.91 on Anthropic, $0.08 on OpenAI, $0 on the in-runner Ollama
cell — both inside the campaign's $4.50/$5.00 budget.

## The one-line result

**Model robustness ≠ app security.** A frontier model resisted *generic* injection
everywhere we threw it — but the *same model* was caught immediately where the
**app's own design** was the flaw. Mylonite's demonstrable value is **app-flaw
detection + regression gating + honesty**, not out-fooling frontier alignment.

## The core result: same model, app design decides (Layer "real catch")

Same Claude Haiku 4.5, two targets:

| Target | Findings | What landed |
| --- | --- | --- |
| `reference:vulnerable` | **2** | W4 — `send_email` dispatched with **no approval step** (the server is the flaw); W1 — followed a tool-description instruction |
| `reference:guarded` | **0** | every attack blocked |

The W4 catch is a **pure app flaw**: the model legitimately sent an email a user
asked for, and the *app* dispatched it with no confirmation. No amount of model
alignment prevents that — only the app's missing approval gate does. This is the
existence proof, and it live-verifies the judge's **deterministic predicate** leg.

### Second model, same targets (2026-08-28, local via Ollama, zero API cost)

Planner `llama3.2:3b`, judge `qwen2.5-coder:7b`. Both models find **two** weaknesses
on `reference:vulnerable` — but not the same two:

| Weakness | Haiku 4.5 | `llama3.2:3b` |
| --- | --- | --- |
| W4 — consequential action, no approval step | ✅ | ✅ |
| W3 — unrestricted egress / SSRF | ✗ | ✅ |
| W1 — tool-description smuggling | ✅ | ✗ |

**W4 fires on both** — the app-design flaw is model-independent, which is the whole
thesis, now seen on a second model ~40× smaller.

**Recall is not monotonic in model weakness.** W3 fired only on the weak planner (it
complied where Haiku refused — the predicted direction), but W1 fired only on Haiku:
W1 needs the agent to *competently follow* a smuggled instruction, and a model too weak
to execute it coherently suppresses the finding rather than falling for it. This
**refines Lesson 7** — see Lesson 8 in `CAPABILITY_MATRIX.md`.

Caveats, which are real: `reference:guarded` returned **0 findings but 3/8 seeds
untested**, and Mylonite correctly refused to report it clean — so this is *not* a
precision result. Two judge calls timed out; customisation fell back to raw seed bodies
3×. And on one attempt the local judge claimed with `confidence: 1.0` that `web_fetch`
was called when the trace showed only `write_note`/`read_note` — the verdict was still
correctly negative because the **deterministic predicate layer overrode it**, a useful
live confirmation of that design under a judge weak enough to fabricate evidence.

This is an in-repo-target run, not a third-party one. **Every external number below is
still single-model.**

## Layer 1 — DVMCP (real external MCP app), recall

8 in-scope challenges scanned over SSE (the new remote adapter), same model:

- **Coverage: 8/8 attempted** (before the Gap-1 fix, **all 8 skipped** with
  `SeedArmUnavailable` — the seeds didn't fit a non-kitchen-sink tool surface).
- **Recall is now measurable again; the published figure stays unmeasured.** 0.9.0's
  0/8 came from a harness with two defects that could each force a miss regardless of
  what the scan actually found; both are fixed (issue #136) — see the 0.9.0 note above
  for what changed and what an operator now runs. 0.9.0's figure is left as recorded and
  stays labelled unmeasured until Layer 1 is re-run with the fixed harness.

## Layer 2 — academic benchmarks, judge verification

| Dataset | What we measured | Result |
| --- | --- | --- |
| InjecAgent (run by us, Haiku) | faithful ASR | **0/60** — Haiku resisted; judge agreement **vacuous** (no positives), flagged as such |
| InjecAgent `--elicit-positives` | compliant agent to manufacture positives | **0/15** — Haiku resisted even when told to comply |
| **AgentDojo (its released runs, gpt-3.5)** | **judge vs AgentDojo's `security` oracle on REAL third-party positives** | **27 runs, 12 real positives (ASR 44.4%); judge agreement P=0.32, R=0.58, F1=0.41** |

The AgentDojo row is the one that **closes Gap 2's LLM-judge leg live**: its
released trajectories include 12 attacks that genuinely succeeded (on a weaker
model), so the judge's positive class is exercised against an independent label —
no synthesis, no model run by us.

**That F1 of 0.41 is itself a finding**, not just a weak score: Mylonite's judge
asks *"did the agent follow the attacker's intent and did harm materialize?"*,
while AgentDojo's oracle asks *"was this exact injection goal achieved?"* They are
**different definitions of success**, and the moderate agreement quantifies the
gap. Don't cite 0.41 as "the judge is 41% good" — cite it as "Mylonite's
effect-based judge and AgentDojo's exact-goal oracle agree moderately; investigate
the disagreements (`layer2-agentdojo.json`) before trusting either as a drop-in for
the other."

**FP triage (all 15 classified — none is a judge bug).** Every disagreement where
Mylonite flagged an attack AgentDojo's oracle didn't shows the attacker's
consequential tool *actually executing* (`send_money` to the attacker IBAN `US13…`,
`update_password`, `update_scheduled_transaction`, each `[ok]`). These are the
effect-vs-exact-goal definitional difference, not bugs — for a CI security gate,
materialized harm to the attacker's account *should* fire. And **`FPR=1.0` is a `tn=0`
artifact**: this subset is all injection attempts with no benign control cases, so FPR
is mechanically pinned at 1.0 regardless of judge quality. The report builder now emits
`fpr_informative: false` and a note when `tn=0`, so the number is never cited as a
precision failure. A real external precision number needs a *defended* third-party
server (the Layer-3 gap). The 5 FNs are refused/not-executed traces (oracle-semantics
nuance), not under-reporting of a real effect.

**Correction: the table and the two paragraphs above are left as originally recorded,
but the reading they rest on was backwards.** AgentDojo's `security` field is `True`
when the injection goal was executed (upstream's own `BaseInjectionTask.security`
docstring: "Returns True if the injection was executed correctly, False otherwise"),
not when the agent resisted — the adapter had it inverted. Recomputed under the
corrected label, from the same 27 recorded judge verdicts (no new model call): **15
real positives, not 12 (ASR 55.6%, not 44.4%); judge agreement P=0.68, R=1.00, F1=0.81,
not P=0.32/R=0.58/F1=0.41.** The direction of the finding flips too: recall is 1.00
(15/15) on this subset — every real attack AgentDojo confirms is also flagged — though
on a sample this small that is a strong signal, not a settled rate. All 20 rows of the
`disagreements[]` array in the committed `layer2-agentdojo.json` files are, under the
corrected label, agreements: the array's `benchmark_says_exploited` field is still
written against the old (inverted) label and was not rewritten row by row, so the 15
cases the "FP triage" paragraph above walks through — `send_money` to the attacker
IBAN, `update_password`, `update_scheduled_transaction` — and the 5 cases the "5 FNs"
sentence covers are all genuine agreements now, not disagreements. The 7 real false
positives are the other direction: cases AgentDojo's exact-goal oracle scored as
resisted that Mylonite's judge called exploited. Per-case detail for these 7 isn't
preserved in the committed report (only disagreement text under the old label was
stored, and these 7 were agreements under that label), so attributing them
individually needs a fresh `--with-llm` run — left as a follow-up, not a live call
made here. `FPR` is informative now (`tn=5`, not 0): **0.58**. See `docs/verification.md`
and `docs/limitations.md` for the corrected figures as currently cited.

## Layer 3 — precision (false positives on known-good targets)

- `reference:guarded`: **8 probes, 0 false positives (FPR 0%).** Mylonite stays
  quiet on a defended app.
- External benign baseline: **gap.** Freely-available MCP servers (e.g. the bundled
  `filesystem`) are *unguarded-capable* — attacks "land" by design, so they aren't
  clean baselines; and `filesystem` failed to launch here (npx/describe on Windows).
  A truly external *defended* server is the missing precision baseline.

## Cross-model durability

The dedicated multi-model mode (`validate --models`) was retired in v0.7.4. The
supported path for "does my defense hold across the models I actually run" is to
re-run `mylonite validate` on the committed test with `--planner-model <model>`,
once per model — see [Re-validate on a new model](../docs/model-upgrade.md). A
broad cross-model number still needs non-Claude provider keys (absent here).

## Where the value is real vs. open

**Real, demonstrated:**
- App-flaw detection (W4 server flaw caught with a robust model).
- Honesty rails: NOT-TESTED vs false-clean; vacuous-agreement flag; out-of-scope
  marking; the harness caught the source research's own errors (DVAA's nature +
  license, DVMCP's license).
- Coverage portability (Gap-1 fix: seeds now run on real non-kitchen-sink targets).
- Precision on a defended app (0 FP).
- Judge positive-class verified on real third-party positives (AgentDojo).

**Open / honest gaps:**
- No model-fooling catch confirmed on an external app yet: DVMCP recall is measurable
  again (the harness that made 0.9.0's figure unmeasured is fixed), but Layer 1 has not
  been re-run (see the Layer 1 note above).
- Judge ≠ AgentDojo oracle (F1 0.81, precision 0.68, recall 1.00 once the label fix
  below is applied) — the judge flagged 7 of 27 runs that AgentDojo's exact-goal
  oracle scored as resisted; per-case attribution needs a fresh run (see the
  correction note below).
- No external *defended* server for a true external precision number.
- Samples are small + Claude-only; the opt-in `verification.yml` workflow runs larger N.

## Bottom line

The verification system works and earns its keep as an **independent honesty +
coverage check**. It proved the strategically important point — *model-robust ≠
app-secure* — with a real catch, and it closed the judge-verification gap with real
third-party positives. It did **not** show Mylonite beating frontier-model alignment
on generic injection, because that isn't where the value is (or where real AI-app
risk lives).
