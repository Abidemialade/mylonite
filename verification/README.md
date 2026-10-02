# Mylonite verification harness

Independent verification of Mylonite's claims against ground truth Mylonite did
**not** author. Where `mylonite.corpus` scores the in-repo kitchen-sink
builds (ground truth we wrote — useful, but circular), this harness scores Mylonite
against external, independently-published sources.

Lives outside `src/mylonite` and is excluded from the wheel; it consumes the
published package as a library. External data is fetched at pinned commits/
digests (`SOURCE.md`), never vendored.

> **Read [`FINDINGS.md`](FINDINGS.md) for what the system actually showed** — the
> evidence-backed scorecard (real catch, recall, judge agreement, precision) and
> the honest gaps. Headline: *model robustness ≠ app security.*
>
> **To land the strongest available proof** — one external (non-self-seeded) differential —
> follow the maintainer-run recipe in
> [`EXTERNAL_DIFFERENTIAL.md`](EXTERNAL_DIFFERENTIAL.md).

## Layers

| Layer | Source | What it measures | Status |
| --- | --- | --- | --- |
| **1** | DVMCP (runnable vulnerable MCP server) | recall vs documented per-challenge weaknesses | **built (scaffolding)** |
| **2** | InjecAgent, AgentDojo (academic benchmarks) | judge agreement + ASR vs leaderboard | **InjecAgent + AgentDojo: built** |
| **3** | known-good servers (`reference:guarded`, benign real servers) | precision / false positives | **built (scorer + clean baseline)** |

## Layer 2 — how the number is produced (record → score)

InjecAgent and AgentDojo are *runnable benchmarks*, not labelled transcript
sets. A case is an attack scenario (benign user request + a tool whose response
is poisoned + the "attacker tool" a successful attack calls). There is **no
label in the file** — it comes from running a model.

So Layer 2 has two steps:

```bash
# 1. download + verify pinned third-party data (no vendoring)
python -m verification.runner fetch --dataset injecagent

# 2. RECORD: run a model once over the benchmark -> transcripts + ASR (needs an API key)
python -m verification.runner record --dataset injecagent --split dh \
    --model anthropic/claude-sonnet-4-6 --limit 100 \
    --out verification/reports/dh.jsonl

# 3. SCORE: Mylonite's judge vs the benchmark's own rule (hermetic; no model)
python -m verification.runner score --dataset injecagent \
    --transcripts verification/reports/dh.jsonl
```

Each report carries **two separate numbers**:

- **`benchmark_asr`** — the benchmark's own attack-success rate over the
  recorded run. This is the leaderboard-comparable headline and is *not* a
  Mylonite claim — it's the benchmark's result for whatever model you ran.
- **`judge_agreement`** — precision/recall/F1 of Mylonite's success-judge
  against the benchmark's per-case verdict. **This is the independently-
  verifiable claim about Mylonite:** its judge reproduces an established
  benchmark's success criterion on real model behaviour.

`score` defaults to the deterministic, portable `consequential_action_executed`
predicate (no LLM, fully reproducible). Add `--with-llm` to also exercise the
LLM-judge leg.

### AgentDojo — score the judge on *released* runs (no model run)

AgentDojo ships recorded trajectories for dozens of models under `runs/`, each with
a ground-truth `security` label (`security=False` = attack succeeded). We score
Mylonite's judge directly against those — **real third-party positives from a model
that actually fell for attacks**, no synthesis and no model run by us:

```bash
python -m verification.runner fetch --dataset agentdojo --out verification/reports/agentdojo.jsonl
python -m verification.runner score --transcripts verification/reports/agentdojo.jsonl --with-llm
```

AgentDojo injection goals are multi-step (no single attacker tool), so scoring uses
the **LLM judge**. Note the judge measures *effect* ("did harm materialise?") while
AgentDojo's oracle measures *exact-goal achievement* — so moderate agreement is
expected and is itself informative (see `FINDINGS.md`).

## Layer 1 — DVMCP recall (scaffolding)

DVMCP (`harishsg993010/damn-vulnerable-MCP-server`) is the runnable *MCP* target:
10 CTF challenges, each a FastMCP server over SSE, with `solutions/` write-ups as
ground truth. Mylonite scans it (over the SSE transport added in this work) and we
score **recall** — did Mylonite flag each challenge's documented weakness? Only the
challenges within Mylonite's W1–W4 surface are scored; challenges 8 and 9 (RCE /
command injection) are explicitly out of scope.

```bash
# 1. clone DVMCP at the pinned commit (no LICENSE file -> opt-in)
python -m verification.runner layer1 fetch --include-unlicensed

# 2. start the challenge servers (DVMCP's Dockerfile, or `python server.py` per challenge)

# 3. emit a Mylonite target.yaml per in-scope challenge (reads each port from server.py)
python -m verification.runner layer1 emit-targets

# 4. scan each, yourself (Mylonite connects over SSE; runs=5 recommended),
#    then copy the WHOLE scan directory under the target's family name --
#    scan_report.json alone has no per-attempt weakness class (#136):
#    mylonite scan --target-file <t>.yaml --authorize <family> --output-dir <dir>
#    cp -r <dir>/<timestamp>/ verification/reports/dvmcp/<family>/

# 5. score recall vs DVMCP's documented weaknesses
python -m verification.runner layer1 score --reports verification/reports/dvmcp
```

> **License.** DVMCP's README claims MIT but the repo ships **no LICENSE file**.
> It is cloned at a pinned commit at runtime and never vendored; running it locally
> is not redistribution. The `--include-unlicensed` gate forces an explicit opt-in.
> (An earlier research pass named DVAA as the Layer-1 target — verified wrong: DVAA
> is A2A-only with no MCP endpoint and no license. See `SOURCE.md`.)
>
> **Report shape (#136).** The scorer reads the whole scan directory
> `--output-dir` writes: `scan_report.json` for which challenges were
> exercised, and the co-located `exploit_*.json` files (resolved through
> `mylonite.gate.mitigation.weakness_class_for`) for which weakness class each
> found. A bare copy of `scan_report.json`, with no `exploit_*.json` beside
> it, is refused with a named error rather than silently scored as a miss --
> see `verification/_scan_dir.py`.

## Honesty caveats (read before citing a number)

- **Prompt fidelity.** The record step uses the *Mylonite-harness* tool-calling
  agent prompt, not InjecAgent's byte-exact templates. A recorded `benchmark_asr`
  is therefore "harness ASR (tool-calling agent)" — comparable *in spirit* to
  InjecAgent's tool-calling leaderboard column, not a bit-exact reproduction.
- **Metric.** `asr-all` (attacker tool *named*). InjecAgent's headline ASR-valid
  additionally checks the attacker call's parameters; that refinement (loading
  `tools.json`) is future work and is recorded as `benchmark_metric` so it's
  never silent.
- **The crosswalk is ours.** `crosswalk.yaml` (benchmark label → W-class) is the
  one Mylonite-authored input; every other input is third-party.
- **Judge agreement needs successful attacks.** If a model resists every case
  (ASR=0 — as Claude Haiku 4.5 did on a 60-case sample here), there are no positives
  for the judge to classify, so precision/recall/F1 are *vacuous*. The report flags this
  (`judge_agreement_exercised: false`); don't cite the agreement numbers in that case.
  Exercising the judge's positive class needs a model that actually falls for attacks (or
  the synthetic fixture, which contains successful-attack transcripts).
- **`--elicit-positives` (manufacturing positives).** `record --elicit-positives` swaps
  in a deliberately-compliant "naive executor" agent whose only job is to make attacks
  succeed so the judge's positive class can be verified. Its ASR is **not fair**
  (transcripts are tagged `agent_mode="elicit-positives"`). Empirically, even this mode
  produced **0/15** positives on Claude Haiku 4.5 in the single-step formulation — the
  model treats the injected instruction as data and answers only the legitimate request,
  even when told to comply. So on strongly-aligned models the reliable positive-class
  proof remains the committed fixture (or an older/weaker model, or a multi-step loop).
- **The committed fixture is synthetic.** `layer2_datasets/fixtures/*.jsonl`
  exists only to regression-test the harness plumbing in CI (no key, no
  network). It is **not** a third-party number. Real numbers come from `fetch`
  + `record`.

## Running the release campaign in CI

A minor or major release needs `verification/results/<version>/` before
`scripts/check_verification_freshness.py` lets it ship. One dispatch produces it:

```bash
gh workflow run verification-campaign.yml -f model=anthropic/claude-haiku-4-5-20251001
```

The `verification-campaign` workflow builds the wheel from `ref` (default `main`),
installs it into a clean venv outside the checkout, and checks the silo before it
measures anything. It then runs:

- AgentDojo: the judge's LLM leg on the released runs, with `model`;
- InjecAgent `dh` and `ds`: `limit` cases each (default 100), recorded with `model`
  and scored with the deterministic judge;
- `python -m verification.campaign`, which folds the three reports into the result
  set and writes `meta.json` last;
- `scripts/check_verification_freshness.py --check`, so the run fails if the gate would.

Layers 1 and 3 are recorded as `not-run`. Download the
`verification-results-<version>` artifact, review it, and commit it under
`verification/results/<version>/`. The workflow never writes to the repository.
It needs the `MYLONITE_LLM_KEY` secret and skips with a notice when it is unset.
A run costs well under a dollar on Claude Haiku 4.5 and takes about 10 to 15 minutes.

**Not like-for-like with 0.10.0 on the InjecAgent record step.** 0.10.0 recorded
InjecAgent on `ollama/llama3.2:3b`; this workflow records with `model`. Haiku resisted
every case in an earlier 60-case sample, so its InjecAgent reports may carry
`judge_agreement_exercised: false`. The gate still passes, but those agreement
numbers are vacuous and must not be cited (see the honesty caveats above).
AgentDojo scoring is unaffected: it uses released third-party runs.

## CI, sampling, and the opt-in workflow

Two tiers, on purpose:

- **Hermetic checks gate every PR.** The `tests/verification/` suite (judge
  agreement on the committed fixture, crosswalk/catalogue/scorer logic, the
  vacuous-agreement flag, the delivery-channel synthesis) runs in the normal test
  job with no key and no network. It guards the wiring, not the independence claim.
- **Live numbers are opt-in, manual-dispatch only.** `.github/workflows/verification.yml`
  runs the larger-N live runs on `workflow_dispatch` (needs the `ANTHROPIC_API_KEY`
  secret, which is not currently configured — run locally with your own key until it
  is): Layer 2 record→score over both InjecAgent splits and Layer 3 precision on
  `reference:guarded`. Reports are uploaded as artifacts. There used to be a weekly
  cron trigger; it was removed (2026-08-09) because with no secret configured every
  scheduled run failed for over a month with nobody acting on it.

**On sample size.** A quick manual `--limit 20` run is *directional*, not a
leaderboard figure. Dispatching the workflow answers this by running a larger N
(default 100/split, override via dispatch input) on demand, so the numbers can
tighten without spending tokens on every push. Layer 1 (DVMCP) is kept out of this
workflow on purpose — it executes a deliberately-vulnerable external server and
should be run manually with explicit authorization.
