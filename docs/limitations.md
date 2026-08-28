# Known limitations

Mylonite's core claim is about honesty: it tells you which fidelity of proof you got, and it
publishes its misses alongside its hits. That claim is worth very little if the limitations
are scattered across four files, so they are collected here.

Nothing on this page is a surprise to the maintainer, and nothing here is being worked
around quietly. Where a limitation is deliberate, it says so and says what would change it.

## 1. On a single-build app, the strong claim is not available

This is the most important one, and it is structural rather than a bug.

A KEPT differential means something different depending on what the *guarded* side of it
actually was:

| Guarded side | What KEPT proves | How you get it |
|---|---|---|
| **Your own control**, toggled | Your implementation is load-bearing. The strong claim. | Declare `control_env` in your `target.yaml` |
| **A canonical control** at the adapter boundary | The attack is real and this class of control closes it — the guarded side was Mylonite's shim, not your code | The default on any single-build app |

The second is genuinely useful, and it is what runs on most real targets. It is not the same
claim, and no surface will print the stronger wording for it — not the terminal panel, not
the gating PR, not the SARIF uploaded to code scanning.

**What would change it:** a guarded leg built without the boundary shim. That work is
deliberately not started, because validating it needs a real third-party MCP server with a
genuine, code-enforced, toggleable control to test against, and no such target has been
identified yet. Building the path before the target exists would produce a feature that
cannot be verified. Tracked in [`TODOS.md`](https://github.com/Abidemialade/mylonite/blob/main/TODOS.md).

## 2. The external evidence base is essentially one model

Every number in [Independent verification](verification.md) comes from **Claude Haiku 4.5** —
the single hosted provider these runs used — at small sample sizes, cost-bounded, run in
June–July 2026. Those remain the only *external* (third-party target) results.

### What a second model actually showed

A second model has now been run against the bundled reference targets, locally via Ollama at
zero API cost (2026-08-28): planner `llama3.2:3b`, judge `qwen2.5-coder:7b`. It is a small
run on the in-repo targets, not a third-party one, so it does not replace anything in the
verification scorecard — but it does turn a previously-unmeasured assumption into a result.

On `reference:vulnerable`, both models found two weaknesses — but **not the same two**:

| Weakness class | Claude Haiku 4.5 | `llama3.2:3b` |
|---|---|---|
| **W4** consequential action with no approval step | found | found |
| **W3** unrestricted egress / SSRF | not found | **found** |
| **W1** tool-description smuggling | **found** | not found |

Three conclusions, and the third is the one that matters most:

1. **W4 fires on both.** The pure app-design flaw is model-independent, which is the central
   claim of this project, now observed on a second model roughly an order of magnitude
   smaller.
2. **W3 fired only on the weaker planner** — it complied with an egress attack Haiku refused.
   This is the predicted direction: for attacks that need the model to *agree*, a weaker
   model exposes more.
3. **W1 fired only on Haiku** — the opposite direction, and it corrects the assumption this
   section used to make. Recall is **not** monotonic in model weakness. W1 requires the agent
   to competently follow a smuggled instruction; a model too weak to execute the attack
   coherently suppresses the finding rather than falling for it. "Point it at a weaker model
   to get a KEPT proof" therefore has a floor as well as a ceiling.

So the earlier framing — that these figures are simply the conservative case — was too
simple. A weaker model raises exposure for *compliance-dependent* attacks and lowers it for
*capability-dependent* ones.

### Caveats on that run, which are substantial

- On `reference:guarded` the run produced **0 findings**, but 3 of 8 seeds were never
  exercised, and Mylonite correctly refused to report it as clean. It is therefore **not** a
  precision result, and is not quoted as one.
- The run was degraded by the small local models: judge calls timed out twice, and payload
  customisation fell back to raw seed bodies 3 times, so some plants were less target-tuned
  than they would be on a stronger model.
- On one attempt the local judge asserted with `confidence: 1.0` that the agent had called
  `web_fetch`, while the recorded tool-call trace showed only `write_note` and `read_note`.
  The verdict was still correctly negative, because the deterministic predicate layer
  overrides the LLM judge — which is the intended design, and worth knowing if you run
  Mylonite with a small self-hosted judge. **Prefer a stronger model for the judge role than
  for the planner role;** `scan` accepts role-separated `--planner-model` / `--judge-model`
  overrides for exactly this reason.

### What is still missing

A second model against a **third-party** target. Every external number remains single-model,
and nothing above changes that.

## 3. Published negatives

The verification harness scores Mylonite against ground truth it did not author, and reports
the misses. In summary:

- **0/8 recall on DVMCP** — coverage went 0 → 100% (all 8 challenges attempted), but Haiku
  resisted every model-fooling attack.
- **0/60 on InjecAgent**, with judge agreement flagged as vacuous (no positives to agree
  about); **0/15** even with `--elicit-positives` telling the agent to comply.
- **LLM-judge agreement F1 of 0.41** against independent labels.
- Against that: a **KEPT external differential** on a third-party MCP email server (fired
  5/5 raw, leaked 0/5 guarded), and **zero false positives** on a benign third-party server.

Full scorecard with caveats:
[verification/FINDINGS.md](https://github.com/Abidemialade/mylonite/blob/main/verification/FINDINGS.md).

## 4. A clean result is the common result

Against a well-designed app and a robust model, Mylonite will often correctly find
**nothing**. A KEPT proof needs a weakness that actually lands, which in practice means an
app-design flaw (a consequential action with no approval step, an unrestricted egress path)
or an app configured to act autonomously.

This is the tool working. But it does mean that if your first run is against a well-built
app, you will see an empty result and learn little about whether Mylonite works — which is
why the [quickstart](quickstart.md) starts with the deliberately-vulnerable reference app.

## 5. Deferred capabilities

Accepted, documented, and not yet built — from
[`TODOS.md`](https://github.com/Abidemialade/mylonite/blob/main/TODOS.md):

- **`launch_failure` is not its own outcome value.** A launch that never started is
  classified and reported as a launch failure in the attempt's reason, but the `outcome`
  literal is still `skipped_planner_failure`. The honest value needs a new enum member in a
  public contract, so it waits for the next batched contract-version bump.
- **`primary_tools` has no readers.** The `target.yaml` field is accepted, validated and
  round-tripped, but does not yet narrow seed selection.
- **Coverage is all-or-nothing.** There is no ratio and no `--min-coverage` threshold to
  gate CI on, because a ratio needs a defined value at 0/0 before it can safely drive an
  exit code.
- **Deeper attack tactics were removed in v0.7.4** — adaptive refinement, tool-chaining
  synthesis, stateful memory poisoning, cross-model durability. They were beaten by
  frontier-aligned models on every external target and none had a third-party proof path.
  The code is in git history and returns only if an external need re-justifies it.

## 6. Project maturity

Mylonite is **beta software with a single maintainer**. As of v0.8.5 that is 241 commits
from one contributor (plus Dependabot), with no external users yet that the maintainer is
aware of.

Concretely, what that does and does not mean:

- The test suite (1,900+ tests), CI (ruff, mypy, pytest, pre-commit), semantic versioning,
  and the versioned extension contracts are real and enforced on every PR.
- Bus factor is one. There is no second reviewer, no on-call, and no SLA on a security
  report beyond what [SECURITY.md](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md)
  states.
- The extension contracts are public API and versioned, but they have not yet been
  stress-tested by third-party plugin authors.

If you are evaluating Mylonite as a dependency in a security pipeline, weigh that
accordingly — and consider pinning a version.

## Reporting something missing

If you hit a limitation that is not on this page, that is worth an issue: an undocumented
gap is a bug in this page, independent of whether it is a bug in the code.
