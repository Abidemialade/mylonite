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

## 2. The published evidence base is one model

Every external number in [Independent verification](verification.md) comes from **Claude
Haiku 4.5** — the single provider keyed on the maintainer's machine — at small sample sizes,
cost-bounded, run in June–July 2026.

The direction of that limitation is worth stating precisely, because it is not the direction
a reader might assume. Lesson 7 of the
[capability matrix](https://github.com/Abidemialade/mylonite/blob/main/verification/CAPABILITY_MATRIX.md)
establishes that a KEPT control-efficacy proof gets **easier**, not harder, on a weaker
model: the check proves a control load-bearing only where the base model would otherwise
cause harm, so a model that self-safeguards (as Haiku does) collapses the differential and
suppresses findings. The published figures are therefore the conservative case — a second,
weaker model would be expected to *raise* recall, not lower it.

That is an expectation, not a measurement, and it stays labelled as one until someone runs
it. The machinery to do so already exists: `scan` accepts role-separated
`--planner-model` / `--judge-model` overrides precisely so the agent-under-test can be a
representatively exploitable model while the judge stays aligned.

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
