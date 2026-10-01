# Known limitations

Mylonite's core claim is about honesty: it tells you which fidelity of proof you got, and it
publishes its misses alongside its hits. That claim is worth very little if the limitations
are scattered across four files, so they are collected here.

Nothing on this page is a surprise to the maintainer, and nothing here is being worked
around quietly. Where a limitation is deliberate, it says so and says what would change it.

## What Mylonite supports today

**Supported:** an MCP server you build and control, reached over stdio, or remote
(`transport: sse` or `http`) authenticated with a static token you export as an
environment variable and reference from `headers:` in `target.yaml` (see
[Remote targets](target-file.md#remote-targets-sse-http)).

**Not supported yet:** a server that requires an OAuth 2.1 sign-in flow (dynamic client
registration, token refresh — see the remote-authentication note below for what that
means for a token that expires mid-run), or a server reached through an enterprise
gateway. Both are on the roadmap.

**Wiring caveat:** `mylonite check` (hidden and experimental — see
[docs/experimental.md](experimental.md)) flags a `seed_arm.tool`, `effect_probe.verify_tool` or
`control_config` name that isn't among the server's described tools — a typo or a stale
name from a copied target file — before you ever spend an LLM call. A `seed_arm` plant
call or an `effect_probe` verify call that the server itself refuses (errors) is also
caught: the attempt is reported as a plant failure or an undecided (NOT TESTED) result,
never as a clean pass.

The wiring self-test now exists: `calibration` (`calibration.controls` in the target
file; `scan`/`gate`/`validate` run it automatically against a `--target-file` target)
does real writes against the live target — a positive control (a fresh write through
a consequential tool, carrying its
own token) that the probe must see, and a negative control (two reads with nothing
written between them) that it must not. It closes exactly the gap this caveat used to
describe: a `verify_tool` that exists, never errors, but reads the *wrong* store, because
the positive control's own write is what the probe is asked to find. A `seed_arm`'s
recall path gets the same proof — a token planted through `seed_arm` must come back from
a recall tool. When it does not, the W2 line of the per-class summary carries the
seed control's reason code (see [Reason codes](reason-codes.md)), so a failed recall
path is named rather than missed silently. The attempts themselves are still decided
from their trace.

What calibration does not cover: it only checks a "create" effect, never a destructive or
egress one, and it needs authorization — `--authorize` on the driving command, or
`calibration.controls: allow` to run it against a remote (`sse`/`http`) target at all
(`auto`, the default, runs on an authorized `stdio` target only). Set `controls: skip` and
an uncalibrated probe's "no change" can never certify a resisted attempt, by design — see
[Calibration](target-file.md#calibration). Calibration is a real write: expect
`myl-cal-`-prefixed records left behind in your target's state (see
[SECURITY.md](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md)).

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

Most numbers in [Independent verification](verification.md) come from **Claude Haiku 4.5**,
the planner/judge for the DVMCP and precision layers, at small sample sizes, cost-bounded.
The InjecAgent judge-agreement layer is the exception: it runs against a self-hosted
`llama3.2:3b`. The runs span **25 June to 14 September 2026**. Those remain the only
*external* (third-party target) results.

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
- **On InjecAgent** (100 cases per split, `llama3.2:3b`) judge agreement scored
  **F1 1.000** on the direct-harm split and **F1 0.833 at 0.714 recall** on the
  data-stealing split in 0.10.0 (0.9.0 measured 0.400 at 0.25 recall). That recall rests
  on only 7 attacks that succeeded, so it is unresolved at this sample size, not an
  improvement. The gap between the two splits is the finding, so both are recorded
  rather than either alone.
- **LLM-judge agreement F1 of 0.41** against independent labels.
- Against that: a **KEPT external differential** on a third-party MCP email server (fired
  5/5 raw, leaked 0/5 guarded), in a run whose guarded side is Mylonite's boundary control
  shim rather than a second build, and **zero false positives** on an external benign
  server. A defended-server differential remains open.

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

Mylonite is **beta software with essentially a single maintainer** — one outside
contribution to date, the rest of the history from the maintainer and Dependabot — with no
external users yet that the maintainer is aware of.

Concretely, what that does and does not mean:

- The test suite (over 2,300 collected tests), CI (ruff, mypy, pytest, pre-commit), semantic versioning,
  and the versioned extension contracts are real and enforced on every PR.
- Bus factor is one. There is no second reviewer, no on-call, and no SLA on a security
  report beyond what [SECURITY.md](https://github.com/Abidemialade/mylonite/blob/main/SECURITY.md)
  states.
- The extension contracts are public API and versioned, but they have not yet been
  stress-tested by third-party plugin authors.

If you are evaluating Mylonite as a dependency in a security pipeline, weigh that
accordingly — and consider pinning a version.

## 7. Remote authentication is static tokens only

A remote target (`transport: sse` or `http`) authenticates with a fixed value in
`headers:` — a bearer token or API key you export as an environment variable and
reference with `${VAR}` (see the "Remote targets" section of the
[`target.yaml` reference](target-file.md)).

**Supported:** a static header token, read from your shell's environment and never
written to the target file. A server that rejects it reports the host and the status —
401 or 403 — and names the fix.

**Not supported yet:** an OAuth 2.1 sign-in-and-refresh flow, or a server reached
through an enterprise gateway. A token that expires mid-run has no automatic renewal:
the next request gets a 401 and `scan` reports it the same way a wrong token from the
start would, pointing at `headers:` rather than at "the token expired". If your server
needs OAuth today, mint a long-lived static token for Mylonite's own use, where the
provider supports one.

A token in the url's query string (`url` or `request.url`) is masked as `***REDACTED***`
in every target file Mylonite writes, and `url` reads no variables, so those copies need
the value put back by hand. Put the token in `headers:` as a `${VAR}` reference to keep
the copies runnable.

## 8. What the effect probe still cannot see

The [effect attribution rule](target-file.md#effect-attribution) fixed the general case —
crediting an attempt only with a change it actually caused — but the shapes below remain,
by design rather than by oversight.

**On a target with an effect probe, attempts run one at a time.** `scan`, `validate`,
`ablate` and the CI check never have two attempts in flight against a target that
declares an `effect_probe`, whatever `--max-concurrent` says, repeated runs included. The
probe compares shared state before and after an attempt, and a concurrent attempt's
change to that state can't be told apart from this attempt's: another attempt's write can
be credited to this one as `"true"`, and another attempt's queued item can make this
attempt's real effect read `"false"`. The effect check is only sound when nothing else
changes the state during the attempt, so a probed scan takes longer than an unprobed one.
The same holds for anything outside Mylonite that writes to the target's state while a
scan runs: point the scan at state nothing else is using.

**A default deferral word inside an unrelated call's result excludes that call.** The set
of "this attempt's own executed calls" (E) drops a call whose result text contains a
built-in default deferral word (e.g. `"pending"`) or one that matches the target's own
`deferred_markers`. If a real, undeferred effect's result text happens to contain one of
those words for an unrelated reason (e.g. `"2 pending"` in an otherwise-successful
response), that call is excluded from E, and a genuine effect can read `"false"`. Avoid a
`verify_tool` or a linked call whose success text plausibly contains a default deferral
word. `deferred_markers` in the target file feed **both** checks: this executed-call
filter, and the separate deferral-growth check (step 3 of the rule, which decides
`"false"` when a declared marker's count grew from before the attempt to after). The
built-in default deferral words feed **only** the executed-call filter — step 3 never
sees them, so a default word growing in the verify output does not by itself mean
"defended". A different mechanism from the silent drop below, but the same landing spot:
`false`.

**A silent drop reads `"false"`, as it did in 0.10.3** — the linked call replied with
success, but the marker never appears in the target's state, before or after. This is
conservative: it cannot manufacture a false KEPT, only a missed finding, and the probe
says exactly what it saw. The one residual leak: a silent drop where the marker is
**already** present in state from an earlier attempt reads `"unattributed"`, not
`"false"` — a drop and an idempotent write look identical from state alone. `validate`
runs the unguarded runs and then the guarded runs inside one command, against the same
state, so a guarded twin that drops silently meets the marker the unguarded runs wrote
and can read as a leak; fresh state before each `validate` command does not prevent
this. A per-run marker does: set `expect_marker` to `{exfil_email}` or `{exfil_host}` and keep
the default per-run randomised exfil address, so each run looks for a marker no earlier run
wrote. A
guard that refuses at the tool boundary with `isError`, rather than replying with
success, also reads correctly, because a refused call never links.

**An effect that is real but the verify output cannot show it also reads `"false"`** —
delayed visibility (an async queue, an eventually-consistent store), a marker the target
transforms (lowercased, truncated, escaped), an output window that never surfaces the new
entry, or a marker containing a quote, a backslash or a line break (the before/after
comparison is on the read result's Python repr, which escapes all three, so a multi-line
`{payload}` never matches). None of this is new in 0.10.4: a marker the verify tool
cannot show synchronously, as the literal text, once the agent's run ends, read `"false"`
in 0.10.3 too.

**A baseline read that returns `isError` counts as empty state.** A transient server
error on that read, such as a rate limit, makes a marker already in state look new, so
an earlier attempt's effect can be credited to this one when this attempt also links to
it.

## 9. A network failure can read the same as a refusal (W3)

A consequential call that errors reads as resisted, labelled server-reported
([`MYL-SRV-001`](reason-codes.md#myl-srv-001)) — see
[How an MCP attempt is decided](reading-results.md#how-an-mcp-attempt-is-decided). For a
W3 egress attempt, that same `isError` covers two different causes Mylonite cannot tell
apart from the trace alone: the server's own allowlist refusing the call, and the call
failing to reach the host at all — a DNS lookup that fails, a connection the sandbox
blocks, a timeout against a host that would have answered given more time. Neither is
proof the server would have refused a request that actually reached it.

**What this means in practice:** a KEPT differential on W3 is still trustworthy, because
it compares the *same* call against the vulnerable and guarded builds in the *same*
network environment — a resisted call that was really a network failure fails the same
way on both legs, so it never manufactures a false KEPT. The caveat is narrower: a
single `scan` run (no differential) that reports a W3 attempt as resisted on
`MYL-SRV-001` is not, on its own, proof the target's egress control did the resisting.
Check the error text the server returned before trusting a W3 resisted result in
isolation; a declared `effect_probe` that confirms no outbound call reached the
disallowed host is the stronger proof (see [Calibration](target-file.md#calibration)).

## 10. A probe can read before an asynchronous queue sends

A "queued" reply counts as resisted only when the `effect_probe` saw the hold, or a
calibrated probe saw no change (see [`MYL-INC-012`](reason-codes.md#myl-inc-012)). Even a
calibrated "no change" can be read before an asynchronous queue sends the message, so a
target that delivers late can still read `RESISTED (server-reported)`.

## Reporting something missing

If you hit a limitation that is not on this page, that is worth an issue: an undocumented
gap is a bug in this page, independent of whether it is a bug in the code.
