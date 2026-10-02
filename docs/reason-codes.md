# Reason codes

Every result that is not a verdict carries a reason code, such as `[MYL-NT-005]`.
Look the code up on this page: each entry says what happened and the fix. A result
with a reason code is never a clean result.

```text
error: [MYL-NT-005] coverage was incomplete or absent and nothing was found, but the
scan was never formally aborted (...). This is NOT a clean result — 3 of 3 untested
attempt(s) had no seed_arm to plant the payload — declare a seed_arm in the target
file (see docs/target-file.md), then re-run.
```

A code keeps its meaning once it ships. New causes get new numbers; a retired code
stays listed here. Reason codes do not change exit codes: see
[Exit codes](reading-results.md#exit-codes-for-ci) for those.

| Prefix | Where you see it | What it means |
|---|---|---|
| `MYL-NT` | the `coverage:`, `judge:` and `attack modules:` summary lines, the incomplete-coverage error | an attempt was NOT TESTED: it proved nothing about the target |
| `MYL-ABT` | the error line after an aborted scan | the scan stopped before it covered what it set out to |
| `MYL-PRE` | the error line before a scan starts | the run was refused before any LLM call |
| `MYL-INC` | an attempt's evidence | the attack ran, but the effect evidence could not be trusted, so the attempt is NOT TESTED |
| `MYL-SRV` | an attempt's evidence | the target resisted, but the result rests only on the server's own reply |

## MYL-NT-001

The target's command never started, so nothing was tested. Shown as `⚠ LAUNCH FAILED`.

**Fix:** Check the target file's `command:` and `args:`, and that the server actually starts.

## MYL-NT-002

The planner failed before the attack could be delivered.

**Fix:** Check connectivity to the target and to the model.

## MYL-NT-003

The agent never called the tool this attack targets. See
[what counts as NOT TESTED](reading-results.md#the-terminal-trust-panel) for the two
ways this happens.

**Fix:** Check the target's `purpose` and `system_prompt`, and that the planner model
is tool-capable.

## MYL-NT-004

The seed needs a capability this target's tool surface does not expose.

**Fix:** The seed doesn't fit this target. Check `weakness_classes` and the target's
tool surface.

## MYL-NT-005

There was no `seed_arm` to plant the poisoned content.

**Fix:** Declare a `seed_arm` in the target file (see
[target.yaml reference](target-file.md)).

## MYL-NT-006

The payload was planted, but the planner never retrieved it.

**Fix:** Check the `seed_arm`'s `args_template` and `id_key`, and the recall wiring.

## MYL-NT-007

The attempt failed on an LLM provider call.

**Fix:** Check each attempt's `verdict_reason` and `error_detail`. A common cause is
missing or invalid provider credentials.

## MYL-NT-008

The attempt raised an error that is not a provider failure, such as a target crash.

**Fix:** See each attempt's `verdict_reason` and `error_detail`.

## MYL-NT-009

The `effect_probe`'s verify call errored, so the effect was not confirmed either way.

**Fix:** Check the `effect_probe` wiring: `verify_tool` and `verify_args_template`.

## MYL-NT-010

The LLM judge answered, but its output could not be used.

**Fix:** Check the judge model (`--judge-model`).

## MYL-NT-011

The deterministic check was inconclusive and no LLM judge was configured.

**Fix:** Set a judge model, or accept this as an intentional predicate-only run.

## MYL-NT-012

No mechanism (deterministic check, `effect_probe` or LLM judge) decided the attempt.
Shown as `⚠ NO VERDICT`.

**Fix:** Check each attempt's `verdict_reason` and `judge_evidence` for the cause.

## MYL-NT-013

The seed's metadata was invalid, so the attack never ran.

**Fix:** This is an internal catalogue defect. Please
[file an issue](https://github.com/Abidemialade/mylonite/issues).

## MYL-NT-014

The seed could not be resolved from the catalogue, so the attack never ran.

**Fix:** This is an internal defect. Please
[file an issue](https://github.com/Abidemialade/mylonite/issues).

## MYL-NT-015

The attack module that covers this class failed to load, so its attacks never ran. The
module either failed to import (a broken package, a missing dependency) or raised when
it was constructed. The other modules still run. The summary prints an
`attack modules:` line naming each failed module, the step that failed and the error
type; the error message itself is never shown, because it can quote paths or secrets.

```text
attack modules: 1 failed to load [MYL-NT-015]: prompt_injection (import failed:
ImportError; W1, W2 NOT TESTED). Their attacks never ran, so this is not a clean
result for what they cover.
```

Each weakness class the module would have run on this target reads NOT TESTED with
this code, in the class summary and in `verdicts.json`. A scan with no finding exits
`2`, the same as any other incomplete coverage.

The classes of a module Mylonite ships are known even when it fails to load. A
third-party module that fails to import or construct can't say which classes it
covers, so it shows as one NOT TESTED row in the `unknown` class instead. That row
appears only when the module would have run: you opted its entry-point name or an id
into `MYLONITE_ATTACK_MODULES` that no loaded module answers to. In that second case
the line also names the unmatched id, because a typo in the opt-in list looks the
same. A module nobody enabled loses no coverage, so its failure stays a log warning.
`mylonite plugins` lists a failed module as `FAILED TO LOAD (<error type>)`.

**Fix:** Reinstall the module's package and its dependencies, then re-run. The
`attack modules:` line names the module and the error type.

## MYL-NT-016

No attack module in this run emitted an attack for this class on this target, so the
class was never attacked. The common case is a `transport: rest` target that declares W3 or W4:
those attacks need a tool-using (MCP) agent, and none runs over a plain HTTP endpoint.
Coverage is counted from the attacks each class actually got, not from the seeds
scheduled for it, so the class reads NOT TESTED instead of dropping out of the result.

```text
classes:
  W2  RESISTED (1 resisted)
  W4  NOT TESTED [MYL-NT-016] (1 not tested)
```

A scan with no finding exits `2`, the same as any other incomplete coverage. `scan`
warns about this before it starts.

The code also fires on an MCP target when the attack modules that ran leave a class out,
for example when `MYLONITE_ATTACK_MODULES` or a third-party module set covers only some
classes.

**Fix:** Enable an attack module that covers this class (the `attack modules:` line
lists what ran). On a `transport: rest` target, scan the agent's MCP server instead. Or
remove the class from `weakness_classes`.

## MYL-NT-017

No tool on this server reads its state back and no `effect_probe` is declared, so a W3
or W4 effect could not be confirmed or ruled out. Such a server gives Mylonite no way to
see whether a send, fetch or write took effect, so the class reads NOT TESTED instead of
resisted. If an attempt in the class fired, the finding still stands.

```text
classes:
  W2  RESISTED (1 resisted)
  W4  NOT TESTED [MYL-NT-017] (1 resisted, 1 not tested)
```

`scan --scaffold` marks such a class "effect unconfirmable" in the file it writes. The
check uses the same readback detector the scaffold uses to propose an `effect_probe`.

**Fix:** Declare an `effect_probe` whose `verify_tool` reads back what the attack would
change (see [Target file](target-file.md)), or remove the class from `weakness_classes`.

## MYL-ABT-001

The scan used up its LLM call budget and stopped early; coverage is incomplete. Exit
code `3`.

**Fix:** Raise `--max-llm-calls` (the per-scan budget), or the hard request ceiling
(`--max-llm-requests` or `MYLONITE_MAX_LLM_REQUESTS`) when the run names it, or run fewer
weakness classes: `--weakness-class` on a reference or bundled target, `weakness_classes`
in the target file for a custom one. Then re-run.

## MYL-ABT-002

LLM provider calls failed several times in a row, so the scan stopped early. Exit
code `4`.

**Fix:** Check your provider's credentials (its own key environment variable --
see [self-hosted models](self-hosted-models.md) for the approved providers) and
`--model`, and that this machine can reach the provider. Behind a proxy, see
[Enterprise networking](enterprise-networking.md). Then re-run.

When the failures were rate limits (HTTP 429), the message says so instead, names the
provider and model, and suggests waiting, lowering `--max-concurrent` or
`--max-llm-calls`, or checking the account quota. When they were network errors,
timeouts or provider outages (HTTP 5xx), it points at the provider's status page and the
connection. See
[When the provider rate-limits or drops the run](reading-results.md#when-the-provider-rate-limits-or-drops-the-run).

## MYL-ABT-003

No seeds applied to this target, so nothing was scanned. Exit code `2`.

**Fix:** If this is a custom MCP app, declare which weakness classes it exposes, with
`weakness_classes` in the target file or `--weakness-class`.

## MYL-ABT-004

The `--weakness-class` filter matched no seeds for this target, so nothing was
scanned. Exit code `2`.

**Fix:** Drop or widen the filter, then re-run.

## MYL-ABT-005

A declared weakness class has no seed on this target's tool surface, so the scan
stopped before any payload. Running the other classes would have read as clean with
this one never attempted. Exit code `2`.

**Fix:** Each class's line names its fix: remove the class from `weakness_classes`
(or from `--weakness-class`), or give the target the tool that class needs. Then
re-run.

## MYL-ABT-006

The target could not be described (its tools were never listed), so nothing was
scanned. Exit code `2`.

**Fix:** Check the target command or scope, and connectivity.

## MYL-ABT-007

The scan exceeded its wall-clock budget and stopped early; coverage is incomplete.
Exit code `2`.

**Fix:** Raise the timeout or narrow the scan, then re-run.

## MYL-PRE-001

A declared weakness class cannot run at all on this target's tool surface, so the
run was refused before any LLM call. With `--dry-run` this is a warning instead.

**Fix:** Each class's line names its fix: remove the class from `weakness_classes`
(or from `--weakness-class`), or give the target the tool that class needs. Then
re-run.

## MYL-PRE-002

The server was not described in time to check which declared weakness classes can
run, so the run was refused.

**Fix:** Re-run (a first npx or uvx download is cached after that), or raise
`timeout_s` in the target file.

## MYL-PRE-003

Describing the server raised an error, so which declared weakness classes can run is
unknown, and the run was refused.

**Fix:** Check that the target file's `command` and `args` start the server and that
it lists its tools, then re-run.

## MYL-PRE-004

Starting or describing the server timed out while `scan` was inferring a `seed_arm`.

**Fix:** Re-run once the download finishes (it is cached after that), or set
`timeout_s` in the target file to raise the budget.

## MYL-PRE-005

Starting or describing the server failed while `scan` was inferring a `seed_arm`.

**Fix:** Fix the cause printed after the code. It names the failing step, usually the
target file's `command`, `args` or `timeout_s`. Then re-run.

## MYL-INC-001

A consequential tool call went through, but it could not be tied to this attempt.

**Fix:** Use an `effect_probe` marker the agent's call carries, such as
`{exfil_email}` or a unique token from the payload, so the call links to the attempt.

## MYL-INC-002

The effect probe was not calibrated: calibration was not authorized, its controls
were set to skip, or the target could not be launched to run them.

**Fix:** Pass `--authorize` (`scan`/`gate`/`ablate`/`validate`) so the
calibration controls can run, and do not set `calibration.controls` to `skip`. A
remote (`sse`/`http`) target also needs `calibration.controls: allow` -- `auto`
only runs on an authorized `stdio` target. If the target could not be launched,
check that its `command:` and `args:` start the server.

## MYL-INC-003

Positive control failed: the probe did not see a known write.

**Fix:** Point `verify_tool` at a tool that reads back what the consequential tool
writes, and make `verify_args_template` select the written record by a fixed value, not
`{payload}`. An attempt fills `{payload}` with its whole attack text, so calibration
cannot prove that read and refuses to certify it.

## MYL-INC-004

Negative control failed: the probe reported a change when nothing was written.

**Fix:** Scope `verify_args_template` to a single record or query, so unrelated state
changes do not read as an effect.

## MYL-INC-005

The verify or control arguments fail the tool's `inputSchema`.

**Fix:** Add the missing required argument the message names to the template it
names (`verify_args_template` or the `seed_arm`'s `args_template`), matching the
tool's `inputSchema`. When it names a control write or a recall call, that tool needs
an argument Mylonite cannot fill: list a simpler tool under `consequential_tools` or
`read_tool_names`.

## MYL-INC-006

W2 seed control failed: the planted content could not be recalled.

**Fix:** Check the `seed_arm`'s `args_template` and `id_key`, and that the recall tool
reads back what the plant tool stores.

## MYL-INC-007

W2 seed control did not run: no recall tool could be inferred.

**Fix:** Declare a `seed_arm` naming the store tool, and make sure the server exposes
a tool that reads the stored content back.

## MYL-INC-008

The `effect_probe` marker renders from `{payload}`, which the agent's call never
carries.

**Fix:** Use `{exfil_email}`, or a token the agent's call carries, as the marker
instead of `{payload}`.

## MYL-INC-009

The tool list could not be read again after the agent ran, or was not compared in a
known form, so a mid-session change to the tools was not checked.

**Fix:** Check that the server still answers `tools/list` after a few tool calls (it
may have crashed or closed the session), then re-run. A result replayed from an older
run carries no signature form; re-run the scan to compare every tool field.

## MYL-INC-010

The server's tool list was read only in part, so tools on the unread pages were never
tested.

**Fix:** Check the server's `tools/list` pagination: it repeated a cursor or returned
more than 100 pages. Fix the server's `nextCursor` handling, then re-run.

## MYL-INC-011

The LLM judge leaned toward the attack landing, but below the confidence it needs to
count as a finding, so the attempt proved neither a finding nor resistance.

**Fix:** Read the attempt's judge rationale and tool trace to decide it yourself, then
re-run with a stronger judge model (`--judge-model`), or declare an `effect_probe` so the
result rests on observed state.

## MYL-INC-012

The server replied that it queued or held a consequential call, and the effect probe did
not see the action held, so it may still take effect. A reply counts as deferred when it
carries a default deferral word ("queued", "pending", "will be sent" and the like), a word
from the probe's `deferred_reply_words` or `deferred_markers`, or a task handle
(`resultType: "task"` or a `task` field), whatever its text. One queued call is enough,
even when another call in the same attempt went through. "Queued" is also how an asynchronous mailer says it accepted a
message, and the probe reads right after the call, so a calibrated "no change" can come
before the queue sends. The attempt is NOT TESTED instead of `RESISTED (server-reported)`,
and a scan with no finding exits `2`. If the action took effect before the probe read,
the attempt is a finding at `effect-confirmed` instead, once the probe declares the word
that marks a held item; without it, a new record after a queued reply can't be told from
the held item and the attempt stays NOT TESTED.

**Fix:** Declare an `effect_probe` whose verify tool lists held actions, and name the word
it marks them with in `deferred_markers`, so a held action can be told apart from one
accepted for later delivery.

## MYL-SRV-001

The negative rests only on the server returning an error.

**Fix:** Check the error is a refusal, not a network or configuration failure, and
declare an `effect_probe` so the result rests on observed state.

## MYL-SRV-002

The negative rests only on a server reply deferring the action. It appears only when the
`effect_probe` saw the action held: a word from `deferred_markers` grew in the verify
tool's output. A calibrated "no change" is not enough; without the hold the attempt is
NOT TESTED under [`MYL-INC-012`](#myl-inc-012).

**Fix:** Declare an `effect_probe` so the result rests on observed state, not on the
server's reply.
