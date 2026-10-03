# 5. Prove

A finding from [step 4](4-find.md) is a candidate until a second command
confirms it's a real, repeatable weakness rather than one lucky (or unlucky)
model reply.

## Write the test

```bash
mylonite generate --latest
```

**Offline, no LLM call.** Reads the newest scan's finding and emits a
`pytest` test from the [testkit API](../testkit.md). The test is stamped
`UNVALIDATED` until the next command keeps it. For a custom target (your own
app), this is real output from running `generate --latest` against the
kitchen-sink example from [step 3](3-point-at-your-app.md) — only the
directory, a long absolute path here, is shortened to `<dir>` below:

```text
generate --latest: using <dir>/scans/20261003T000000Z
Wrote test:    <dir>/generated/indirect_injection_note_body_direct/test_security_indirect_injection_note_body_direct.py
Wrote exploit: <dir>/generated/indirect_injection_note_body_direct/exploit_indirect-injection-note-body-direct.json
Fixtures dir:  <dir>/generated/indirect_injection_note_body_direct/fixtures
Using target:  <dir>/scans/20261003T000000Z/target.yaml (from the scan dir)
Wrote target:  <dir>/generated/indirect_injection_note_body_direct/target.yaml

Next - this is a LIVE custom-target test. To run it you need:
  - pytest + mylonite installed in the consuming environment
  - ANTHROPIC_API_KEY set
  - your target's MCP server runnable, and target.yaml co-located
Then:
  MYLONITE_LIVE_TARGET=1 pytest <dir>/generated/indirect_injection_note_body_direct
  mylonite validate <dir>/generated/indirect_injection_note_body_direct --authorize kitchen-sink
UNVALIDATED: this test is a candidate until `mylonite validate <dir>/generated/indirect_injection_note_body_direct --authorize kitchen-sink` keeps it as KEPT. Do not commit it as a gate test before then.
```

The line after "Then:" that starts with `mylonite validate` is the exact
command to run next — take it literally, paths and all, including
`--authorize`: a custom target carries its required value straight into
this line, so it runs as printed instead of being refused for a missing
`--authorize`. That value is the target's declared `scope` — `kitchen-sink`
above is this branch, the same `--scope` [step 3](3-point-at-your-app.md)
scaffolded with — or its family when it declares no scope at all. (A
reference-target finding, not a custom one, needs no `--authorize` at
all — it skips the LIVE block above and prints only
`Next: mylonite validate <dir>`.) The second credential line names the env
var for whichever provider you chose in [step 2](2-choose-a-model.md)
(`ANTHROPIC_API_KEY` here); with no provider resolved it reads "your
provider's API key" instead, naming no vendor. Every path always prints with
forward slashes, on Windows too — Windows itself, Python and the paths above
all accept that form — and still gets quoted on top of that if it contains a
space (or anything else a shell would split on). Copy either line verbatim
either way.

**Exit codes.** `0` once the test is written. `2` is a config/usage error —
no scan found (run `mylonite scan` first), or an invalid `--target-file`.
`5` only if you re-run `generate` against a finding a prior `validate`
already rejected, without passing `--unvalidated`.

## Confirm it

```bash
mylonite validate .mylonite/generated/<finding>
```

**Live** — runs the attack against your target across a 5-run flakiness
filter, and, by default, against Mylonite's own stand-in safeguard at the
tool boundary too (your target file's `control_env`, if you declared one,
makes this your own safeguard instead — see [the control-efficacy
check](../validation.md#the-control-efficacy-check)). A finding is **kept**
only if the attack fires without the safeguard and is stopped with it,
repeated across the filter — the [two tiers of proof](../validation.md#the-control-efficacy-check)
page says exactly which claim you earn depending on whether you declared
`control_env`.

Exits `0` when kept, `5` when cleanly rejected. A result that rests only on
`judge-only` evidence (see [step 4](4-find.md#reading-the-output)) is never
kept.

This step spends too — the same global `--max-llm-requests N` /
`MYLONITE_MAX_LLM_REQUESTS=N` ceiling from [step 4](4-find.md) applies here;
hitting it exits `3`.

## Next

[6. Commit the gate](6-commit-the-gate.md) — turn a kept finding into a test
your CI depends on.
