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
`UNVALIDATED` until the next command keeps it, and the command prints the
exact `mylonite validate <dir>` to run next.

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

## Next

[6. Commit the gate](6-commit-the-gate.md) — turn a kept finding into a test
your CI depends on.
