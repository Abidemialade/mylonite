# 7. Re-prove

You've shipped a fix for the finding [step 6](6-commit-the-gate.md)
committed. Mylonite doesn't write that fix — it's a change in your own
app's code or configuration that closes the gap the gate test proved. This
page starts from there, once it's shipped. One local command answers the
question the rest of this journey has been building toward: **did it
actually work?**

```bash
MYLONITE_LIVE_TARGET=1 pytest .mylonite/gate/
```

**The environment variable is not optional.** Without
`MYLONITE_LIVE_TARGET=1`, the test is **skipped** — every time, before the
fix and after it — and `pytest` exits `0` either way, which looks like a
pass but proves nothing. The emitted test is wrapped in a
`pytest.mark.skipif` that pytest evaluates before the test body ever runs,
so a bare `pytest .mylonite/gate/` never reaches the re-drive, and never
reaches `@testkit.pending_fix(...)` either. `mylonite generate`/`gate`
print this exact command, with the variable, for that reason.

With `MYLONITE_LIVE_TARGET=1` set, this **re-drives your real app live**:
it launches your MCP server and calls the model from [step 2](2-choose-a-model.md)
again (`testkit.assert_target_resists`), so it needs that provider's key and
network access to both the provider and your server — the same
prerequisites `gate` itself needed. It is not a replay of recorded fixtures;
each run genuinely re-attacks your current build.

This spends too: the global `--max-llm-requests N` / `MYLONITE_MAX_LLM_REQUESTS=N`
ceiling from [step 4](4-find.md) still applies here, since the redrive goes
through the same LLM call path.

The committed test also carries `@testkit.pending_fix(...)`, and that
decorator is what makes the same command answer "fired before, resisted
after" at each stage, with no separate "before" run to remember to keep
around:

1. **Before the fix.** The attack still lands, so the check fails — reported
   as an expected failure (`xfail`), and the run stays **green**: `pytest`
   itself exits `0`. This is the "fired before" half: a check that could
   pass today would be lying about what the pending test is still proving.
   This is the stage this step's one command reaches if you run it before
   shipping anything — exit `0` is expected here too, which is why a bare
   exit-code check alone can't tell "pending, as committed" apart from
   "actually fixed" (read the printed text either way).
2. **After the fix.** The attack lands on no re-drive attempt and is
   stopped on at least one (3 attempts by default —
   `MYLONITE_REDRIVE_ATTEMPTS=1` makes this a cheaper, single-attempt
   check; an attempt where the agent made no tool calls counts as neither,
   and if every attempt is like that the test errors instead), so the check now **fails on purpose** — a real
   `pytest` failure, exit `1` — printing: *The attack did not land on any
   re-drive attempt this run. If your fix has landed, remove the
   `@testkit.pending_fix(...)` line above this test.* This is the exit code
   this step expects right after you ship a real fix: `1` here is the
   "resisted after" half, read as a prompt to act, not a broken build.
3. **Marker removed.** Delete the `@testkit.pending_fix(...)` line. The test
   is now a plain regression gate: exit `0` while the fix holds, exit `1` if
   the attack ever works again — the thing CI depends on from here on.

`pytest -m mylonite_pending_fix` lists every test on your branch still
waiting on step 3. The full mechanism — including what counts as "fixed"
for a live re-drive, and what a check that never reached a verdict does
instead of silently passing — is documented once, in [the pending-fix
lifecycle](../testkit.md#the-pending-fix-lifecycle) and [CI
gating](../ci-gating.md#other-ci-systems-jenkins-gitlab), including the
full cost table; this page exists so the command to run is never more than
one page away from "I just fixed it."

## When you change models instead

Re-proving against a new or upgraded model, rather than after a code fix, is
a different page: [Re-validate on a new model](../model-upgrade.md).

## The habit, from here

Steps 1-7 are one pass. Run `gate` again — on the next change, on a nightly
schedule, against the next app you point it at — and each pass adds to the
same committed gate directory rather than starting over.
