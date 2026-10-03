# 1. Try it

No API key, no git, no server of your own. One command, with
[uv](https://docs.astral.sh/uv/) installed:

```bash
uvx --from "mylonite[demo]" mylonite demo
```

Or install first, then run it the same way every time after:

```bash
pip install "mylonite[demo]"
mylonite demo
```

GitHub-hosted runners (`ubuntu-latest`, `windows-latest`) don't preinstall
`uv`. In CI, or anywhere you can't install it first, use the `pip install`
path above — it needs only Python.

Either way this replays a recorded run against the bundled practice
app's vulnerable and guarded builds, in-process with no network ports opened.
It shows a kept finding and its generated test, then the differential: what
got through on the unsafe build, what was stopped on the safe one. The
model's replies are pre-recorded, so the run is
offline and gives the same answer every time; the scan engine, the adapters
and the comparison itself are the real ones. The output names which model
produced the recording and when. `demo --live` makes the same run with a
live model you choose (see [step 2](2-choose-a-model.md)) instead of the
recording.

**Exit codes.** `0` on success, whether replayed or `--live`. Replay's only
failure is `2` (a missing or corrupt fixture — reinstall `mylonite`, or add
`--live`). `--live` adds the two codes every other live command uses: `4` if
no provider is reachable, `3` if it runs out of budget before both builds
finish.

## What to look for

- A **kept** finding: the attack landed on the vulnerable build, was
  stopped on the guarded one, and still held when the attack was reworded.
  The recording has one run per build, so the output marks stability
  "not measured"; a live `validate` repeats each build to measure it.
- The generated test for that finding: its check fails (**red**) on the
  vulnerable build, and the test file itself passes (**green**) on the
  guarded one. That contrast is what every later step works toward
  producing for your own app.

See [the practice app](../quarry.md) for what's deliberately broken in it
and why, and [Reading the results](../reading-results.md) for what every
field in the output means.

## Next

[2. Choose a model](2-choose-a-model.md) — every step from here on either
needs one, or tells you it doesn't.
