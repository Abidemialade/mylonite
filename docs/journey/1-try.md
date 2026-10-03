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

Either way this replays a recorded scan against the bundled practice
app's vulnerable and guarded builds — in-process, no network ports opened —
and prints the differential: what got through on the unsafe build, what was
stopped on the safe one. The model's replies are pre-recorded, so the run is
offline and gives the same answer every time; the scan engine, the adapters
and the comparison itself are the real ones. The output names which model
produced the recording and when. `demo --live` makes the same run with a
live model you choose (see [step 2](2-choose-a-model.md)) instead of the
recording.

## What to look for

- A **kept** finding: the attack landed on the vulnerable build and was
  stopped on the guarded one, repeated across runs so one lucky or unlucky
  reply can't decide it.
- The generated test for that finding, run against both builds: **red**
  (fails) on vulnerable, **green** (passes) on guarded. That contrast — the
  same test, two outcomes — is what every later step is working toward
  producing for your own app.

See [the practice app](../quarry.md) for what's deliberately broken in it
and why, and [Reading the results](../reading-results.md) for what every
field in the output means.

## Next

[2. Choose a model](2-choose-a-model.md) — every step from here on either
needs one, or tells you it doesn't.
