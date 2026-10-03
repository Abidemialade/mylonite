# The journey

Seven steps, each its own page, each the smallest unit a reader can follow
without jumping ahead: try the tool, choose a model, point it at your app,
find a weakness, prove it's real, commit the gate, then re-prove it after you
fix it. Every other doc page goes deeper on one of these; this set is the
order to read them in, start to finish, on your own machine.

## Before you start

- **Python 3.11-3.14.** Step 1 needs nothing else — no key, no git, no
  model, no manual install if you have [uv](https://docs.astral.sh/uv/).
- **A git repository**, once you reach [Commit the gate](6-commit-the-gate.md):
  `gate --open-pr` and `gate --workflows` both resolve your repo root with
  `git rev-parse --show-toplevel`. Only `--open-pr` additionally refuses a
  dirty working tree — it switches branch and commits; `--workflows` alone
  just writes `.github/workflows/*` files and doesn't check. You don't need
  a repository at all for steps 1-5 — `scan`, `generate` and `validate`
  write only under `.mylonite/`, inside or outside one. Stated here, not
  only under the `--open-pr` flag, because step 6 is reachable from a fresh
  checkout with no commits yet.
- **An MCP server you can run locally** (stdio), for steps 3 onward. No
  server yet? [Try it](1-try.md) uses the bundled one instead, so you can
  do steps 1-2 and see the shape of steps 3-7 before you have your own app
  wired up — or follow [Point at your app](3-point-at-your-app.md)'s two
  worked examples, launching a real server by name.

## The bar this is measured against

**Under 10 minutes from a clean checkout to a first finding on your own
server** (steps 1 through 4) is the target this journey is built to hit — a
target Mylonite's own rehearsal times on a fresh machine, not a promise made
in advance of measuring it. If your server needs more setup than `--command`/
`--arg` (a database, a long cold start), expect longer; [Point at your
app](3-point-at-your-app.md) says what the timer does and doesn't count.

## The seven steps

1. [Try it](1-try.md) — see a kept finding and a test that goes red, then
   green, with no key and no install step beyond `pip`.
2. [Choose a model](2-choose-a-model.md) — pick a provider (or run locally,
   for free) before any command that calls one.
3. [Point at your app](3-point-at-your-app.md) — scaffold a `target.yaml`
   for your MCP server, free, no model call.
4. [Find](4-find.md) — run the attack, read a candidate.
5. [Prove](5-prove.md) — confirm a candidate is a real, repeatable weakness.
6. [Commit the gate](6-commit-the-gate.md) — turn it into a test and a PR
   that gates CI.
7. [Re-prove](7-re-prove.md) — after you ship the fix, the loop that shows
   it actually worked.

## Coverage, before you spend anything

Not every app shape gets every step's full claim — see [Coverage by app
shape](../index.md#coverage-by-app-shape) for which weakness classes apply to
yours before you start step 3.
