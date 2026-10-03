# 6. Commit the gate

`gate` runs steps [4](4-find.md) and [5](5-prove.md) in one command — scan,
generate, validate — and, opt-in, opens the pull request. This is the step
that needs [a git repository](index.md#before-you-start): `--open-pr` and
`--workflows` both resolve your repo root with `git rev-parse
--show-toplevel` and refuse a dirty working tree.

```bash
mylonite gate --target-file app.yaml --authorize my-app
```

**By default, nothing outside `.mylonite/gate/` changes.** `gate` writes the
test, the exploit record and the validation report there, and prints the
exact `git`/`gh` commands to commit and open the PR yourself.

```bash
mylonite gate --target-file app.yaml --authorize my-app --open-pr --workflows
```

`--open-pr` creates the branch, commits, pushes and opens the PR via `gh`.
`--workflows` adds the two CI templates: a per-PR gate and a nightly
discovery run, each naming the key variable your [chosen provider](2-choose-a-model.md)
needs. Only a **kept** finding (step 5's bar) makes it through; a finding
that was found but not proven is never silently gated as if it were. See
[CI gating](../ci-gating.md) for the full flow, every flag, and what the PR
body carries (the fix, the impact, the evidence, and a reviewer checklist).

## A finding you haven't fixed yet

`gate` commits a test for a weakness that still works on your app as a
**pending fix**, so the PR doesn't turn CI red the day it merges. [Step
7](7-re-prove.md) is exactly this: what to run once you've shipped the fix.

## Next

[7. Re-prove](7-re-prove.md) — ship the fix, then show it actually worked.
