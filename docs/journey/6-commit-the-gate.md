# 6. Commit the gate

`gate` runs steps [4](4-find.md) and [5](5-prove.md) in one command — scan,
generate, validate — and, opt-in, opens the pull request. This is the step
that needs [a git repository](index.md#before-you-start): `--open-pr` and
`--workflows` both resolve your repo root with `git rev-parse
--show-toplevel`. Only `--open-pr` refuses a dirty working tree —
`--workflows` alone writes its CI files without that check.

```bash
mylonite gate --target-file app.yaml --authorize my-app
```

**By default, nothing outside `.mylonite/gate/` changes.** `gate` writes the
test, the exploit record and the validation report there, and prints the
exact `git`/`gh` commands to commit and open the PR yourself. This is real,
copy-pasteable output for a single kept W2 finding (the pattern id
`indirect-injection-note-body-direct` from the kitchen-sink example in
[step 3](3-point-at-your-app.md)) — a different finding writes different
filenames (the hash after `w2-`/`w4-`/etc. is `sha256(pattern_id)`, so it's
the same every time for the same finding, never random), and on Linux/macOS
the paths use `/` instead of `\`:

```text
Gate artifacts written to '.mylonite\gate'. Your repository was not modified.
To commit them and open the gating PR, run:
  git checkout -b mylonite/gate-indirect-injection-note-body-direct
  git add '.mylonite\gate\test_w2-494b28.py' '.mylonite\gate\exploit_w2-494b28.json' '.mylonite\gate\validation_report.json' '.mylonite\gate\target.yaml' '.mylonite\gate\fixtures' '.mylonite\gate\PR_BODY.md'
  git commit -m 'Mylonite gate: indirect-injection-note-body-direct'
  git push -u origin mylonite/gate-indirect-injection-note-body-direct
  gh pr create --base main --head mylonite/gate-indirect-injection-note-body-direct --title 'Mylonite gate: indirect-injection-note-body-direct' --body-file '.mylonite\gate\PR_BODY.md'
```

**To commit the gate without opening a PR,** run the plain command above
(no `--open-pr`), then run only the printed `git checkout -b` and
`git add`/`git commit` lines yourself, verbatim — stop before the `git
push`/`gh pr create` lines. That commits the gate test to a local branch;
push and open the PR whenever you're ready, or never.

To do the whole thing — commit, push and open the PR — in one run:

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

**Capping the spend.** `gate` runs `scan` and `validate` under the hood, so
the same `--max-llm-calls` (per-scan budget) and global
`--max-llm-requests N` / `MYLONITE_MAX_LLM_REQUESTS=N` (hard ceiling, exits
`3`) from [step 4](4-find.md) apply to the whole `gate` run.

**Exit codes.** `9` means at least one proven finding was kept and its gate
test written; `0` means the scan ran and found nothing. `10` means nothing
was kept, but something reproduced without proof — a **candidate**, printed
with the reason and how to get it proven, never written as a gate test
(never-keep-unproven). `5` is a finding that was rejected rather than kept;
`6`/`7` are the generator/validator returning nothing (an internal
failure); `8` means the git/gh step itself failed — your findings and
validation report are still on disk, not lost.

## A finding you haven't fixed yet

`gate` commits a test for a weakness that still works on your app as a
**pending fix**, so the PR doesn't turn CI red the day it merges. [Step
7](7-re-prove.md) is exactly this: what to run once you've shipped the fix.

## Next

[7. Re-prove](7-re-prove.md) — ship the fix, then show it actually worked.
