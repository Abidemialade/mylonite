# Re-validate on a new model

A committed Mylonite test proves that a safeguard stopped an attack **with a particular
model driving your agent**. When you change that model — a new version, a new provider, a
cheaper tier — re-prove the test against it before you ship. This is the scheduled half of
the workflow: run it when the model changes, not on every commit.

> **Why this matters.** A model can resist an injection on its own good behaviour. If that
> behaviour is what was stopping the attack, a model change can remove the protection
> without any change to your code. Re-validating asks the same question the original
> validation did — does the attack fire without the safeguard and get stopped with it? —
> with the new model in the planner's seat.

## 1. Find the committed test

`mylonite generate` (or `gate`) wrote the test into a directory such as
`.mylonite/generated/<finding>/` or your gate directory. The `notes` field of its
`validation_report.json` records the model it was last proved against, as
`validated against model: <model>`.

## 2. Re-validate with the new planner model

The *planner* is the model driving the agent under test, so it is the one to change.
Keep the customiser and judge where they were, so the only variable is the model your
app actually runs:

```bash
mylonite validate .mylonite/generated/<finding> \
  --target-file app.yaml --authorize my-app \
  --planner-model <new-model>
```

This is **live**: it re-drives your app, calls the provider, and needs its API key. It
prints the calls and tokens it used when it finishes. To compare several models, run it
once per model.

For a test against the bundled reference app, drop `--target-file` and `--authorize`.

## 3. Read the verdict

`validate` stamps the model it proved the test against into the report — the planner
model, plus the customiser and judge models when they differ:

```
validated against model: <new-model>  (customiser: <model>, judge: <model>)
```

- **Kept on the new model.** The safeguard still carries the security with the new model
  driving your agent. Commit the updated `validation_report.json` (and, for the
  reference app, the re-recorded `fixtures/`).
- **Not kept on the new model.** Read which leg failed (see
  [Reading the results](reading-results.md)). Two readings are possible, and the
  `reproducibility` line tells them apart:
    - the **differential** no longer holds because the attack now lands *with* the
      safeguard in place — the safeguard does not stop this attack on the new model;
    - the attack no longer fires **without** the safeguard either — the new model resists
      it on its own. The test then no longer discriminates, and the safeguard's value for
      this attack cannot be measured with this model. Keep the safeguard: a later model may
      not resist.

## 4. Carry it into CI

The committed test records, when it is generated, the model the per-PR gate re-drives
with. Once the new model is the one you ship, regenerate the gate with it so the per-PR
check runs against that model:

```bash
mylonite gate --target-file app.yaml --authorize my-app --model <new-model>
```

## 5. Make it routine

Add the re-validation to whatever process ships a model change — the pull request that
bumps the model name, or a scheduled job that re-validates the committed tests against
each model you deploy. The same run reports its spend on the `llm:` line.

See also: [the validation engine](validation.md), [model roles](attack-modes.md#composing-the-model-roles),
and [CI gating](ci-gating.md).
