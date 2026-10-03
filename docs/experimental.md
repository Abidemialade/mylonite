# Experimental commands

`check` and `ablate` are hidden — they don't show up in the top-level help
listing — and neither one runs unless you set `MYLONITE_EXPERIMENTAL=1`.
Without it, each exits with a one-line message telling you to set the
variable. They may change shape or be removed in a later release — don't
build a CI step on either yet.

```bash
export MYLONITE_EXPERIMENTAL=1          # bash/zsh
$env:MYLONITE_EXPERIMENTAL = "1"        # PowerShell
```

## `check` — static structural pre-check

Zero-key, zero-spend on-ramp: connects to a target ONCE (`describe()` — no LLM call, no
attack) and reports structural exposure from the tool schemas alone.

Options: a positional `reference:vulnerable` / `reference:guarded` target, or
`--target-file PATH` for your own app (or set `target_file:` in `mylonite.yaml`) —
one of the two is required; `--enforce` (exit `1` on the substantive W1–W4 structural
findings instead of reporting and exiting `0`). The "unpinned descriptions" advisory is
**shown but does not gate**: it fires on every tool of every server on first contact, so
gating on it would make `--enforce` red for everyone. `--config mylonite.yaml`
(auto-discovered from `./mylonite.yaml` when present).

`check` takes no `--authorize` and makes no writes at all. To run the calibration
controls (real writes proving a declared `effect_probe` can see a change before a real
scan ever trusts its "no change"), run `scan`/`gate`/`validate` with `--authorize`
against the same `--target-file` — see [Calibration](target-file.md#calibration).

`check` loads the target file before it connects, so a file the loader refuses stops
`check` with exit `2` and the loader's message. One example: a `transport: rest` target
that declares an `effect_probe`.

```bash
MYLONITE_EXPERIMENTAL=1 mylonite check reference:vulnerable   # zero-key, no target file needed
MYLONITE_EXPERIMENTAL=1 mylonite check --target-file app.yaml
MYLONITE_EXPERIMENTAL=1 mylonite check --target-file app.yaml --enforce
```

A structural surface with any URL-taking tool can never come back fully clean — a
tool that reaches the network is itself a finding `--enforce` counts, so treat `--enforce`
as the honest first rung of a ramp (report it, fix the substantive findings it names, keep
it green as the surface changes), not a one-time gate you flip on once the surface happens
to read "clean."

Reports: consequential tools with no approval-shaped sibling tool, descriptions that
steer the agent, tools taking an apparent network destination, content-processing tools
that could carry an indirect-injection payload, unpinned tool descriptions (paste-ready
digests for `control_config.description_pins`), a target-file wiring name
(`seed_arm.tool`, `effect_probe.verify_tool`, or any `control_config` tool-name field)
that isn't among the server's described tools — a typo or a name copied from another
target file — and which weakness classes the surface suggests. Every finding except the
unpinned-descriptions advisory counts toward `--enforce`, including the wiring-name one:
a name that names no real tool means the plant or the effect probe silently never fires.
Every finding is a hint to confirm, never a verdict — `scan`/`gate` are what prove an
attack actually lands.

## `ablate` — score the safeguards

Toggle each AI safeguard and report which are **load-bearing**, **security theater**,
**redundant**, **no-attack** (the attack itself never reproduced, so there's nothing to
attribute), or **inconclusive** (a leg of the comparison never produced a trustworthy
result — a crash, a provider outage, a target that failed to launch). See
[the control-efficacy check](validation.md#the-control-efficacy-check).

**Without `control_env` declared in your `target.yaml`, `ablate` grades Mylonite's own
boundary stand-in, not your safeguard.** The matrix's `guarded side:` line names which one
played the guarded side on that run; a load-bearing row only earns the stronger claim
("your implementation is doing the work") when `guarded side:` names your own
server-layer control. Declare `control_env` to get that reading — see
[Which claim you earned](reading-results.md#which-claim-you-earned).

Options: `--target-file PATH` (**required** — there is no positional target form, and the
bundled `reference:*` targets are not accepted); `--authorize` (the target's `scope`, or
its family when it declares no scope); `--controls W2,W3,W4`;
`--iterations N`; `--redundancy` (all-minus-one, to tell redundant from theater);
`--max-seeds N`; `--model` (any LiteLLM provider via a `provider/model` prefix).

On a target that declares an `effect_probe`, the raw and guarded legs of each
comparison run one after the other instead of at the same time, so slower is the
cost of a correct read on a target whose evidence lives in state the two legs
would otherwise share (a file, a database, a remote server). A target with no
`effect_probe` keeps running its legs at the same time.

```bash
MYLONITE_EXPERIMENTAL=1 mylonite ablate --target-file app.yaml --authorize my-app --controls W2,W4 --redundancy
```

A control that comes back `no-attack` has nothing to attribute — it is not the same as
"untested": the attack ran and simply never reproduced on this surface, so there is no
result for that control to earn or lose.
