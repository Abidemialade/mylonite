# Experimental commands

`check`, `ablate` and `access` are hidden — they don't show up in the top-level help
listing — and none of them runs unless you set `MYLONITE_EXPERIMENTAL=1`.
Without it, each exits with a one-line message telling you to set the
variable. They may change shape or be removed in a later release — don't
build a CI step on any of them yet.

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

`check reference:vulnerable` and `check reference:guarded` report the **same** findings
and the same `--enforce` exit code: `check` only reads tool schemas (`describe()`), and the
guarded twin's safeguard is a runtime behaviour that schema has no way to show. A tool
surface looking identical either way is expected, not a sign the guard did nothing —
`scan`/`gate`, which actually drive an attack and compare the two builds, are what show the
guard's effect.

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

After the findings, `check` prints the same tool inventory `scan --scaffold` writes into
the target file: every tool with its role, where the role came from, and whether the
scan's confirm gate treats it as consequential. It then names any tool with an unknown
role, which the scan treats as consequential. To confirm them, list every consequential tool under `control_config.consequential_tools`, including the ones already recognised: every tool left off that list is then treated as not consequential. Like the unpinned-descriptions advisory, the
inventory and the unknown-role line are not structural findings and never gate
`--enforce`: most servers have such a tool on first contact.

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

## `access` — compare a coding agent's GitHub grant with its intent

`access` reads what a coding agent can really reach in a GitHub test
organisation and compares it with an intent file the organisation's owner
approved. Every repository, permission or scope the agent holds beyond the
intent is a finding, and each finding names the configuration change that
clears it. For a GitHub App it can also drill revocation: it mints two
installation tokens, revokes one, and checks that the revoked token stops
working while the other still works.

```bash
export OWNER_TOKEN=...            # an organisation owner's token, used read-only
export APP_KEY_PATH=./app-key.pem # the App's private key file, for the drill
MYLONITE_EXPERIMENTAL=1 mylonite access --intent intent.yaml --authorize my-test-org \
  --owner-token-env OWNER_TOKEN --app-id 123456 --app-key-env APP_KEY_PATH
```

To start an intent file from the agent's current grant, run
`mylonite access --draft-intent intent.yaml --authorize my-test-org
--identity-kind github_app --app-slug my-agent --owner-token-env OWNER_TOKEN`
(for a classic token, `--identity-kind classic_token --token-env NAME`). It
writes the repositories, permissions or scopes the agent holds today, with
`approved_by` empty and no `approved_on`, so `access` refuses the file until
you edit it and approve it. Both escalation fields are written as `forbidden`,
and an `admin` level is written as `write` with a comment saying so. It
refuses to overwrite an existing file, sends no write, and runs no drill.

It runs only when the intent file is approved (`approved_by` and
`approved_on` set), says `environment: test`, and names the same organisation
as `--authorize`. All three are checked before any request is sent.

Options: `--intent PATH` and `--authorize ORG` (both required);
`--token-env NAME` (the agent's classic token, for a `classic_token`
identity); `--owner-token-env NAME` (an owner's token, for a `github_app`
identity); `--app-id ID` with `--app-key-env NAME` (a variable holding the
path to the App's private key; give both or neither); `--no-drill`;
`--out DIR` (default `./mylonite-access/`). Tokens and the key path come only
from environment variables. A missing variable is named, never shown, and no
token text is printed or written to the report.

**What it reads:** token scopes, App permissions, the repositories the agent
can reach and its level on each, repository rulesets and their bypass lists,
and the organisation's plan tier. It never reads file contents. Repositories
outside the organisation are counted, never named.

**The one write:** the drill revokes the installation tokens it minted
itself, with `DELETE /installation/token`. Nothing else is changed.

**Output:** `report.md` and `report.json` under `--out`, with a digest of the
inputs and a "not tested" list. Exit `0` when the grant matches the intent and
the drill held or did not run; `1` on an over-grant, an escalation, or a drill
that did not hold or came back `invalid`; `2` on a refused intent, a missing
variable or a token GitHub refuses. The last console line gives the result and
the not-tested count, for example
`result: PASS (12 items not tested; see report.md)`.

**What it does not test:** the drill does not run for a classic token (it can
only be revoked by hand in GitHub settings), without the App's private key,
with `--no-drill`, when the intent sets `controls.revocation: not_expected`,
when `--app-id` differs from the installation's app id, or when GitHub returns
no installation id to mint a token for. The report then lists the drill as not
tested, with that reason. For a classic token, the branch-rule bypass check
lists each ruleset's bypass actors as not tested: whether the token's user is
covered by a role or team needs membership data this version does not read. Fine-grained
tokens, classic branch protection, required review, approval for destructive
actions and what the agent did in real runs are not checked in this version;
the report lists each one.
