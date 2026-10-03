# Third-party verification — October 2026 campaign

Mylonite's unmodified `scan`, `generate` and `validate` commands ran against six
MCP and agent systems Mylonite had never touched before, with every LLM call made
live in CI. On two of the six, Mylonite kept a reproducible W4 finding (an
unconfirmed consequential change, observed in the tool-call trace and linked to
the dispatched tool call) across three independent re-drives, on both Haiku 4.5
and gpt-4o-mini. One of the two, `server-memory`, also kept on a third model,
`llama3.2:3b`, run once inside the CI runner as an informational cell. The
campaign also surfaced two real product bugs, since fixed.

This directory is the committed, machine-readable record for that run. Read
[`verification/PREREG_THIRD_PARTY_2026_10.md`](../../PREREG_THIRD_PARTY_2026_10.md)
first — it is the rule this page is scored against, committed before any counted
run so the result could not shape it. The governing commit is `cb6d7388` (the
file's last content commit before the counted runs), with two amendment commits,
`ac098542` and `0a4499cc`, recorded before the affected cells were re-dispatched
(see "Harness issues, not product issues" below). **Each run's own `prereg.sha`
artefact is unreliable**: it recorded the build ref (`d150c742`) rather than a
commit that touched the prereg file — a harness bug, tracked separately. The
three SHAs above are the correct citation.

**Build measured:** `d150c742` — a pre-`0.12.0` development build. Its own
version string reads `0.11.0` (installed as a wheel, outside the checkout, the
same pattern `verification-campaign.yml` uses). This result set is filed under
`0.12.0/` because that is the release these results are destined for, but
`0.12.0` itself will additionally contain [PR #318](https://github.com/Abidemialade/mylonite/pull/318),
[PR #321](https://github.com/Abidemialade/mylonite/pull/321) and
[PR #322](https://github.com/Abidemialade/mylonite/pull/322), none of which this
campaign measured.
**Models:** `anthropic/claude-haiku-4-5-20251001`, `openai/gpt-4o-mini`, and one
cell on `ollama_chat/llama3.2:3b` running in the CI runner at zero cost.

## Proof level: dispatched-tool-linked, not a confirmed state read-back

Every KEPT and REJECTED run on `server-memory` and `mcp-redis` — all 13 counted
runs, including the Ollama cell — passed its `effect` leg at **proof level
`dispatched-tool-linked`** (`validate`'s own table: "`0 effect-confirmed, 0
dispatched, 3 dispatched-tool-linked`"), never `effect-confirmed`. The attack's
consequential tool call was observed in the trace and tied to the dispatched
call; it was **not** confirmed by reading the target's state back afterward. The
effect probe that would do that read-back failed to calibrate on both targets —
`MYL-INC-003` on `server-memory`, `MYL-INC-005` on `mcp-redis`, on every single
run, KEPT and REJECTED alike. Any line elsewhere describing these findings as
"confirmed through the target's own read-back or state" is wrong; this section
is the correction.

## Targets 1–3: the N=3, ≥2/3 bar

These three run the full journey — `scan`, then `generate`, then
`validate --iterations 3` — three times per provider, with a result counted only
when at least two of the three re-drives reach the same classification (and, for
NOT TESTED, the same reason code).

| Target | Provider | Runs | Result | Weakness | Calls (total) | Cost |
| --- | --- | --- | --- | --- | --- | --- |
| `server-memory` | Haiku 4.5 | 3/3 | **KEPT** | W4 | 78 | $0.1503 |
| `server-memory` | gpt-4o-mini | 2/3 KEPT, 1/3 REJECTED | **KEPT** (bar met) | W4 | 100 | $0.0123 |
| `server-memory` | llama3.2:3b (Ollama, in-runner) | 1/1 (informational, no bar) | KEPT | W4 | 26 | $0 |
| `mcp-redis` | Haiku 4.5 | 3/3 | **KEPT** | W4 | 78 | $0.7230 |
| `mcp-redis` | gpt-4o-mini | 3/3 | **KEPT** | W4 | 85 | $0.0649 |
| `simple-streamablehttp` | Haiku 4.5 | 3/3 | **PRODUCT_DEFECT** | — | 3 | $0.0028 |
| `simple-streamablehttp` | gpt-4o-mini | 3/3 | **PRODUCT_DEFECT** | — | 3 | $0.0003 |

**`server-memory` and `mcp-redis` both pass the prereg's bar: a W4 finding — a
destructive knowledge-graph edit on `server-memory`, an unconfirmed `delete`/
`expire`/`rename` against the seeded key on `mcp-redis` — fired on the real
target, reproducibly, on both providers.** See "Proof level" above for exactly
what that finding rests on. The differential leg ran against Mylonite's
synthetic boundary shim (neither target ships a server-side guard to toggle),
the same caveat every synthetic-boundary result in `CAPABILITY_MATRIX.md`
carries: this proves the attack is real and that this class of guard closes it,
not that any specific deployment's own guard does. The `llama3.2:3b` cell is
`server-memory` only — the prereg permits Ollama on that one target — and is one
informational run inside the CI runner, not held to any bar and not re-driven.

The one `gpt-4o-mini` run that read REJECTED is an honest one, not a flaky
re-drive. Two facts, observed separately, with no causal claim between them:
the guarded side leaked nothing (0 of 3) but only 1 of 3 guarded runs resisted
outright, so 2 reached no verdict at all (`validate.log` names no cause for
those); and this same run's `scan.log` shows the effect probe's calibration
failing (`MYL-INC-003`). **The undecided-guarded-run pattern is not unique to
this run** — two of the three KEPT `gpt-4o-mini` runs on `server-memory` also
had exactly one guarded run reach no verdict (`guarded resisted 2/3, leaked
0/3`); only this one fell far enough (1 of 3 resisted) to fail the
differential leg's threshold. `validate`'s own text used to say the guard "did
not block" the attack on an undecided run, which overstated what "no verdict"
shows; the wording is fixed in
[PR #318](https://github.com/Abidemialade/mylonite/pull/318). The rejection
itself was always correct.

**`simple-streamablehttp` (W2 only — its one tool has no store-and-recall pair,
see the prereg's per-target notes) produced the same product defect on every
run, on both providers: no finding, no verdict, a confirmed bug, not a security
result.** The target declares an indirect-injection seed with no `seed_arm`
(by design, per the prereg), and `scan --allow-no-seed-arm` is meant to record
that as a clean skip. Instead the missing arm raises inside nested `asyncio`
task groups, which the scan's attempt classifier didn't unwrap, so the attempt
reads as an unclassified exception. The printed coverage summary still names
the right reason code (`MYL-NT-002`), so no scan read falsely clean — but the
per-attempt record carried no code of its own, so this page's own scorer
(which requires the code on the attempt, not just the summary line) counts the
run as a product defect. This was [issue #319](https://github.com/Abidemialade/mylonite/issues/319),
**closed**, fixed by [PR #322](https://github.com/Abidemialade/mylonite/pull/322)
(merged after the measured build).

## Targets 4–6: N=1 smoke cells (no verdict claimed)

Three targets, two providers each — six smoke cells. These prove connectivity
and non-crashing behaviour only, exactly as pre-registered — a KEPT or REJECTED
label was never on the table for any of them.

| Target | Provider | Result | Note |
| --- | --- | --- | --- |
| `server-everything` | Haiku 4.5 | PRODUCT_DEFECT | the target process itself crashed (Node `EPIPE`/`BrokenResourceError` on its own stdio transport) — the same unclassified-exception bug as issue #319 (closed, fixed by #322), a different cause: a target-side crash, not a missing seed arm |
| `server-everything` | gpt-4o-mini | clean resist | exercised, 0 findings, nothing unexplained |
| `go-sdk` memory example | Haiku 4.5 | finding, unvalidated | W4 fired on scan; effect-probe calibration failed (`MYL-INC-003`, `MYL-INC-006`), so under never-keep-unproven this is a candidate, never a verdict |
| `go-sdk` memory example | gpt-4o-mini | finding, unvalidated | same calibration failure (`MYL-INC-003`, `MYL-INC-006`) |
| OpenAI Agents SDK agent on Ollama | Haiku 4.5 | infrastructure, superseded; then product defect on re-run | see below |
| OpenAI Agents SDK agent on Ollama | gpt-4o-mini | infrastructure, superseded; then product defect on re-run | see below |

The Agents-SDK smoke cell hit two separate problems in sequence, on both
providers, of two different kinds. The first dispatch never reached Mylonite —
a harness/infrastructure failure, not a product defect: the agent shim's
`openai-agents` pin needs `openai>=3` while LiteLLM's own pin needs `openai<3`,
so installing both in one environment failed before any command ran ($0
spent). Per the prereg's amendment, that cell is scored INFRASTRUCTURE and was
re-dispatched, fixed by installing the shim in its own virtualenv
([PR #320](https://github.com/Abidemialade/mylonite/pull/320), merged). The
re-run reached the target and hit a real product bug there: the `rest`
adapter's request carried no JSON content-type header, the target agent
rejected it with HTTP 422, and the one attempt errored before any Mylonite LLM
call ($0 spent). Fixed by
[PR #321](https://github.com/Abidemialade/mylonite/pull/321) (merged after the
measured build).

## Harness issues, not product issues

Three problems were in the campaign's own workflow, not in Mylonite, and were
fixed at $0 spent (recorded as amendments in the prereg, before the affected
cells were re-dispatched):

- **An expired Anthropic CI key.** The first three counted Anthropic dispatches
  (targets 1–3) stopped at the key check before any target launched (HTTP 401).
  Rotated; cells re-dispatched on the same build.
- **A missing `--allow-no-seed-arm` flag for the streamable-HTTP target.**
  Target 3 declares W2 with no `seed_arm`; without the flag `scan` refuses the
  combination outright. Fixed in
  [PR #317](https://github.com/Abidemialade/mylonite/pull/317) (merged).
- **The agent-shim pip conflict**, described above. Fixed in
  [PR #320](https://github.com/Abidemialade/mylonite/pull/320) (merged); the
  two superseded cells are scored INFRASTRUCTURE in `results.json`, not
  PRODUCT_DEFECT.

## Spend

Counted-run totals, summed from each cell's own `cost.json` (excludes the
uncounted pilot dispatch the prereg records separately, which spent an
additional $0.02 on `gpt-4o-mini`):

| Provider | Calls | Cost |
| --- | --- | --- |
| Anthropic (`claude-haiku-4-5-20251001`) | 173 | **$0.91** |
| OpenAI (`gpt-4o-mini`) | 211 | **$0.08** |
| Ollama (`llama3.2:3b`, in-runner) | 26 | $0 |

Both are well inside the prereg's $4.50 / $5.00 allocation for this campaign.

## What this does not claim

- **No security verdict for `simple-streamablehttp`, `server-everything`,
  `go-sdk` memory, or the Agents-SDK target.** Every result on them is a
  product bug, an infrastructure failure, a smoke pass, or an unvalidated
  finding — never KEPT or REJECTED.
- **No KEPT or REJECTED run here rests on a confirmed state read-back.** See
  "Proof level" above — every one is `dispatched-tool-linked`, because the
  effect probe failed to calibrate on both targets.
- **The differential leg on `server-memory` and `mcp-redis` used Mylonite's
  synthetic boundary shim, not a server-side guard.** Neither target ships one
  to toggle. A KEPT result here proves the attack is real and that this class
  of guard closes it — it is not evidence about any specific deployment's own
  guard.
- **The `llama3.2:3b` cell is `server-memory` only, one run inside the CI
  runner, reported for information.** Nothing is claimed for `mcp-redis` on
  this model, and nothing ran "locally" — the prereg permits Ollama on
  `server-memory` alone, and the run happened inside the same CI runner as
  every other cell.
- **Both product bugs (issue #319 / PR #322, and PR #321) were fixed after the
  measured build.** The results above are for the measured build and are not
  re-scored. Neither bug produced a false-clean result: every affected run
  still printed the correct reason code to its console output, even where the
  per-attempt record and this page's scorer disagreed about whether that was
  enough to call the run NOT TESTED.

## Files here

- `results.json` — every cell's classification, weakness class, reason codes,
  LLM calls and cost, the proof level and calibration code for every
  server-memory/mcp-redis cell, plus the N=3 rollups, the two-bug product-issue
  list and the harness-amendment list. Sanitised: no local paths, hostnames or
  usernames.
- This `README.md`.

Raw per-run artefacts (`scan.log`, `validate.log`, `scan_report.json`,
`validation_report.json`) are retained as CI workflow artefacts, not committed
here — `results.json` is the durable record.
