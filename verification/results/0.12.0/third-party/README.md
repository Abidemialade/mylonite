# Third-party verification — October 2026 campaign

Mylonite's unmodified `scan`, `generate` and `validate` commands ran against six
MCP and agent systems Mylonite had never touched before, with every LLM call made
live in CI. On two of the six, Mylonite kept a reproducible W4 finding (an
unconfirmed consequential change, caught and confirmed through the target's own
state) across three independent re-drives, on every provider tried, including a
3B model running locally at zero cost. The campaign also surfaced three real
product bugs, logged as GitHub issues.

This directory is the committed, machine-readable record for that run. Read
[`verification/PREREG_THIRD_PARTY_2026_10.md`](../../PREREG_THIRD_PARTY_2026_10.md)
first — it is the rule this page is scored against, committed before any counted
run so the result could not shape it.

**Build measured:** `d150c742` (installed as a wheel, outside the checkout, the
same pattern `verification-campaign.yml` uses).
**Models:** `anthropic/claude-haiku-4-5-20251001`, `openai/gpt-4o-mini`, and one
cell on `ollama_chat/llama3.2:3b` running in the CI runner at zero cost.

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
target and was confirmed through the target's own read-back, reproducibly, on
every provider tried.** The differential leg ran against Mylonite's synthetic
boundary shim (neither target ships a server-side guard to toggle), the same
caveat every synthetic-boundary result in `CAPABILITY_MATRIX.md` carries: this
proves the attack is real and that this class of guard closes it, not that any
specific deployment's own guard does.

The one `gpt-4o-mini` run that read REJECTED is an honest one, not a flaky
re-drive: the guarded side leaked nothing (0 of 3), but the effect probe's
calibration failed (`MYL-INC-003`), so 2 of the 3 guarded runs reached no
verdict at all — `validate`'s own text used to say the guard "did not block"
the attack, which overstated what an undecided run shows. The wording is fixed
in [PR #318](https://github.com/Abidemialade/mylonite/pull/318); the rejection
itself was always correct.

**`simple-streamablehttp` (W2 only — its one tool has no store-and-recall pair,
see the prereg's per-target notes) produced the same product defect on every
run, on both providers: no finding, no verdict, a confirmed bug, not a security
result.** The target declares an indirect-injection seed with no `seed_arm`
(by design, per the prereg), and `scan --allow-no-seed-arm` is meant to record
that as a clean skip. Instead the missing arm raises inside nested `asyncio`
task groups, which the scan's attempt classifier doesn't unwrap, so the attempt
reads as an unclassified `planner_exception`. The printed coverage summary still
names the right reason code (`MYL-NT-002`), so no scan read falsely clean — but
the per-attempt record carries no code of its own, so this page's own scorer
(which requires the code on the attempt, not just the summary line) counts the
run as a product defect. Logged as
[issue #319](https://github.com/Abidemialade/mylonite/issues/319), open at the
time of this write-up.

## Targets 4–6: N=1 smoke cells (no verdict claimed)

These prove connectivity and non-crashing behaviour only, exactly as
pre-registered — a KEPT or REJECTED label was never on the table for them.

| Target | Provider | Result | Note |
| --- | --- | --- | --- |
| `server-everything` | Haiku 4.5 | PRODUCT_DEFECT | target crashed mid-attempt (Node `EPIPE`/`BrokenResourceError` on its own stdio transport); surfaced as an unclassified `planner_exception`, same root cause as issue #319 |
| `server-everything` | gpt-4o-mini | clean resist | exercised, 0 findings, nothing unexplained |
| `go-sdk` memory example | Haiku 4.5 | finding, unvalidated | W4 fired on scan; effect-probe calibration failed (`MYL-INC-003`, `MYL-INC-006`), so under never-keep-unproven this is a candidate, never a verdict |
| `go-sdk` memory example | gpt-4o-mini | finding, unvalidated | same calibration failure (`MYL-INC-003`, `MYL-INC-006`) |
| OpenAI Agents SDK agent on Ollama | Haiku 4.5 | product defect, two causes | see below |
| OpenAI Agents SDK agent on Ollama | gpt-4o-mini | product defect, two causes | see below |

The Agents-SDK smoke cell hit two separate problems in sequence, on both
providers. The first dispatch never reached Mylonite: the agent shim's
`openai-agents` pin needs `openai>=3` while LiteLLM's own pin needs `openai<3`,
so installing both in one environment failed before any command ran ($0
spent). Fixed by installing the shim in its own virtualenv
([PR #320](https://github.com/Abidemialade/mylonite/pull/320), merged). The
re-run reached the target and failed there instead: the `rest` adapter's
request carried no JSON content-type header, the target agent rejected it with
HTTP 422, and the one attempt errored before any Mylonite LLM call ($0 spent).
A fix is open as
[PR #321](https://github.com/Abidemialade/mylonite/pull/321), not yet merged
at the time of this write-up.

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
  [PR #320](https://github.com/Abidemialade/mylonite/pull/320) (merged).

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
  product bug, a smoke pass, or an unvalidated finding — never KEPT or
  REJECTED.
- **The differential leg on `server-memory` and `mcp-redis` used Mylonite's
  synthetic boundary shim, not a server-side guard.** Neither target ships one
  to toggle. A KEPT result here proves the attack is real and that this class
  of guard closes it — it is not evidence about any specific deployment's own
  guard.
- **The Ollama cell on `server-memory` is one run, reported for information.**
  It is not held to the N=3 bar and is not re-driven.
- **Issues #319 and #321 are open, not fixed, as of this write-up.** Neither
  defect produced a false-clean result: every affected run still printed the
  correct reason code to its console output, even where the per-attempt record
  and this page's scorer disagreed about whether that was enough to call the
  run NOT TESTED.

## Files here

- `results.json` — every cell's classification, weakness class, reason codes,
  LLM calls and cost, plus the N=3 rollups, the product-issue list and the
  harness-amendment list. Sanitised: no local paths, hostnames or usernames.
- This `README.md`.

Raw per-run artefacts (`scan.log`, `validate.log`, `scan_report.json`,
`validation_report.json`) are retained as CI workflow artefacts, not committed
here — `results.json` is the durable record.
