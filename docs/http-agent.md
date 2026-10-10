# Test a plain HTTP agent (no MCP)

Most guides here assume your app speaks MCP. Many agents don't — they're a plain
HTTP endpoint that takes a prompt and returns a reply. The `rest` transport points
Mylonite at any such endpoint. You describe the request shape once in a
`target.yaml`; you change **nothing** in the app under test.

## What you get (and what you don't)

A plain HTTP agent is a black box: Mylonite can send it a prompt and read the
reply, but it can't see a tool surface or the agent's internal actions. So the
`rest` transport tests the **prompt-injection / goal-hijack** class (`W2`), judged
on the reply: given a message with an embedded, unauthorized instruction, does the
agent obey it or treat it as untrusted data?

It does **not** test tool-description poisoning (`W1`) or effect-based egress /
consequential-action findings (`W3`/`W4`) — those need a tool surface or a
side-effect probe a black box can't provide. If your agent exposes tools, prefer
the [MCP transports](test-your-app.md): an `effect_probe` that confirms a side effect
works there. A `rest` target file that declares an `effect_probe` is refused on load
with exit `2`, before any model call, because Mylonite has no way to read the app's
state over a plain HTTP reply.

## Scaffold it in one command

You don't have to hand-write the target file. Point `--scaffold` at your endpoint and it
writes a **runnable** `target.yaml` (no MCP server to introspect, so it's ready as-is):

```bash
mylonite scan --scaffold my-agent.yaml \
  --rest-url https://my-agent.internal/v1/chat \
  --rest-response-path choices.0.message.content
```

Then edit the request block if needed (auth headers, body shape) and scan it. Or write the
file by hand:

## The target file

```yaml
family: my-agent
transport: rest
weakness_classes: [W2]
request:
  url: https://my-agent.internal/v1/chat
  method: POST                       # default POST
  headers:                           # optional; carry auth here — never logged
    Authorization: Bearer ${MY_TOKEN}
  body: '{"messages": [{"role": "user", "content": "{prompt}"}]}'
  response_path: choices.0.message.content
  timeout_s: 30                      # optional; default 30 (see below)
```

- **`url`** — the endpoint Mylonite posts to.
- **`body`** — the request body template. The `{prompt}` placeholder is where the
  attack payload is substituted. The payload is JSON-escaped, so a JSON body stays
  valid. `{prompt}` is required.
- **`response_path`** — a dotted path into the JSON response to pull out the
  agent's reply (list indices are numbers, e.g. `choices.0.message.content`). Omit
  it to judge the whole response body.
- **`headers`** — optional auth; values are never written to any log, report, or
  test artifact. Each `${VAR}` here prints one line naming the variable and the host
  it is sent to (`target file sends $MY_TOKEN to my-agent.internal`). Mylonite's own
  credentials, such as a provider key, `MYLONITE_API_KEY` or `GH_TOKEN`, are refused
  here; copy the value into your own name first (`export MY_TOKEN="$GH_TOKEN"`). See
  [Remote targets](target-file.md#remote-targets-sse-http). When the body is JSON and
  you set no `Content-Type`, Mylonite sends `Content-Type: application/json`; a
  `Content-Type` you set always wins.
- **`timeout_s`** — the HTTP client timeout for every call to the agent, in
  seconds. Defaults to **30**. A local-model agent often takes longer than 30s per
  turn; raise this if a scan fails with a timeout. The error names `request.timeout_s`
  and its current value, so you know which field to raise.

## Run it

```bash
mylonite scan --target-file my-agent.yaml --authorize my-agent
```

`--authorize` is mandatory, as for every real target: you assert you own or are
authorized to test it (see the [responsible-use policy](security.md)). From there
the flow is the same as any target — `generate` emits the regression test,
`validate` checks it, `gate` opens the PR:

```bash
mylonite gate --target-file my-agent.yaml --authorize my-agent
```

## Notes

- **What a kept test proves on a black box.** The HTTP adapter sees only the agent's
  reply: it records no tool calls and runs no effect probe. So every finding on a
  `rest` target is decided by the LLM judge, and its
  [evidence tier](reading-results.md#evidence-tier) is `judge-only`. `validate` and
  `gate` decide `kept` by stability and consensus, and a kept test is capped at
  **STABLE, NOT PROVEN** ("black-box target: the LLM judge is the only evidence"). It
  never reads KEPT, even when the input-framing differential below passes. `validate`
  still writes the test, which gates reproduction only; `gate` lists the finding as a
  candidate and never commits it (see [CI gating](ci-gating.md#exit-codes)).
- **Test an input defence: `--prove-input-control`.** Opt into an **input
  data-framing ("spotlighting")** differential — Mylonite drives the same attack
  raw and again wrapped as untrusted data, and `kept` then means that input framing
  **is load-bearing** for this attack on your agent (the label still reads STABLE,
  NOT PROVEN, because the judge decided each run). It's the black-box analogue of
  the untrusted-data envelope; use it to check whether a realistic input guard would
  defend you.
- **The structural recommendation.** Because a `rest` target has no tool surface to
  key a fix to, `gate`/`report` prescribe what generalises to any HTTP agent instead:
  input framing (structured, labelled messages instead of string-concatenating the
  user's message into the system prompt — the `--prove-input-control` differential
  above measures exactly this), collapsed authorization (propagate the caller's own
  identity downstream instead of one shared service credential for the whole agent —
  the highest-value REST finding), and endpoint-boundary enforcement (an explicit
  allowlist of upstream endpoints/actions the wrapper may invoke, since there is no
  tool boundary to attach one to).
- **Server-side differential.** To toggle a *server-side* guard instead, declare
  `vulnerable_launch` / `control_env` (see [Concepts](concepts.md)) so Mylonite can
  run the endpoint with its guard on and off.
- **Scope.** This is still AI-layer testing — it exercises the agent's prompt
  handling, not the surrounding HTTP service. Traditional endpoint security belongs
  to DAST tools.
