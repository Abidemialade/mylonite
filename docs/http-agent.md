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
the [MCP transports](test-your-app.md); if it can report a side effect over HTTP,
declare an `effect_probe`.

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
family: my-http-agent
transport: rest
weakness_classes: [W2]
request:
  url: https://my-agent.internal/v1/chat
  method: POST                       # default POST
  headers:                           # optional; carry auth here — never logged
    Authorization: Bearer ${MY_TOKEN}
  body: '{"messages": [{"role": "user", "content": "{prompt}"}]}'
  response_path: choices.0.message.content
```

- **`url`** — the endpoint Mylonite posts to.
- **`body`** — the request body template. The `{prompt}` placeholder is where the
  attack payload is substituted. The payload is JSON-escaped, so a JSON body stays
  valid. `{prompt}` is required.
- **`response_path`** — a dotted path into the JSON response to pull out the
  agent's reply (list indices are numbers, e.g. `choices.0.message.content`). Omit
  it to judge the whole response body.
- **`headers`** — optional auth; values are never written to any log, report, or
  test artifact.

## Run it

```bash
mylonite scan --target-file my-http-agent.yaml --authorize my-http-agent
```

`--authorize` is mandatory, as for every real target: you assert you own or are
authorized to test it (see the [responsible-use policy](security.md)). From there
the flow is the same as any target — `generate` emits the regression test,
`validate` proves it, `gate` opens the PR:

```bash
mylonite gate --target-file my-http-agent.yaml --authorize my-http-agent
```

## Notes

- **Control-efficacy on a black box.** The control-efficacy differential needs a way
  to toggle a safeguard, and a black box exposes none — so `validate`/`gate`
  **automatically** decide `kept` by stability + effect + consensus for a `rest`
  target (a finding is never falsely rejected for lack of a differential).
- **Test an input defence: `--prove-input-control`.** Opt into an **input
  data-framing ("spotlighting")** differential — Mylonite drives the same attack
  raw and again wrapped as untrusted data, and `kept` then means that input framing
  **is load-bearing** for this attack on your agent. It's the black-box analogue of
  the untrusted-data envelope; use it to check whether a realistic input guard would
  defend you.
- **Server-side differential.** To toggle a *server-side* guard instead, declare
  `vulnerable_launch` / `control_env` (see [Concepts](concepts.md)) so Mylonite can
  run the endpoint with its guard on and off.
- **Scope.** This is still AI-layer testing — it exercises the agent's prompt
  handling, not the surrounding HTTP service. Traditional endpoint security belongs
  to DAST tools.
