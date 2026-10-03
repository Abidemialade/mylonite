# 3. Point at your app

If your agent exposes its tools over MCP (a local stdio server, or a remote
one with a static token), this is the on-ramp. No MCP? Use the
[`rest` transport](../http-agent.md) instead and skip to its own scaffold
command — everything from step 4 on works the same way once you have a
`target.yaml`.

**Free: no model call, no attack, no `--authorize` needed.**

```bash
mylonite scan --command "python" --arg "my_server.py" --scaffold app.yaml --scope my-app
```

This launches your server once, lists its tools, and writes a commented
`target.yaml` starter: which weakness classes look reachable (from your
tools' names, descriptions and schemas — a hint to confirm, not a verdict), a
`seed_arm` (how to plant untrusted content), and a proposed `effect_probe`
(how to confirm damage landed) where it can see a plausible readback tool.
Without one, the classes that need it read **NOT TESTED, effect
unconfirmable**, with the reason stated — see [the full target.yaml
reference](../target-file.md) for every field it fills in and
[Test your own app](../test-your-app.md) for the end-to-end walkthrough this
page summarises.

## What the 10-minute bar counts, and what it doesn't

The stated first-proof target ([journey overview](index.md#the-bar-this-is-measured-against))
starts the clock here, not at step 1. It covers this scaffold step plus
[Find](4-find.md) against a server that's already running and reachable —
it does not count time spent getting your own server to start at all (a
database to seed, credentials to obtain, a slow cold boot). If your server
needs that kind of setup, do it before timing yourself against the bar.

## Next

[4. Find](4-find.md) — the first step that spends a model call.
