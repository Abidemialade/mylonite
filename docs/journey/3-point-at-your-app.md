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

`--arg` is repeatable, in order, for a server that takes more than one
argument.

**Exit codes.** `--scaffold` exits `0` once it writes the file, `2` on any
config/usage error — a missing `--command`, an `app.yaml` that already
exists without `--force`, or a server that fails to launch or speak MCP.
There's no `3`/`4` here: scaffold makes no LLM call, so there's no budget or
provider to exceed.

The [first-proof bar](index.md#the-bar-this-is-measured-against) starts
counting here, against a server that's already running — not against the
time it takes your own server to start (a database to seed, a slow cold
boot).

## Two worked examples

No server of your own handy yet? Point the same command at either of these
— both are real, independently runnable MCP servers, not Mylonite's own
reference app.

**The official MCP memory server** (`@modelcontextprotocol/server-memory`,
Node — needs [Node.js](https://nodejs.org/) installed so `npx` is on your
`PATH`). It keeps a knowledge graph and stores whatever it's told to; no
install step beyond Node, since `npx` fetches the package on first run. The
two blocks below are the same command for two different shells, not two
different setups — use whichever shell you're actually typing into: the bash
block for a bash/zsh/Git-Bash/WSL/Linux/macOS shell (Git Bash provides a
writable `/tmp` even on Windows), the PowerShell block only if you're
invoking `mylonite` straight from PowerShell or `cmd.exe`:

```bash
mylonite scan --command npx --arg "-y" --arg "@modelcontextprotocol/server-memory" \
  --env "MEMORY_FILE_PATH=/tmp/mylonite-memory.json" \
  --scaffold app.yaml --scope server-memory
```

```powershell
mylonite scan --command npx --arg "-y" --arg "@modelcontextprotocol/server-memory" `
  --env "MEMORY_FILE_PATH=$env:TEMP\mylonite-memory.json" `
  --scaffold app.yaml --scope server-memory
```

The first `npx -y` run downloads the package before the server can answer at
all, which can take longer than this launch's 120-second default budget on a
slow or fresh machine. Either pre-fetch it once yourself —
`npm install -g @modelcontextprotocol/server-memory`, or just
`npx -y @modelcontextprotocol/server-memory` and let it exit on its own — or
raise the budget with the `MYLONITE_MCP_STARTUP_TIMEOUT_S` env var (seconds;
see [target-file.md](../target-file.md#mcp-session-timeout)). Either way,
every later launch reuses the cached package and is fast.

**Mylonite's own reference app** (`mcp-kitchen-sink`, Python — the deliberately
vulnerable target [step 1](1-try.md) replays; this launches it as a real
stdio subprocess instead). Install its `mcp` extra from PyPI, then point at
the console script it ships — no arguments needed, same command on both
platforms:

```bash
pip install "mcp-kitchen-sink[mcp]"
mylonite scan --command mcp-kitchen-sink-vulnerable --scaffold app.yaml --scope kitchen-sink
```

```powershell
pip install "mcp-kitchen-sink[mcp]"
mylonite scan --command mcp-kitchen-sink-vulnerable --scaffold app.yaml --scope kitchen-sink
```

Either way, `--authorize` on every later step must equal the `--scope` value
you scaffolded with (`server-memory` or `kitchen-sink` above).

## Next

[4. Find](4-find.md) — the first step that spends a model call.
