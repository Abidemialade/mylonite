# `mcp_kitchen_sink` — deliberately-insecure reference MCP agent

**a.k.a. "the reference app"** — Mylonite's built-in proving ground. The reference app,
the `mcp-kitchen-sink` pip package, and the `reference:vulnerable` /
`reference:guarded` scan targets are all the **same artifact** under three
names. The canonical walkthrough is [`docs/quarry.md`](../../docs/quarry.md).

> ⚠️ **This package is intentionally insecure research scaffolding.** It exists
> as ground truth for Mylonite's differential-oracle validation engine
> (see `ROADMAP.md` Phases 0–2). **Do not expose it to anything but loopback.**
> Both server variants refuse to bind to non-loopback interfaces by default.
> See `mylonite/SECURITY.md` for the project's dual-use policy.
>
> **The reference app is a deliberately vulnerable in-process reference
> agent. It never binds to a network. Never point Mylonite at a system you
> don't own or operate** (see SECURITY.md).

## What this is

A small agentic application with four tools — `read_note`, `write_note`,
`web_fetch`, `send_email` — shipped in two variants:

- **`server_vulnerable`**: Seeded weaknesses across three categories that
  Phase 1 of Mylonite's exploit-finding agent will discover:
  - Indirect prompt injection — tool results are inlined into the planner's
    context with no quarantine wrapper.
  - Tool poisoning — tool descriptions carry text that the planner happily
    treats as instruction.
  - Excessive agency — `web_fetch` has no allow-list; `send_email` fires
    without confirmation.
- **`server_guarded`**: Same tool surface, hardened. Untrusted content goes
  through an `<untrusted>` quarantine envelope; tool descriptions pass a
  character allowlist; `web_fetch` is restricted; `send_email` requires a
  separate `confirm_send` step.

A thin LiteLLM-backed planner (`planner.py`) sits in front of either server
and is used as "the agent under attack" in the validation tests. Two planner
variants mirror the server variants so the differential oracle has a clean
vulnerable-vs-guarded matchup.

## The four seeded weaknesses

The full catalogue (loci, summaries) is in
[`seeds/seeds.yaml`](seeds/seeds.yaml); the attack patterns that exercise each
weakness live in `src/mylonite/scan/seeds.py`. The scenario-by-scenario
walkthrough is [`docs/quarry.md`](../../docs/quarry.md).

| W  | Name                                    | OWASP LLM    | OWASP ASI    | MITRE ATLAS | Guard (in `server_guarded`)                       |
|----|-----------------------------------------|--------------|--------------|-------------|---------------------------------------------------|
| W1 | tool-description-instruction-smuggling | LLM01        | ASI02        | AML.T0051   | description allowlist + parenthetical refusal     |
| W2 | indirect-injection-via-note-body       | LLM01, LLM05 | ASI01, ASI06 | AML.T0051   | `read_note` wraps bodies in `<untrusted>`         |
| W3 | unrestricted-web-fetch                 | LLM06        | ASI02, ASI05 | AML.T0049   | `web_fetch` hostname allowlist                    |
| W4 | unconfirmed-email-send                 | LLM06        | ASI02        | —           | two-step send: `send_email` + `confirm_send`      |

## Try it

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
mylonite scan reference:vulnerable
mylonite scan reference:guarded
```

Runs Mylonite's real scan pipeline against both builds of the reference app and
finds the weaknesses above on the vulnerable build, none on the guarded one —
that vulnerable-vs-guarded gap is the differential oracle in action. See
[`docs/quarry.md`](../../docs/quarry.md) for the full walkthrough and the
follow-on `mylonite scan`/`generate`/`validate` flows.

## How to run

```bash
# from the repo root — two editable installs:
pip install -e ".[dev]"
pip install -e ./reference_targets/mcp_kitchen_sink

python -m mcp_kitchen_sink.server_vulnerable    # vulnerable, loopback only
python -m mcp_kitchen_sink.server_guarded       # hardened, loopback only
```

Both servers exit immediately if the configured bind address is not
loopback (`127.0.0.1` / `::1`).

## Real MCP stdio server (custom-target on-ramp)

`server_vulnerable.py`/`server_guarded.py` above are in-process server
*classes* only — programmatic use from tests, or `mylonite scan`'s built-in
`reference:vulnerable`/`reference:guarded` targets. To drive this same tool
surface through mylonite's generic `--target-file` custom-target flow
(`scan`/`ablate`/`validate`/`gate`) — the same code path a real third-party
MCP app goes through — use the real stdio-speaking wrappers instead:

```bash
pip install -e "./reference_targets/mcp_kitchen_sink[mcp]"   # needs the mcp SDK

mcp-kitchen-sink-vulnerable   # console script, or:
python -m mcp_kitchen_sink.stdio_vulnerable

mcp-kitchen-sink-guarded      # / python -m mcp_kitchen_sink.stdio_guarded
```

Each speaks real MCP over stdin/stdout until the peer closes the pipe —
exactly what a `target.yaml`'s `command`/`args` spawn. `examples/target.yaml`
at the repo root is a ready-to-use target file pointed at the vulnerable
variant:

```bash
mylonite scan --target-file examples/target.yaml --authorize kitchen-sink
```

See `tests/integration/test_custom_target_offline.py` for an offline
(scripted-LLM) test that spawns this real subprocess end-to-end.

## Seeds

`seeds/` contains a small bank of failure-mode descriptions used by the
forthcoming security-mutation-score check in Phase 2. Each seed pairs a
specific weakness in the vulnerable server with a guard in the guarded
server and is tagged with OWASP LLM / OWASP ASI / MITRE ATLAS IDs.

## Tests

`tests/` proves the basic differential ground truth:

1. A canned indirect-injection payload against `server_vulnerable` makes the
   planner act on the injected instruction.
2. The same payload against `server_guarded` is refused.

These two tests are the contract that Phase 2's validation pipeline
mechanises.

## License

Apache-2.0, same as the parent project. See `LICENSE` at the repo root.
