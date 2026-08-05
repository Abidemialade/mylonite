# Mylonite

> **Model robustness is not the same as application security.** A frontier model can resist
> every generic prompt-injection and still hand an attacker a win, because the hole is in
> your app's design, not the model's alignment. Mylonite tests whether your **app-layer
> controls** are stopping the attack, writes a **validated** regression test for each
> weakness, and gates CI so a model upgrade can't silently strip the protection away.

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — system prompt, tools, RAG
pipeline, agent memory — and emits **validated regression tests** that gate
CI. It deliberately does *not* test the surrounding traditional code; that
work belongs to SAST/DAST tools.

The phased build plan lives in
[`ROADMAP.md`](https://github.com/Abidemialade/mylonite/blob/main/ROADMAP.md).

!!! success "Status: the full pipeline works"
    `scan` → `generate` → `validate` → `gate` runs end to end against the bundled reference
    app and your own MCP (Model Context Protocol) app (`--target-file`). Findings are proven by the
    [control-efficacy check](validation.md) (the two-build differential on the reference
    app), emitted as committed pytest regression tests, and surfaced as a gating PR,
    [SARIF](reading-results.md), or a JSON bundle. Every claim is checked by an
    [independent verification harness](verification.md). The surface is deliberately
    narrow — every shipped feature runs on an MCP app you didn't author and is on a path
    to third-party proof. See [the changelog](https://github.com/Abidemialade/mylonite/blob/main/CHANGELOG.md).

!!! quote "Example: same model, two app versions"
    The *same* model, two versions of the bundled app: against the vulnerable version
    Mylonite catches a `send_email` dispatched with no approval step (a pure app-design
    flaw); against the guarded version it finds nothing. The app's design decides — see the
    full [independent scorecard](verification.md), negatives included.

## Where to go next

- [Quickstart](quickstart.md) — install and run the end-to-end pipeline in a few commands.
- [Try it — the reference app](quarry.md) — a 60-second offline demo against a deliberately
  vulnerable reference agent.
- [Test your own app](test-your-app.md) — point Mylonite at your MCP server.
- [Weakness classes](weakness-classes.md) — what's tested and how an attack is proven.
- [Attack modes](attack-modes.md) — the single-shot W1–W4 attack engine.
- [The validation engine](validation.md) — the control-efficacy check and the differential.
- [Independent verification](verification.md) — the honest scorecard against ground truth Mylonite didn't author.
- [CLI reference](cli-reference.md) · [Architecture](architecture.md) · [Plugin authoring](plugin-authoring.md).
- [Standards mapping](standards-mapping.md) — OWASP LLM / OWASP ASI / MITRE
  ATLAS / NIST AI RMF.
- [Security](security.md) — responsible-use and dual-use policy.
