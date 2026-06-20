# Mylonite

> Point it at your AI agent; it finds a real weakness and writes the
> regression test that closes it forever — in your repo, gating your CI.

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — system prompt, tools, RAG
pipeline, agent planner — and emits **validated regression tests** that gate
CI. It deliberately does *not* test the surrounding traditional code; that
work belongs to SAST/DAST tools.

The phased build plan lives in
[`ROADMAP.md`](https://github.com/Abidemialade/mylonite/blob/main/ROADMAP.md).

!!! success "Status: the full pipeline works"
    `scan` → `generate` → `validate` → `gate` runs end to end against the bundled
    Quarry twins and your own MCP app (`--target-file`). Findings are proven by the
    [differential oracle](validation.md), emitted as committed pytest regression tests,
    and surfaced as a gating PR, [SARIF](reading-results.md), or a JSON bundle. Recent
    depth: stateful [memory poisoning](attack-modes.md#memory-poisoning), tool-chaining
    synthesis, control-efficacy ablation, and [cross-model durability](validation.md#cross-model-durability).
    See [the changelog](https://github.com/Abidemialade/mylonite/blob/main/CHANGELOG.md).

## Where to go next

- [Quickstart](quickstart.md) — install and the magic moment in a few commands.
- [Try it — the Quarry](quarry.md) — a 60-second offline demo against a deliberately
  vulnerable reference agent.
- [Test your own app](test-your-app.md) — point Mylonite at your MCP server.
- [Weakness classes](weakness-classes.md) — what's tested and how an attack is proven.
- [Attack modes](attack-modes.md) — single-shot, adaptive, tool-chaining, memory poisoning.
- [The validation engine](validation.md) — the differential oracle (the moat).
- [CLI reference](cli-reference.md) · [Architecture](architecture.md) · [Plugin authoring](plugin-authoring.md).
- [Standards mapping](standards-mapping.md) — OWASP LLM / OWASP ASI / MITRE
  ATLAS / NIST AI RMF.
- [Security](security.md) — responsible-use and dual-use policy.
