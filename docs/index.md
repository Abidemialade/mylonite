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

!!! info "Status: Phase 1.5"
    The exploit-finding scan loop works today: `mylonite scan` runs against
    the bundled Quarry reference twins and real MCP stdio servers
    (filesystem / fetch / github), and `mylonite demo` shows the
    vulnerable-vs-guarded differential offline with no API key. The test
    generator and differential-oracle validation engine are Phase 2, in
    progress. See [the changelog](https://github.com/Abidemialade/mylonite/blob/main/CHANGELOG.md).

## Where to go next

- [Quickstart](quickstart.md) — install + the commands that work today.
- [The Quarry](quarry.md) — a 60-second offline demo against a deliberately
  vulnerable reference agent, and the bridge to scanning a real MCP server.
- [Concepts](concepts.md) — the AI-attack-surface scope and the
  differential-oracle moat, in plain English.
- [Plugin authoring](plugin-authoring.md) — the five extension contracts.
- [Standards mapping](standards-mapping.md) — OWASP LLM / OWASP ASI / MITRE
  ATLAS / NIST AI RMF.
- [Security](security.md) — responsible-use and dual-use policy.
