# Mylonite

> Point it at your AI agent; it finds a real weakness and writes the
> regression test that closes it forever — in your repo, gating your CI.

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — system prompt, tools, RAG
pipeline, agent planner — and emits **validated regression tests** that gate
CI. It deliberately does *not* test the surrounding traditional code; that
work belongs to SAST/DAST tools.

The full product thesis lives in
[`PLAN.md`](https://github.com/Abidemialade/mylonite/blob/main/PLAN.md).

!!! warning "Status: v0.1.0 (Phase 0)"
    Only the foundations are in place: contracts, threat taxonomy, the
    deliberately-vulnerable reference MCP agent, and OSS scaffolding. The
    exploit-finding agent, test generator, and validation engine arrive in
    v0.2+. See [the changelog](https://github.com/Abidemialade/mylonite/blob/main/CHANGELOG.md).

## Where to go next

- [Quickstart](quickstart.md) — install + the commands that work today.
- [Concepts](concepts.md) — the AI-attack-surface scope and the
  differential-oracle moat, in plain English.
- [Plugin authoring](plugin-authoring.md) — the five extension contracts.
- [Standards mapping](standards-mapping.md) — OWASP LLM / OWASP ASI / MITRE
  ATLAS / NIST AI RMF.
- [Security](security.md) — responsible-use and dual-use policy.
