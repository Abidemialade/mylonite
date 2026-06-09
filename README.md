# Mylonite

> Point it at your AI agent; it finds a real weakness and writes the
> regression test that closes it forever — in your repo, gating your CI.

[![CI](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Abidemialade/mylonite/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mylonite.svg)](https://pypi.org/project/mylonite/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/mylonite.svg)](https://pypi.org/project/mylonite/)

Mylonite is an open-source framework for **AI-layer security testing**. It
targets the AI/agentic part of an application — the system prompt, tools,
RAG pipeline, agent planner — and emits **validated regression tests** that
gate CI. It deliberately does *not* test the surrounding traditional code;
that work belongs to SAST/DAST tools.

The full product thesis, market positioning, and phased build plan live in
[PLAN.md](./PLAN.md).

> **Status:** v0.1.0 — Phase 0 foundations only. The exploit-finding agent,
> test generator, and validation engine arrive in v0.2+. See
> [CHANGELOG.md](./CHANGELOG.md) and the
> [issue tracker](https://github.com/Abidemialade/mylonite/issues) for what
> is and isn't implemented today.

## Magic-moment quickstart *(planned for v0.2)*

```bash
pip install mylonite
mylonite scan ./my-agent --authorize ./my-agent
# → finds an AI-layer weakness
# → writes test_security_<id>.py
# → validates via the differential oracle
# → opens a PR with a gating GitHub Action
```

The `scan` command is a stub in v0.1.0. The commands that *do* work today:

```bash
mylonite version
mylonite taxonomy list --framework owasp-llm
mylonite taxonomy list --framework owasp-asi
mylonite taxonomy list --framework atlas
mylonite taxonomy list --framework nist
```

## What's in v0.1.0

- **Versioned extension contracts** — five Python Protocols for attack
  modules, target adapters, test generators, validators, and compliance
  mappers. Plugins register via standard PyPI entry points.
- **Threat-taxonomy module** — OWASP LLM Top 10 (2025), OWASP Agentic
  Security Initiative (2026), MITRE ATLAS (v5.4.0), and NIST AI RMF, all as
  data files with provenance.
- **Deliberately-vulnerable reference MCP agent** — under
  `reference_targets/mcp_kitchen_sink/`, used as ground truth for the
  differential-oracle validation engine that lands in Phase 2. **Loopback
  only by default**; see its own README before running.
- **OSS scaffolding** — Apache-2.0, contributor docs, CI, pre-commit,
  Dependabot, dual-use security policy.

## Documentation

- [PLAN.md](./PLAN.md) — full product spec and build plan.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — dev setup, how to author a plugin.
- [GOVERNANCE.md](./GOVERNANCE.md) — decision-making, registry acceptance.
- [SECURITY.md](./SECURITY.md) — responsible-disclosure + dual-use policy.
- Docs site (mkdocs-material): `mkdocs serve` from a checkout. Hosted docs
  land with the Phase 4 launch.

## Responsible use

Mylonite reproduces working weaknesses in AI agents. **Use it only against
targets you control or are contractually authorized to test.** The CLI
refuses to run without an explicit `--authorize` flag naming the target.
The bundled vulnerable reference agent binds to loopback only.

Full policy: [SECURITY.md](./SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
