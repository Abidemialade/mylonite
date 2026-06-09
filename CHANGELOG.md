# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-09

### Added

- Apache-2.0 LICENSE + NOTICE.
- README with magic-moment quickstart placeholder (v0.2 preview).
- CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1), GOVERNANCE, SECURITY.
- `.github/` issue templates (bug, attack-pattern submission, adapter request),
  PR template, CODEOWNERS, Dependabot config, CI workflow (ruff / mypy / pytest
  on Python 3.11 / 3.12 / 3.13).
- `pyproject.toml` (hatchling, PEP 621), `.pre-commit-config.yaml`.
- `mylonite` Typer CLI with `version` and `taxonomy list` commands; placeholder
  stubs for `scan` / `generate` / `validate` / `init`.
- Pydantic `Settings` config schema (`mylonite.config`) — LLM provider is
  required, no default.
- Five versioned extension-point contracts under `src/mylonite/contracts/`:
  attack module, target adapter, test generator, validator, compliance mapper.
  Each ships a Protocol, a runtime-checkable ABC, and a `CONTRACT_VERSION`.
- JSON schemas mirroring the contract Pydantic models, under
  `src/mylonite/schemas/`; regenerator script under `scripts/`.
- Threat-taxonomy module (`src/mylonite/taxonomy/`) with data files for OWASP
  LLM Top 10 2025, OWASP Agentic Security Initiative 2026, MITRE ATLAS
  v5.4.0 (pinned to upstream commit), and NIST AI RMF subcategories relevant
  to red-team evidence.
- Plugin entry-point registry with major-version compatibility checks; one
  reference implementation per contract.
- Deliberately-vulnerable reference MCP agent under
  `reference_targets/mcp_kitchen_sink/`, in vulnerable and guarded variants,
  for use as differential-oracle ground truth in Phase 2.
- mkdocs-material docs scaffold.

[Unreleased]: https://github.com/Abidemialade/mylonite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Abidemialade/mylonite/releases/tag/v0.1.0
