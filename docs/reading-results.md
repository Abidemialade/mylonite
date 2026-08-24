# Reading the results

A finding is only useful if a human (or a pipeline) can act on it. Mylonite renders
every scan and validation in the format you actually consume — from a terminal trust
panel to GitHub code scanning to a machine-readable bundle — all from the same
underlying data, all offline (no LLM, no network).

The one command for all of it is `mylonite report`, pointed at a scan dir, a
`generate`-emitted dir (before or after `validate` — both write into the same
dir), or a `*_report.json`.

```bash
mylonite report .mylonite/scans/<dir>                 # terminal trust panel
mylonite report <dir> --sarif out.sarif               # GitHub code scanning
mylonite report <dir> --json finding.json             # dashboards / SIEM / bots
```

## The terminal trust panel

The default. For a scan it shows the findings, coverage per weakness class, and any
**NOT TESTED** gap (an attack pattern that couldn't be delivered — surfaced loudly, never silently
counted as clean). For a validation it shows the verdict and the evidence behind it:

```
leg          result   metric  detail
build        pass      -      offline pass with fixtures
differential pass     1.00    vulnerable fired, guarded resisted
flakiness    pass     1.00    reproducibility 5/5 vulnerable, 5/5 guarded
metamorphic  pass     0.86    robustness (6/7 perturbations held; gates kept)
gate: kept = build ✓ AND differential ✓ AND flakiness ✓ AND metamorphic ✓  =>  KEPT
reproducibility: vulnerable fired 5/5, guarded resisted 5/5
mutation score: 7/8   |   compliance: OWASP-LLM LLM01 · OWASP-ASI ASI01 · NIST MEASURE-2.7
```

That panel is the **anti-false-positive trust signal**: ~46% of security alerts are
false positives, so a finding that ships with a machine-checkable differential proof
("fired 5/5, resisted 5/5") is worth far more than one that just asserts a problem.

## SARIF 2.1.0 — `--sarif` (GitHub code scanning)

SARIF is the portal to where developers already triage every other finding — the
GitHub **Security tab** and PR checks. `--sarif` writes a SARIF 2.1.0 document where
each result carries:

- a **severity** (`security-severity` + level) GitHub uses to bucket the finding,
- the **compliance tags** (OWASP-LLM/ASI · MITRE ATLAS · NIST),
- the **differential proof** in the message ("fired N/N on the vulnerable target,
  resisted M/M with the control — the safeguard, not the model, carries the security"),
- a **location** — a `logicalLocation` pinning the implicated tool/field (a remote MCP
  tool has no source line, so the honest unit is the tool + field), plus a real
  prompt-file line when the AI layer is a committed file.

```bash
mylonite report .mylonite/generated/<dir> --sarif mylonite.sarif
# then upload via github/codeql-action/upload-sarif in CI
```

## JSON finding bundle — `--json`

For everything that isn't GitHub/pytest — dashboards, SIEM, Slack bots, custom CI.
A single `finding.json` (versioned `schema_version`) with, per finding: `pattern_id`,
`weakness_class`, `severity`, `attack_shape`, the full `compliance` block, the R4
`localization` (tool/field/line), the `proof` (vuln/guard counts + `kept`), and the
`proven_control`. It reuses the exact data the SARIF report computes — no new
analysis. Source: `mylonite.report.bundle`.

## The gating PR

When you run [`gate`](ci-gating.md), the PR body is itself a result surface:

- **What was found** — the validated weakness, compliance tags, attack tier.
- **The differential proof** — the fires/resists numbers and the kept formula, so the
  reviewer sees *why the test is trustworthy*, not just that it exists.
- **Located at** — the exact locus to fix: which tool's *description* smuggled the
  instruction, which tool's *returned content* was trusted, which action *handler* fired
  without a guard, or which *system-prompt line* is at fault. Derived deterministically
  from the finding (`mylonite.gate.localize`).
- **The proven fix** — an evidence-anchored recommendation naming the actual tool and
  argument that landed the exploit (your own tool, for a `--target-file` app; the
  reference app's tool, for the bundled `reference:*` targets), as a fenced **code
  sketch** (never a diff — Mylonite doesn't assert it knows your file layout), tiered
  deterministic/probabilistic/detective (`mylonite.gate.recommend`). Framed as a
  **Proven fix** for a control-efficacy finding, a **Recommended fix** otherwise.
- **Inline annotations** — with `--open-pr`, a finding that maps to a committed prompt
  line also posts a best-effort GitHub check-run annotation on that line.

## Compliance metadata (everywhere)

Every emitted artefact — exploit JSON, validation report, SARIF, JSON bundle, PR
body — carries the compliance mapping for the finding: **OWASP LLM Top 10 (2025)**,
**OWASP ASI (2026)**, **MITRE ATLAS** technique IDs, and a **NIST AI RMF** function tag.
This is near-free at generation time and is the foundation of audit/compliance reporting
— see [Standards mapping](standards-mapping.md).

## Exit codes (for CI)

| Code | Meaning |
|------|---------|
| 0 | success / the test is kept |
| 2 | config or usage error (incl. an empty scan — never reads as a clean pass) |
| 3 | LLM-call budget exceeded |
| 4 | provider unreachable |
| 5 | the generated test was rejected (not kept) |

A clean exit `0` means the run actually happened — an aborted or empty scan exits
non-zero so a misconfiguration can never masquerade as "all clear".
