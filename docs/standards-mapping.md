# Standards mapping

Every confirmed exploit produced by Mylonite carries metadata identifying
its position in four major frameworks. The mapping is near-free at
generation time and is the foundation for compliance and audit-evidence
reporting.

## Frameworks

| Framework             | Bundled version | Loader                                                                                          |
| --------------------- | --------------- | ----------------------------------------------------------------------------------------------- |
| OWASP LLM Top 10      | 2025            | [`mylonite.taxonomy.load_owasp_llm`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)        |
| OWASP Agentic (ASI)   | 2026            | [`mylonite.taxonomy.load_owasp_asi`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)        |
| MITRE ATLAS           | `v2026.05`      | [`mylonite.taxonomy.load_atlas`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)            |
| NIST AI RMF           | AI RMF 1.0      | [`mylonite.taxonomy.load_nist_ai_rmf`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)      |

Provenance of each data file is documented in
[`src/mylonite/taxonomy/data/SOURCE.md`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/data/SOURCE.md).

## Standards the controls themselves follow

The four frameworks above are what findings are *tagged* with. Two further
standards shape how the boundary controls **behave** — worth stating plainly,
because a control that cites a standard should implement it.

| Standard | Where it is used | What we take from it |
| --- | --- | --- |
| [FIDES](https://arxiv.org/abs/2505.23643) (Costa et al.; ships in Microsoft Agent Framework as [`agent_framework.security`](https://learn.microsoft.com/en-us/agent-framework/agents/security)) | `InformationFlowControl` (W2), `ConfirmGateControl` (W4) | Two independent label axes (`integrity`, `confidentiality`), most-restrictive-wins propagation, per-sink `accepts_untrusted` / `max_allowed_confidentiality` policies, and the three enforcement modes (`observe` / `approve` / `block`) |
| [MCP tool annotations](https://modelcontextprotocol.io/) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) | Tool classification for every control | The protocol's own risk vocabulary, read as **tier-1 classification evidence** ahead of name heuristics |

Two deliberate deviations, so the claim stays accurate:

- **FIDES labels each content item and propagates per item**; Mylonite tracks a
  single accumulated session label. Coarser — and FIDES documents the same
  most-restrictive-wins conservatism as a known limitation of its own model.
  FIDES's variable indirection and `quarantined_llm` are not implemented.
- **MCP annotations are hints from a possibly-untrusted server**, and the spec
  says so explicitly. They therefore inform classification but never outrank an
  operator's `control_config` declaration. A tool annotated `readOnlyHint: true`
  that is then observed writing is reported as an **annotation/behaviour
  mismatch** — a defect in the target, not a classification problem to route
  around.

## How tagging works

A `ComplianceMapper` (one of the five extension points) walks a confirmed
`ExploitRecord` and emits a `ComplianceTags` object with lists of IDs across
the four frameworks. The bundled mapper consults the taxonomy and derives related
tags (for example, a NIST AI RMF function from the OWASP class); a custom mapper can
replace it via the plugin entry point.

## Auto-generated mapping tables

Auto-generated cross-reference tables (every OWASP LLM entry → matching OWASP ASI /
MITRE ATLAS / NIST entries) are a planned addition. Today you can hand-query the
bundled taxonomy via the loaders in the table above:

```python
from mylonite import taxonomy

for entry in taxonomy.load_owasp_llm():
    print(entry.id, entry.name, entry.source_url)
```
