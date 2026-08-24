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
