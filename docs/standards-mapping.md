# Standards mapping

Every confirmed exploit produced by Mylonite carries metadata identifying
its position in four major frameworks. The mapping is near-free at
generation time and is the foundation of the compliance / audit-evidence
packs that ship in Phase 6.

## Frameworks

| Framework             | Bundled version | Loader                                                                                          |
| --------------------- | --------------- | ----------------------------------------------------------------------------------------------- |
| OWASP LLM Top 10      | 2025            | [`mylonite.taxonomy.load_owasp_llm`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)        |
| OWASP Agentic (ASI)   | 2026            | [`mylonite.taxonomy.load_owasp_asi`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)        |
| MITRE ATLAS           | `v2026.05`      | [`mylonite.taxonomy.load_atlas`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)            |
| NIST AI RMF           | AI RMF 1.0      | [`mylonite.taxonomy.load_nist_ai_rmf`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/loader.py)      |

Provenance of each data file is documented in
[`src/mylonite/taxonomy/data/SOURCE.md`](https://github.com/Abidemialade/mylonite/blob/main/src/mylonite/taxonomy/data/SOURCE.md).

## How tagging will work

A `ComplianceMapper` (one of the five extension points) walks a confirmed
`ExploitRecord` and emits a `ComplianceTags` object with lists of IDs across
the four frameworks. The reference mapper that ships in v0.1.0 is a
naive pass-through; real mappers consult the bundled taxonomy and infer
related tags from the attack pattern.

## Auto-generated mapping tables

The auto-generated cross-reference tables (every OWASP LLM entry → matching
OWASP ASI / MITRE ATLAS / NIST entries) land in **Phase 5** of
[`ROADMAP.md`](https://github.com/Abidemialade/mylonite/blob/main/ROADMAP.md). For
v0.1.0 you can hand-query via the CLI:

```bash
mylonite taxonomy list --framework owasp-llm
mylonite taxonomy list --framework owasp-asi
mylonite taxonomy list --framework atlas
mylonite taxonomy list --framework nist
```
