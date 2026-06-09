# Threat-taxonomy data — provenance

Every data file in this directory is sourced from a canonical upstream
publisher. If you refresh one, update both its `framework_version` field and
the relevant row below.

| File                                 | Upstream                                                                                     | Pinned version  | Retrieved   | License      |
| ------------------------------------ | -------------------------------------------------------------------------------------------- | --------------- | ----------- | ------------ |
| `owasp_llm_top10_2025.yaml`          | OWASP GenAI Security Project — LLM Top 10 (<https://genai.owasp.org/llm-top-10/>)            | 2025            | 2026-06-08  | CC BY-SA 4.0 |
| `owasp_asi_2026.yaml`                | OWASP Agentic Security Initiative — Top 10 for Agentic Applications 2026                     | 2026 (Dec 2025) | 2026-06-08  | CC BY-SA 4.0 |
| `mitre_atlas_tactics.yaml`           | `mitre-atlas/atlas-data` release `v2026.05`                                                  | 2026.05         | 2026-06-08  | Apache-2.0   |
| `mitre_atlas_techniques.yaml`        | `mitre-atlas/atlas-data` release `v2026.05`                                                  | 2026.05         | 2026-06-08  | Apache-2.0   |
| `nist_ai_rmf.yaml`                   | NIST AI 100-1 (AI RMF 1.0) + NIST AI 600-1 (GenAI Profile)                                   | AI RMF 1.0      | 2026-06-08  | Public domain |

## OWASP LLM Top 10 (2025)

- Canonical landing page: <https://genai.owasp.org/llm-top-10/>
- Each entry's `source_url` points at the per-risk page on the OWASP GenAI
  site.
- Descriptions are paraphrased one-sentence summaries of the published
  entries; the canonical wording is the OWASP page.

## OWASP Agentic Security Initiative — Top 10 for Agentic Applications 2026

- Released: 2025-12-09 by the OWASP GenAI Security Project.
- Canonical page: <https://genai.owasp.org>
- Cross-references to OWASP LLM Top 10 (2025) are encoded in each entry's
  `references` list.

## MITRE ATLAS

- Upstream: <https://github.com/mitre-atlas/atlas-data>
- Pinned release: `v2026.05` (modified-date `2026-05-27`).
- The upstream YAML is converted into Mylonite's two-file split (tactics +
  techniques) via a one-shot script. To refresh:

  1. Download the latest `ATLAS-<version>.yaml` release asset.
  2. Run the converter (kept out of the committed tree; see commit history).
  3. Update the `framework_version` field on each entry and this README's row.
  4. Smoke-test by loading via `mylonite.taxonomy.load_atlas`.
- `ROADMAP.md` cites ATLAS `v5.4.0`; the upstream renamed to date-based
  versioning. `v2026.05` is the current canonical release as of retrieval.

## NIST AI RMF

- Anchor doc: NIST AI 100-1 "AI Risk Management Framework (AI RMF 1.0),"
  January 2023.
- Generative-AI profile: NIST AI 600-1 "Artificial Intelligence Risk
  Management Framework: Generative Artificial Intelligence Profile,"
  July 2024.
- The bundled subset (~20 subcategories) is the entries most directly
  produced as evidence by adversarial-testing tools. The full ~70-entry
  catalogue lands in Phase 5 when the audit-evidence pack work begins.
- Source URLs point at the NIST AI RMF Playbook entries:
  <https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook>.
