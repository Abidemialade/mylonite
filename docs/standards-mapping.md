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
  operator's `control_config` declaration. The verdict goes further: a
  `readOnlyHint` alone never makes a call a read there, so it can never turn a
  call that went through into "resisted". It needs your
  `control_config.verdict_read_tools` entry, a read verb in the tool's name, or
  a calibrated effect probe certified through that tool (see
  [Reading results](reading-results.md)). When a calibrated effect probe sees a
  write after an attempt whose only consequential call went to a tool annotated
  `readOnlyHint: true`, the log records an **annotation/behaviour mismatch**, a
  defect in the target, not a classification problem to route around.

## How tagging works

A `ComplianceMapper` (one of the five extension points) walks a confirmed
`ExploitRecord` and emits a `ComplianceTags` object with lists of IDs across
the four frameworks. The bundled mapper consults the taxonomy and derives related
tags (for example, a NIST AI RMF function from the OWASP class); a custom mapper can
replace it via the plugin entry point.

**This is Mylonite's own mapping, hand-assigned — not a mapping the standards
bodies themselves publish.** Treat every tag as our judgment of where a finding
sits, not as certification. Two different provenance paths, and neither is a
published crosswalk:

- **OWASP LLM / OWASP ASI / MITRE ATLAS IDs are hand-assigned per seed**, in
  code (`src/mylonite/scan/seeds.py`) and in
  [`reference_targets/mcp_kitchen_sink/seeds/seeds.yaml`](https://github.com/Abidemialade/mylonite/blob/main/reference_targets/mcp_kitchen_sink/seeds/seeds.yaml).
  Each seed's author picked the closest-fitting ID at the time it was written.
- **NIST AI RMF tags are derived, not assigned.** Each bundled NIST entry
  lists the OWASP IDs it relates to, and a finding inherits every NIST entry
  that references one of its own OWASP tags
  (`src/mylonite/taxonomy/compliance.py`). The NIST text itself is NIST's own;
  the link from a NIST subcategory to an OWASP ID is Mylonite's crosswalk, not
  one NIST publishes.

## Weakness class to standards IDs

The four weakness classes Mylonite tests ([W1–W4](weakness-classes.md)) carry
a fixed set of IDs, consistent across every bundled target family. Where a
class has several seeds, the row lists every ID any of them carries; a single
finding carries only its own seed's IDs:

| Class | OWASP LLM | OWASP ASI | MITRE ATLAS |
|---|---|---|---|
| W1 — tool-description instruction smuggling | LLM01 | ASI02 | AML.T0051 |
| W2 — indirect prompt injection via ingested data | LLM01, LLM05 | ASI01, ASI06 | AML.T0051 |
| W3 — excessive egress / SSRF | LLM06 | ASI02, ASI05 | AML.T0049 |
| W4 — excessive agency / unconfirmed consequential action | LLM06 | ASI02 | **none** |

**W4 has no ATLAS technique assigned.** No MITRE ATLAS technique in the
bundled `v2026.05` catalogue cleanly matches "an agent dispatched a
consequential action without confirmation" — rather than force a loose fit,
the mapper leaves it untagged. A W4 finding's NIST tags are still derived from
its OWASP IDs as usual.

## Coverage is partial, by design

Across every bundled seed, only **3 of the 10** OWASP LLM Top 10 entries
(LLM01, LLM05, LLM06) and **4 of the 10** OWASP ASI Top 10 entries (ASI01,
ASI02, ASI05, ASI06) are ever emitted, and only **2** MITRE ATLAS techniques
(AML.T0049, AML.T0051) appear at all. That's not a gap in the taxonomy loaders
— all ten entries of each framework, and the full ATLAS catalogue, are bundled
and queryable (see [Auto-generated mapping tables](#auto-generated-mapping-tables)
below) — it's a direct reflection of what the attack library currently tests:
four weakness classes, not ten OWASP categories. A report or SARIF upload
listing "LLM01, LLM05, LLM06" is not a claim that Mylonite checked LLM02–LLM04
or LLM07–LLM10; it only has evidence for the classes it attacked. Don't market
or report compliance coverage beyond what a specific run's tags actually say.

## Auto-generated mapping tables

Auto-generated cross-reference tables (every OWASP LLM entry → matching OWASP ASI /
MITRE ATLAS / NIST entries) are a planned addition. Today you can hand-query the
bundled taxonomy via the loaders in the table above:

```python
from mylonite import taxonomy

for entry in taxonomy.load_owasp_llm():
    print(entry.id, entry.name, entry.source_url)
```
