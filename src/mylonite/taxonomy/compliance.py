"""Derive cross-framework compliance tags from the bundled taxonomy.

The seeds carry OWASP LLM / ASI / MITRE tags; NIST AI RMF is derived here from
the bundled taxonomy's cross-references (single source of truth — no per-seed
NIST tagging to drift). Used by the reference compliance mapper.
"""

from __future__ import annotations

from mylonite.contracts._types import ComplianceTags
from mylonite.taxonomy.loader import load_nist_ai_rmf


def enrich_with_nist(tags: ComplianceTags) -> ComplianceTags:
    """Add the NIST AI RMF ids cross-referenced by the finding's OWASP LLM/ASI tags.

    Returns ``tags`` unchanged when nothing new is derivable (so it is a no-op on
    a finding with no OWASP tags, and idempotent).
    """
    owasp = set(tags.owasp_llm) | set(tags.owasp_asi)
    if not owasp:
        return tags
    derived = set(tags.nist_ai_rmf)
    for entry in load_nist_ai_rmf():
        for ref in entry.references:
            if ref.framework in ("owasp-llm", "owasp-asi") and ref.id in owasp:
                derived.add(entry.id)
    if derived == set(tags.nist_ai_rmf):
        return tags
    return tags.model_copy(update={"nist_ai_rmf": sorted(derived)})
