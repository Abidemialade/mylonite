"""Taxonomy loader sanity checks.

These tests don't make network calls (``source_url`` reachability is a smoke
check left to humans); they verify that every bundled data file loads, that
cross-references resolve, and that source URLs come from an allowlist of
canonical publishers.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from mylonite.taxonomy import (
    load_atlas,
    load_atlas_tactics,
    load_atlas_techniques,
    load_nist_ai_rmf,
    load_owasp_asi,
    load_owasp_llm,
)

ALLOWED_HOSTS = {
    "genai.owasp.org",
    "atlas.mitre.org",
    "airc.nist.gov",
    "www.nist.gov",
}


def test_owasp_llm_loads_ten_entries() -> None:
    entries = load_owasp_llm()
    assert len(entries) == 10
    assert {e.id for e in entries} == {f"LLM{i:02d}" for i in range(1, 11)}


def test_owasp_asi_loads_ten_entries() -> None:
    entries = load_owasp_asi()
    assert len(entries) == 10
    assert {e.id for e in entries} == {f"ASI{i:02d}" for i in range(1, 11)}


def test_atlas_tactics_match_upstream_count() -> None:
    # Upstream MITRE ATLAS v2026.05 publishes 16 tactics.
    assert len(load_atlas_tactics()) == 16


def test_atlas_techniques_loaded() -> None:
    techniques = load_atlas_techniques()
    assert len(techniques) > 0
    assert any(t.sub_technique_of is not None for t in techniques)


def test_atlas_alias() -> None:
    assert load_atlas() == load_atlas_techniques()


def test_nist_subcategories_have_known_function() -> None:
    entries = load_nist_ai_rmf()
    assert len(entries) >= 15
    assert {e.function for e in entries} <= {"GOVERN", "MAP", "MEASURE", "MANAGE"}


@pytest.mark.parametrize(
    "loader",
    [load_owasp_llm, load_owasp_asi, load_atlas_tactics, load_atlas_techniques, load_nist_ai_rmf],
)
def test_source_urls_are_canonical(loader: object) -> None:
    for entry in loader():  # type: ignore[operator]
        host = urlparse(entry.source_url).hostname or ""
        assert host in ALLOWED_HOSTS, f"unexpected source host {host!r} in {entry.id}"


def test_asi_references_resolve_to_owasp_llm() -> None:
    llm_ids = {e.id for e in load_owasp_llm()}
    for asi in load_owasp_asi():
        for ref in asi.references:
            if ref.framework == "owasp-llm":
                assert ref.id in llm_ids, f"{asi.id} references unknown LLM id {ref.id}"
