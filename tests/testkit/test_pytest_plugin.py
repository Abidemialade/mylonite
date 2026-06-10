"""Tests for the bundled pytest11 plugin's marker registry.

Covers the ATLAS / NIST marker namespaces added alongside the existing OWASP
set: that the frozensets are built from the bundled taxonomy, that the shared
``_marker_name`` sanitiser produces the names the generator emits, and that the
namespaces don't collide with the OWASP set.
"""

from __future__ import annotations

from mylonite.testkit._pytest_plugin import (
    REGISTERED_ATLAS_MARKERS,
    REGISTERED_NIST_MARKERS,
    REGISTERED_OWASP_MARKERS,
    _marker_name,
)


def test_marker_name_sanitises_taxonomy_ids() -> None:
    """Non-alphanumeric chars collapse to ``_``; the whole name lowercases."""
    assert _marker_name("atlas", "AML.T0051") == "atlas_aml_t0051"
    assert _marker_name("nist", "MEASURE-2.6") == "nist_measure_2_6"


def test_atlas_markers_built_from_bundled_taxonomy() -> None:
    """The ATLAS frozenset is non-empty and contains the sanitised W2 technique."""
    assert "atlas_aml_t0051" in REGISTERED_ATLAS_MARKERS
    assert len(REGISTERED_ATLAS_MARKERS) > 0
    assert all(name.startswith("atlas_") for name in REGISTERED_ATLAS_MARKERS)


def test_nist_markers_built_from_bundled_taxonomy() -> None:
    """The NIST frozenset is non-empty and consistently namespaced."""
    assert len(REGISTERED_NIST_MARKERS) > 0
    assert all(name.startswith("nist_") for name in REGISTERED_NIST_MARKERS)


def test_marker_namespaces_are_disjoint() -> None:
    """OWASP / ATLAS / NIST marker namespaces must not overlap."""
    assert REGISTERED_OWASP_MARKERS.isdisjoint(REGISTERED_ATLAS_MARKERS)
    assert REGISTERED_OWASP_MARKERS.isdisjoint(REGISTERED_NIST_MARKERS)
    assert REGISTERED_ATLAS_MARKERS.isdisjoint(REGISTERED_NIST_MARKERS)
