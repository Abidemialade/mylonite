"""CHANGELOG.md structural invariants.

These run on every PR, which is the point: the release gate in
``.github/workflows/release.yml`` only fires on a pushed tag, so without these a
CHANGELOG defect is discovered at release time. The last assertion in particular
catches the exact 0.7.6/0.7.7 failure -- version bumped, CHANGELOG not updated --
while it is still a pull request.

Deliberately offline: no ``git tag`` shelling out. CI's test jobs check out at
``fetch-depth: 1``, which fetches no tags at all, so a git-backed test would see
an empty tag list and fail every version. The set of versions that have no tag is
closed and small, so it is encoded directly as ``KNOWN_UNTAGGED`` -- the same
explicit-allowlist shape ``tests/test_layout.py`` uses for its own exceptions.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from release_version import (  # noqa: E402
    KNOWN_UNTAGGED,
    changelog_path,
    changelog_versions,
    has_content,
    link_refs,
    package_version,
    section_body,
)

CHANGELOG = changelog_path().read_text(encoding="utf-8")
VERSIONS = [version for version, _ in changelog_versions(CHANGELOG)]
REFS = link_refs(CHANGELOG)


def test_every_release_header_has_a_link_reference() -> None:
    """A header with no matching ``[x]:`` renders as literal bracketed text."""
    missing = [version for version in VERSIONS if version not in REFS]
    assert not missing, f"CHANGELOG headers with no link-reference definition: {missing}"


def test_unreleased_has_a_link_reference() -> None:
    assert "Unreleased" in REFS, "CHANGELOG.md has no '[Unreleased]:' link-reference definition"


def test_no_orphan_link_references() -> None:
    """Every definition points at a section that exists."""
    orphans = [key for key in REFS if key != "Unreleased" and key not in VERSIONS]
    assert not orphans, f"link-reference definitions with no matching header: {orphans}"


def test_no_link_reference_points_at_a_tag_that_does_not_exist() -> None:
    """0.6.0 / 0.7.1 / 0.7.2 shipped but were never tagged.

    Pointing a link at ``v0.6.0`` is not just a 404 -- that tag matches
    ``release.yml``'s trigger, so creating one to satisfy the link would publish a
    months-old build to PyPI. These three must resolve to a commit or to the tag
    that actually contains them.
    """
    dangling = [
        (key, url)
        for key, url in REFS.items()
        for untagged in KNOWN_UNTAGGED
        if f"v{untagged}" in url
    ]
    assert not dangling, (
        f"link-references pointing at a tag that does not and will not exist: {dangling}"
    )


def test_current_package_version_has_a_changelog_section() -> None:
    """The 0.7.6/0.7.7 failure mode, caught at PR time rather than at tag time."""
    version = package_version()
    assert version in VERSIONS or _is_unreleased(version), (
        f"version.py declares {version!r} but CHANGELOG.md has no section for it "
        "and it is not the pending [Unreleased] work"
    )


def _is_unreleased(version: str) -> bool:
    """True when ``version`` is the last *released* one, i.e. work is pending.

    Between releases ``version.py`` still names the previous release while new
    entries accumulate under ``[Unreleased]``. That is the normal steady state, so
    it must not fail -- what must fail is a version naming nothing at all.
    """
    return bool(VERSIONS) and version == VERSIONS[0]


def test_released_sections_are_not_empty() -> None:
    """An empty section would publish a GitHub Release with a blank body."""
    empty = [v for v in VERSIONS if not has_content(section_body(CHANGELOG, v))]
    assert not empty, f"CHANGELOG sections with no content: {empty}"
