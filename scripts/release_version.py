"""Pure, read-only helpers for reasoning about a release's version metadata.

Imported by :mod:`scripts.prepare_release` (the CLI), by ``tests/test_changelog.py``,
and by the ``gate`` job in ``.github/workflows/release.yml``. One parser feeding all
three is the point: it is what stops the test and the release gate from drifting
apart and disagreeing about whether a release is well-formed.

Two deliberate constraints:

* **Standard library only.** The release gate runs before anything is built or
  installed, so it must work on a bare ``actions/setup-python`` with no
  ``pip install``. ``tomllib`` is 3.11+, which matches ``requires-python``.
* **No writes, no ``subprocess``, no network.** Every function here is a pure
  function of file contents. Mutation lives in ``prepare_release.py``, behind a
  single ``--check`` guard, so a verification run can never dirty the tree.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/Abidemialade/mylonite"

TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")
VERSION_RE = re.compile(r"^__version__\s*=\s*[\"'](?P<version>[^\"']+)[\"']", re.M)
HEADER_RE = re.compile(
    r"^## \[(?P<version>\d+\.\d+\.\d+)\] - (?P<date>\d{4}-\d{2}-\d{2})\s*$", re.M
)
UNRELEASED_RE = re.compile(r"^## \[Unreleased\]\s*$", re.M)
LINKREF_RE = re.compile(r"^\[(?P<key>[^\]]+)\]:\s*(?P<url>\S+)\s*$", re.M)

#: Documented in CHANGELOG.md as released, but never tagged and never published.
#:
#: 0.6.0's release commit (529ff26) is on ``main`` but was never tagged; 0.7.1 and
#: 0.7.2 were squash-merged into the commit that ``v0.7.3`` tags, so their own
#: commits are unreachable. All three describe work that genuinely shipped, so the
#: sections stay -- deleting them would make the CHANGELOG lie about the past. What
#: must never happen is a link-ref pointing at a ``vX.Y.Z`` tag for one of these:
#: those tags do not exist, and creating one now would match ``release.yml``'s
#: trigger and publish a two-month-old build to PyPI.
KNOWN_UNTAGGED = frozenset({"0.6.0", "0.7.1", "0.7.2"})


def version_module_path(root: Path = ROOT) -> Path:
    return root / "src" / "mylonite" / "version.py"


def package_version(root: Path = ROOT) -> str:
    """``__version__`` as declared in ``src/mylonite/version.py``.

    Read by regex rather than by importing the module: the release gate runs
    without the package installed.
    """
    text = version_module_path(root).read_text(encoding="utf-8")
    match = VERSION_RE.search(text)
    if match is None:  # pragma: no cover - only reachable if version.py is mangled
        raise ValueError(f"no __version__ assignment found in {version_module_path(root)}")
    return match.group("version")


def _pyproject(root: Path = ROOT) -> dict[str, object]:
    with (root / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def pyproject_static_version(root: Path = ROOT) -> str | None:
    """``[project].version``, or ``None`` when the version is declared dynamic."""
    project = _pyproject(root).get("project", {})
    assert isinstance(project, dict)
    version = project.get("version")
    return version if isinstance(version, str) else None


def pyproject_dynamic_fields(root: Path = ROOT) -> list[str]:
    project = _pyproject(root).get("project", {})
    assert isinstance(project, dict)
    dynamic = project.get("dynamic", [])
    return [str(item) for item in dynamic] if isinstance(dynamic, list) else []


def hatch_version_path(root: Path = ROOT) -> str | None:
    """``[tool.hatch.version].path`` -- where hatchling reads the version from."""
    tool = _pyproject(root).get("tool", {})
    if not isinstance(tool, dict):
        return None
    hatch = tool.get("hatch", {})
    if not isinstance(hatch, dict):
        return None
    version = hatch.get("version", {})
    if not isinstance(version, dict):
        return None
    path = version.get("path")
    return path if isinstance(path, str) else None


def changelog_path(root: Path = ROOT) -> Path:
    return root / "CHANGELOG.md"


def changelog_versions(text: str) -> list[tuple[str, str]]:
    """``(version, date)`` for every dated release header, in file order."""
    return [(m.group("version"), m.group("date")) for m in HEADER_RE.finditer(text)]


def link_refs(text: str) -> dict[str, str]:
    """Markdown link-reference definitions, keyed by their bracket label."""
    return {m.group("key"): m.group("url") for m in LINKREF_RE.finditer(text)}


def section_body(text: str, version: str) -> str | None:
    """The body of ``## [version] - DATE``, up to the next ``## [`` header.

    Returns ``None`` when no such header exists. An existing-but-blank section
    returns the whitespace it contains, so callers can distinguish "absent" from
    "present but empty" -- the release gate has to reject both, but for different
    reasons and with different messages.
    """
    start = None
    for match in HEADER_RE.finditer(text):
        if match.group("version") == version:
            start = match.end()
            break
    if start is None:
        return None
    following = re.compile(r"^## \[", re.M).search(text, start)
    return text[start : following.start()] if following else text[start:]


def has_content(body: str | None) -> bool:
    """True when ``body`` holds at least one non-blank line.

    ``release.yml`` used ``[ ! -s release-notes.md ]``, which a whitespace-only
    section passes -- producing a GitHub Release with an empty body. This is that
    check, done properly and moved to before the irreversible PyPI upload.
    """
    return body is not None and any(line.strip() for line in body.splitlines())


def compare_url(previous: str, version: str) -> str:
    return f"{REPO_URL}/compare/v{previous}...v{version}"


def unreleased_url(version: str) -> str:
    return f"{REPO_URL}/compare/v{version}...HEAD"


def tag_for(version: str, prefix: str = "v") -> str:
    return f"{prefix}{version}"


def version_from_tag(tag: str, prefix: str = "v") -> str | None:
    """The ``X.Y.Z`` inside a tag, or ``None`` if it isn't a well-formed release tag.

    Prereleases are deliberately rejected: ``release.yml`` publishes straight to
    PyPI, and the old glob ``v[1-9]*.*.*`` matched ``v1.0.0rc1`` by accident.
    """
    if prefix != "v":
        if not tag.startswith(prefix):
            return None
        tag = "v" + tag[len(prefix) :]
    match = TAG_RE.match(tag)
    return match.group("version") if match else None
