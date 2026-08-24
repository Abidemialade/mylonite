"""Version wiring sanity check.

This used to assert that ``pyproject.toml``'s static ``version`` matched
``mylonite.__version__`` -- a reconciliation between two hand-maintained copies.
The version is now hatch-dynamic and read from ``src/mylonite/version.py``, so
that class of drift is structurally impossible rather than merely detected.

What is still worth pinning is the wiring itself: a well-meaning "let's just put
the version back in pyproject.toml" would silently restore the two-copy problem,
and the build would keep working, so nothing else would notice.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import mylonite

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_pyproject_declares_the_version_dynamically() -> None:
    project = _pyproject()["project"]
    assert "version" in project.get("dynamic", []), (
        'pyproject.toml must declare dynamic = ["version"]'
    )
    assert "version" not in project, (
        "pyproject.toml declares a static [project].version again -- that reintroduces "
        "the two-copy drift that hatch-dynamic versioning removed"
    )


def test_hatch_reads_the_version_from_the_version_module() -> None:
    path = _pyproject()["tool"]["hatch"]["version"]["path"]
    assert path == "src/mylonite/version.py"
    assert (ROOT / path).is_file()


def test_runtime_version_is_a_release_string() -> None:
    """What the CLI prints and what every artefact stamps."""
    parts = mylonite.__version__.split(".")
    assert len(parts) == 3 and all(part.isdigit() for part in parts), (
        f"__version__ {mylonite.__version__!r} is not X.Y.Z"
    )
