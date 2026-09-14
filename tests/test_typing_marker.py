"""The `Typing :: Typed` classifier must be backed by a real `py.typed` marker.

Issue #133. `pyproject.toml` has advertised `Typing :: Typed` since the first
release while shipping no marker file, so PEP 561 consumers got no inline types
from the installed package: mypy reports
`Skipping analyzing "mylonite.…": module is installed, but missing library stubs
or py.typed marker` and silently falls back to `Any` for every symbol the
package exposes — including the five extension contracts that are public API.

The classifier is a promise to downstream type checkers, and it was false.
"""

from __future__ import annotations

import importlib.resources as ir
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_the_marker_file_exists_in_the_package() -> None:
    marker = Path(__file__).resolve().parent.parent / "src" / "mylonite" / "py.typed"
    assert marker.is_file(), (
        "src/mylonite/py.typed is missing. Without it, PEP 561 says a type "
        "checker must ignore this package's inline annotations entirely."
    )


def test_the_marker_is_resolvable_as_package_data() -> None:
    """Resolved the way a consumer's type checker finds it — through the package,
    not through a source-tree path. A marker that exists in the repo but is not
    part of the installed package keeps the promise broken."""
    assert (ir.files("mylonite") / "py.typed").is_file()


def test_the_marker_is_empty() -> None:
    """PEP 561 defines `py.typed` as a marker; only the `partial\\n` form carries
    meaning, and this package is fully annotated (`mypy src` is a CI gate). An
    accidental payload here would be silently ignored by some checkers and
    treated as a stub-package declaration by others."""
    marker = Path(__file__).resolve().parent.parent / "src" / "mylonite" / "py.typed"
    assert marker.read_text(encoding="utf-8") == ""


def test_the_classifier_and_the_marker_agree() -> None:
    """Either both or neither. This is the assertion that would have caught the
    original defect: the classifier was added and the marker never was."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    classifiers = data["project"]["classifiers"]
    marker = Path(__file__).resolve().parent.parent / "src" / "mylonite" / "py.typed"

    assert ("Typing :: Typed" in classifiers) == marker.is_file(), (
        "pyproject.toml's `Typing :: Typed` classifier and src/mylonite/py.typed "
        "must be added and removed together — the classifier alone is a promise "
        "to downstream type checkers that the missing marker breaks."
    )
