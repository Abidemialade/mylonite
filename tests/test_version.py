"""Version sanity check."""

from __future__ import annotations

import tomllib
from pathlib import Path

import mylonite


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    assert mylonite.__version__ == data["project"]["version"]
