"""The public ``contracts`` facade is complete, and stays the import path.

Guards issue #89: ``ScanReport``/``ScanAttempt``/``AbortReason``/
``ScanAttemptOutcome`` were absent from ``mylonite.contracts.__all__``, so
consumers imported the private ``contracts._types`` module -- the de facto path.
These tests fail if a previously-exported type disappears from the facade, or if
a module outside the ``contracts`` package imports from ``contracts._types``.
"""

from __future__ import annotations

import re
from pathlib import Path

import mylonite.contracts as facade
from mylonite.contracts import _types

_SRC = Path(__file__).resolve().parents[2] / "src" / "mylonite"

_PRIVATE_TYPES_IMPORT = re.compile(r"from mylonite\.contracts\._types import", re.MULTILINE)

# The four that were missing and drove consumers onto the private module.
_PREVIOUSLY_MISSING = ("ScanReport", "ScanAttempt", "AbortReason", "ScanAttemptOutcome")


def test_facade_exports_the_previously_missing_types() -> None:
    for name in _PREVIOUSLY_MISSING:
        assert name in facade.__all__, name
        assert getattr(facade, name) is getattr(_types, name), name


def test_no_module_outside_contracts_imports_the_private_types_module() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        # Inside the contracts package, importing _types directly is correct: the
        # facade itself re-exports from it, and the ABC modules use it to avoid a
        # self-import cycle.
        if path.parent.name == "contracts" or path.parent.parent.name == "contracts":
            continue
        if _PRIVATE_TYPES_IMPORT.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_SRC)))
    assert not offenders, (
        "these modules import the private contracts._types instead of the public "
        f"mylonite.contracts facade: {offenders}"
    )
