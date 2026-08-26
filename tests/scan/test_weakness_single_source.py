"""The W1-W4 taxonomy has exactly one definition, and it stays that way.

Guards issue #93: the four weakness classes used to be re-declared independently
across ``scan/``, ``report/``, ``gate/`` and ``plugins/``. They now live in
``mylonite.scan.weakness``; these tests fail if the ``Weakness`` type alias drifts
from the enum, or if a full key-set re-listing is reintroduced anywhere in ``src/``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

from mylonite.scan.seeds import Weakness
from mylonite.scan.weakness import WEAKNESS_CLASSES, WeaknessClass

_SRC = Path(__file__).resolve().parents[2] / "src" / "mylonite"

# A set/frozenset literal that re-lists all four classes, in any order, e.g.
# ``{"W1", "W2", "W3", "W4"}``. The ordered Literal (square brackets) is exempt.
_FULL_SET_RELISTING = re.compile(r"\{\s*(?:\"W[1-4]\"\s*,\s*){3}\"W[1-4]\"\s*\}")


def test_enum_values_are_the_wire_strings() -> None:
    assert [w.value for w in WeaknessClass] == ["W1", "W2", "W3", "W4"]
    assert sorted(WEAKNESS_CLASSES) == ["W1", "W2", "W3", "W4"]
    # StrEnum members compare/hash as their string, so membership works on plain str.
    assert "W2" in WEAKNESS_CLASSES
    assert WeaknessClass.W2 == "W2"


def test_literal_alias_stays_in_sync_with_the_enum() -> None:
    assert set(get_args(Weakness)) == {w.value for w in WeaknessClass}


def test_make_control_handles_every_weakness_class() -> None:
    # make_control raises for an unknown class, so this fails the moment a class
    # is added to the enum without a dispatch branch in control_shim.
    from mylonite.scan.control_shim import make_control

    for w in WeaknessClass:
        assert make_control(w) is not None, w


def test_severity_partition_covers_every_weakness_class() -> None:
    # Adding a class without classifying its base severity leaves it out of the
    # partition — a checkable error rather than a silent Medium default.
    from mylonite.report.severity import _HIGH_BASE_SEVERITY, _MEDIUM_BASE_SEVERITY

    assert (_HIGH_BASE_SEVERITY | _MEDIUM_BASE_SEVERITY) == WEAKNESS_CLASSES


def test_no_module_re_lists_the_full_key_set() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        # weakness.py is the source; it derives the set from the enum, not a literal.
        if path.name == "weakness.py":
            continue
        if _FULL_SET_RELISTING.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_SRC)))
    assert not offenders, (
        "these modules re-list the full W1-W4 key set instead of importing "
        f"WEAKNESS_CLASSES from mylonite.scan.weakness: {offenders}"
    )
