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

import pytest
import typer

from mylonite.scan.seeds import Weakness
from mylonite.scan.weakness import (
    WEAKNESS_CLASSES,
    WeaknessClass,
    apply_weakness_class_filter,
    validate_weakness_class_flag_or_exit,
)

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


def test_validate_weakness_class_flag_accepts_known_uppercase_values() -> None:
    validate_weakness_class_flag_or_exit(["W2", "W4"])  # must not raise


def test_validate_weakness_class_flag_rejects_unknown_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        validate_weakness_class_flag_or_exit(["W9"])
    from mylonite.exit_codes import EXIT_CONFIG

    assert excinfo.value.exit_code == EXIT_CONFIG
    err = capsys.readouterr().err
    assert "W9" in err
    assert "--weakness-class" in err


def test_validate_weakness_class_flag_rejects_lowercase_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#205c: lowercase is REJECTED, not silently upper-cased --
    a typo like 'w4' must be caught, not quietly coerced."""
    with pytest.raises(typer.Exit):
        validate_weakness_class_flag_or_exit(["w4"])
    err = capsys.readouterr().err
    assert "w4" in err


def test_apply_weakness_class_filter_is_a_noop_with_no_flag() -> None:
    effective, added = apply_weakness_class_filter(["W2", "W4"], None)
    assert effective == ["W2", "W4"]
    assert added == []


def test_apply_weakness_class_filter_declares_when_the_target_declares_nothing() -> None:
    """#227: an empty ``declared`` (no weakness_classes: line, or the inline
    mcp:custom flags with nothing else to set them) has nothing to filter --
    the flag declares the classes instead, exactly like the inline path
    already does on its own."""
    effective, added = apply_weakness_class_filter([], ["W2"])
    assert effective == ["W2"]
    assert added == ["W2"]


def test_apply_weakness_class_filter_intersects_a_declared_set() -> None:
    """#227: the flag never WIDENS a declared set any more -- it narrows it,
    order preserved from the file, and reports nothing as flag-added (the
    class was already in the file)."""
    effective, added = apply_weakness_class_filter(["W2", "W3", "W4"], ["W4", "W2"])
    assert effective == ["W2", "W4"]
    assert added == []


def test_apply_weakness_class_filter_refuses_an_empty_intersection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#227: naming only classes the target doesn't declare used to WIDEN
    past the declared set; now it matches nothing and refuses up front,
    before any spend, rather than silently running zero seeds."""
    with pytest.raises(typer.Exit) as excinfo:
        apply_weakness_class_filter(["W4"], ["W3"])
    from mylonite.exit_codes import EXIT_CONFIG

    assert excinfo.value.exit_code == EXIT_CONFIG
    err = capsys.readouterr().err
    assert "W3" in err
    assert "W4" in err
    assert "--weakness-class" in err


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
