"""Single source of truth for the W1-W4 weakness-class enumeration.

The four weakness classes are the product's central taxonomy. Before this module
they were re-declared independently in seed typing, target-file validation,
report rendering, gate mitigation and the attack modules, so adding a class meant
finding and editing every re-listing and nothing failed if you missed one.

Everything that names the classes now imports from here. Adding ``W5`` is one edit
to :class:`WeaknessClass`; the drift guard in
``tests/scan/test_weakness_single_source.py`` fails if a literal re-list of the
key set is reintroduced or if the ``Weakness`` type alias falls out of sync.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class WeaknessClass(StrEnum):
    """The weakness classes Mylonite tests for.

    ``StrEnum`` (the same convention as :class:`mylonite.contracts.AbortReason`)
    so a member *is* its wire string: ``WeaknessClass.W1 == "W1"`` and it
    serialises to ``"W1"``. Membership tests against plain strings therefore work
    unchanged.
    """

    W1 = "W1"
    W2 = "W2"
    W3 = "W3"
    W4 = "W4"


#: All weakness-class ids as a frozenset, for membership checks
#: (``"W2" in WEAKNESS_CLASSES``). Derived from the enum, never re-spelled.
WEAKNESS_CLASSES: frozenset[str] = frozenset(WeaknessClass)


def validate_weakness_class_flag_or_exit(values: Iterable[str]) -> None:
    """CLI pre-flight for ``--weakness-class`` (#205c): exit ``EXIT_CONFIG``
    naming any value that isn't an exact, uppercase, known class id --
    rejects both an unknown class (``W9``) and a lowercase typo (``w4``)
    rather than silently coercing either.
    """
    bad = [v for v in values if v not in WEAKNESS_CLASSES]
    if not bad:
        return
    import typer

    from mylonite._cli_io import echo_err
    from mylonite.exit_codes import EXIT_CONFIG

    echo_err(
        f"--weakness-class: unknown value(s) {bad!r}; expected one of "
        f"{sorted(str(w) for w in WEAKNESS_CLASSES)} (uppercase, e.g. W2)."
    )
    raise typer.Exit(code=EXIT_CONFIG)
