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

#: Classes whose finding turns on a real side effect materialising: a URL
#: actually fetched (W3), a message actually sent (W4). Only a probe of the
#: target's own state can confirm that effect.
EFFECTFUL_WEAKNESS_CLASSES: frozenset[str] = frozenset({"W3", "W4"})


def apply_weakness_class_filter(
    declared: list[str], flag: Iterable[str] | None
) -> tuple[list[str], list[str]]:
    """Resolve a custom target's effective ``weakness_classes`` against
    ``--weakness-class`` (#227): the flag means the SAME thing everywhere now
    -- "only these classes run".

    * No flag: ``declared`` is returned unchanged; nothing came from the flag.
    * ``declared`` is empty (the target file has no ``weakness_classes:``, or
      an inline ``mcp:custom`` target with no other source for them): there is
      nothing to filter, so the flag *declares* the classes instead -- the
      same thing the inline ``mcp:custom`` CLI flags already do on their own.
    * ``declared`` is non-empty: the flag *filters* it (set intersection,
      preserving the file's order) -- never widens it. A class named by the
      flag that the file doesn't declare is simply not in the result; if
      NONE of the flag's classes are declared, the intersection is empty and
      this refuses up front, before any spend, rather than silently scanning
      nothing or (the old bug) widening past what the file declared.

    Returns ``(effective_classes, added_by_flag)``. ``added_by_flag`` names
    classes that have no ``weakness_classes:`` line to point a fix at (the
    empty-``declared`` case) -- a caller reporting an uncoverable class can
    then say "drop it from the flag" instead of "remove it from
    weakness_classes", which would name a key the target file doesn't have.
    """
    flag_list = list(flag or [])
    if not flag_list:
        return list(declared), []
    if not declared:
        return flag_list, flag_list
    filtered = [w for w in declared if w in flag_list]
    if not filtered:
        import typer

        from mylonite._cli_io import echo_err
        from mylonite.exit_codes import EXIT_CONFIG
        from mylonite.reason_codes import PRE_WEAKNESS_FILTER_EMPTY, get, tag

        echo_err(
            tag(
                PRE_WEAKNESS_FILTER_EMPTY,
                f"error: --weakness-class {sorted(flag_list)} matches none of this "
                f"target's declared weakness_classes {list(declared)}; nothing would "
                f"be scanned. {get(PRE_WEAKNESS_FILTER_EMPTY).fix}",
            )
        )
        raise typer.Exit(code=EXIT_CONFIG)
    return filtered, []


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
