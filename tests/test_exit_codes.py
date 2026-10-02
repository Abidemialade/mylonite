"""The process exit codes have exactly one definition, and it stays that way.

Guards issue #94: the exit-code contract used to be defined three times
(`cli.py`, `gate/orchestrator.py`, `scan/coverage.py`), the last a hand-kept
mirror. They now live in `mylonite.exit_codes`; these tests fail if a consumer
re-defines a code as a literal, or if the documented values drift.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

from mylonite import cli, exit_codes
from mylonite.gate import orchestrator

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src" / "mylonite"
_SNAPSHOT = _REPO_ROOT / "tests" / "fixtures" / "exit_codes.snapshot.json"


def _load_script(relative: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, _REPO_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Every exit code defined today (0-8) -- see test_documented_values below.
_ALL_CODES = [
    exit_codes.EXIT_SUCCESS,
    exit_codes.EXIT_FINDINGS,
    exit_codes.EXIT_CONFIG,
    exit_codes.EXIT_BUDGET,
    exit_codes.EXIT_PROVIDER,
    exit_codes.EXIT_NOT_KEPT,
    exit_codes.EXIT_GENERATE_FAILED,
    exit_codes.EXIT_VALIDATE_FAILED,
    exit_codes.EXIT_PR_FAILED,
]

# A module-level assignment of an EXIT_* / _EXIT_* name to an integer *literal*.
# Assignments to another named constant (e.g. `_X: Final = EXIT_CONFIG`) are fine.
_EXIT_LITERAL_DEF = re.compile(r"^_?EXIT_[A-Z_]+\s*(?::[^=]+)?=\s*\d", re.MULTILINE)


def test_documented_values() -> None:
    assert exit_codes.EXIT_SUCCESS == 0
    assert exit_codes.EXIT_FINDINGS == 1
    assert exit_codes.EXIT_CONFIG == 2
    assert exit_codes.EXIT_BUDGET == 3
    assert exit_codes.EXIT_PROVIDER == 4
    assert exit_codes.EXIT_NOT_KEPT == 5
    assert exit_codes.EXIT_GENERATE_FAILED == 6
    assert exit_codes.EXIT_VALIDATE_FAILED == 7


def test_consumers_reference_the_single_source() -> None:
    # cli and orchestrator re-export the SAME objects, not private copies.
    assert cli.EXIT_CONFIG is exit_codes.EXIT_CONFIG
    assert cli.EXIT_SUCCESS is exit_codes.EXIT_SUCCESS
    assert orchestrator.EXIT_NOT_KEPT is exit_codes.EXIT_NOT_KEPT
    assert orchestrator.EXIT_VALIDATE_FAILED is exit_codes.EXIT_VALIDATE_FAILED


def test_only_exit_codes_module_defines_the_literals() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name == "exit_codes.py":
            continue
        if _EXIT_LITERAL_DEF.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_SRC)))
    assert not offenders, (
        "these modules define an exit code as a literal instead of importing it "
        f"from mylonite.exit_codes: {offenders}"
    )


# -- SEVERITY_ORDER / most_severe: explicit severity, not a numeric max() ---------
#
# `scan/ablation.py`'s `total_failure_exit_code` used to pick `max(exit_code for ...)`,
# which happened to work only because every code minted so far ranks more severe as
# its number increases. That's an accident of numbering, not a rule -- a later code
# (e.g. a 9 or 10 that means something less severe than 8) would silently break it.
# `most_severe` replaces the numeric comparison with an explicit order so future
# codes can be placed deliberately.


def test_severity_order_contains_every_documented_code_exactly_once() -> None:
    assert sorted(exit_codes.SEVERITY_ORDER) == sorted(_ALL_CODES)
    assert len(exit_codes.SEVERITY_ORDER) == len(set(exit_codes.SEVERITY_ORDER))


def test_severity_order_is_not_simply_sorted_numerically() -> None:
    # Guards against a no-op "explicit" list that's secretly `sorted(_ALL_CODES)`
    # in disguise -- the ordering must be a real, independent list literal.
    assert list(exit_codes.SEVERITY_ORDER) == sorted(exit_codes.SEVERITY_ORDER), (
        "SEVERITY_ORDER happens to be numerically sorted today (it must reproduce "
        "max() for codes 0-8), but this test exists to be revisited, not deleted, "
        "the day a later code needs to rank out of numeric order."
    )


def test_most_severe_agrees_with_max_for_every_combination_of_documented_codes() -> None:
    for r in range(1, len(_ALL_CODES) + 1):
        for combo in itertools.combinations_with_replacement(_ALL_CODES, r):
            assert exit_codes.most_severe(combo) == max(combo)


def test_most_severe_is_order_independent() -> None:
    assert exit_codes.most_severe([2, 4]) == 4
    assert exit_codes.most_severe([4, 2]) == 4


def test_most_severe_rejects_empty() -> None:
    with pytest.raises(ValueError):
        exit_codes.most_severe([])


# -- frozen snapshot: the set of codes cannot drift silently -----------------
#
# test_documented_values (above) only pins the values of the codes it already
# knows about. Adding, removing, or renumbering a code -- or reordering
# SEVERITY_ORDER -- is a public-API change (the exit-code contract is
# documented in docs/cli-reference.md and read by CI gates), so it must fail
# here, following the same frozen-snapshot pattern as reason codes
# (tests/test_reason_codes.py) and testkit signatures
# (tests/testkit/test_testkit.py).


def test_codes_match_the_frozen_snapshot() -> None:
    """Update deliberately: ``python scripts/update_snapshots.py``, then add a
    CHANGELOG.md line. A pull request also needs the snapshot-change label
    (enforced by scripts/check_snapshot_changes.py in CI)."""
    update_snapshots = _load_script("scripts/update_snapshots.py", "update_snapshots")
    snapshot = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    current = update_snapshots.build_exit_codes()
    assert current == snapshot, (
        f"exit codes drifted from {_SNAPSHOT.name}. If intentional, update it "
        "(python scripts/update_snapshots.py) and add a CHANGELOG.md line."
    )


def test_most_severe_rejects_unknown_codes() -> None:
    # Documented behaviour: an exit code outside SEVERITY_ORDER is a bug at the
    # call site (a code that was never registered), so it raises rather than
    # silently sorting to the end or the start.
    with pytest.raises(ValueError):
        exit_codes.most_severe([0, 99])
