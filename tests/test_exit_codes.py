"""The process exit codes have exactly one definition, and it stays that way.

Guards issue #94: the exit-code contract used to be defined three times
(`cli.py`, `gate/orchestrator.py`, `scan/coverage.py`), the last a hand-kept
mirror. They now live in `mylonite.exit_codes`; these tests fail if a consumer
re-defines a code as a literal, or if the documented values drift.
"""

from __future__ import annotations

import re
from pathlib import Path

from mylonite import cli, exit_codes
from mylonite.gate import orchestrator

_SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"

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
