"""The scan pipeline is assembled in one place, and stays that way.

Guards issue #92: the discover -> filter-by-family -> ScanEngine(+customiser+judge)
assembly was duplicated across the scan command, the gate, the custom-target
re-drive, ablation and the emitted-test runtime, and the attack-family allowlist
was spelled five times. It now lives in `mylonite.scan.assembly`. These tests
fail if a `ScanEngine` is constructed, or the family allowlist re-spelled,
anywhere else in `src/`.
"""

from __future__ import annotations

import re
from pathlib import Path

from mylonite.scan.assembly import ATTACK_FAMILIES, build_scan_engine, discover_attack_modules

_SRC = Path(__file__).resolve().parents[2] / "src" / "mylonite"

_SCAN_ENGINE_CTOR = re.compile(r"\bScanEngine\s*\(")
# A set/frozenset literal naming the two attack families, in either order.
_FAMILY_SET_LITERAL = re.compile(
    r"\{\s*\"(?:prompt-injection|excessive-agency)-family\"\s*,"
    r"\s*\"(?:prompt-injection|excessive-agency)-family\"\s*\}"
)
_ALLOWED = {"assembly.py"}


def test_public_api() -> None:
    assert callable(build_scan_engine)
    assert callable(discover_attack_modules)
    assert frozenset({"prompt-injection-family", "excessive-agency-family"}) == ATTACK_FAMILIES


def test_scan_engine_constructed_only_in_assembly() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name in _ALLOWED:
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _SCAN_ENGINE_CTOR.search(line):
                offenders.append(f"{path.relative_to(_SRC)}:{i}")
    assert not offenders, (
        "these construct a ScanEngine directly instead of using "
        f"mylonite.scan.assembly.build_scan_engine: {offenders}"
    )


def test_attack_family_allowlist_named_once() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name in _ALLOWED:
            continue
        if _FAMILY_SET_LITERAL.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_SRC)))
    assert not offenders, (
        "these re-spell the attack-family allowlist instead of importing "
        f"ATTACK_FAMILIES from mylonite.scan.assembly: {offenders}"
    )
