"""Enforce house rule 1: `src/` never calls `typer.echo` directly.

Three independent review passes found unredacted secrets reaching stderr via
`typer.echo` (DCR-0007, DCR-0011, DCR-0006). The redaction helper existed and
was used at *some* call sites — the gap was that each site got to decide. This
test removes the decision.
"""

from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"
_ALLOWED = {"_cli_io.py"}
_CALL = re.compile(r"\btyper\.echo\s*\(")


def test_no_direct_typer_echo_outside_the_output_boundary() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name in _ALLOWED:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _CALL.search(line):
                offenders.append(f"{path.relative_to(_SRC)}:{lineno}")
    assert not offenders, (
        "these call typer.echo directly, bypassing redaction — use "
        "mylonite._cli_io.echo / echo_err / echo_exc instead:\n  " + "\n  ".join(offenders)
    )
