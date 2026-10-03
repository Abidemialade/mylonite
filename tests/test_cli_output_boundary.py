"""Enforce house rule 1: `src/` never calls `typer.echo`, `console.print`, or
bare `print` directly outside the output boundary.

Three independent review passes found unredacted secrets reaching stderr via
`typer.echo` (DCR-0007, DCR-0011, DCR-0006). The redaction helper existed and
was used at *some* call sites — the gap was that each site got to decide. This
test removes the decision for `typer.echo`.

A later spec-compliance review found the SAME class of gap one layer over:
`_cli_io.py`'s own docstring claimed "every human-facing string now leaves
through here," but this test only checked `typer.echo` — `console.print(...)`
and bare `print(...)` calls in `cli.py`, `gate/orchestrator.py`, and
`gate/pr.py` bypassed it entirely. Concretely, `mylonite report` rendered
`render_summary()`'s output via a bare `console.print(...)` with NO
redaction, even though `mylonite scan` redacted the exact same string. This
test now also removes that decision.
"""

from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"
# `target_file.py` (#187): `load_target_file`'s own relative-SQLite-path
# warning prints with a bare `print(..., file=sys.stderr)`, not
# `mylonite._cli_io.echo_err` -- this function must keep importing and
# running with NOTHING beyond its own module's dependencies (pydantic/yaml)
# installed, because `gate-action/action.yml`'s runtime-detection step calls
# it from a bare `python` before any later step needs `typer`. The one print
# site there still calls `mylonite._redaction.redact()` by hand, the same
# function `echo_err` itself calls, so the redaction guarantee this test
# protects still holds.
_ALLOWED = {"_cli_io.py", "target_file.py"}

# Each pattern is a (label, compiled regex, guidance) triple. All three route
# through mylonite._cli_io — the single place secret-shaped tokens are masked
# before a human-facing string leaves the process.
_CALLS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("typer.echo", re.compile(r"\btyper\.echo\s*\("), "echo / echo_err / echo_exc"),
    # Matches `console.print(` and `_console.print(` (any name ending in
    # "console") — a Rich Console's print method, not a builtin print().
    ("console.print", re.compile(r"console\.print\s*\("), "console_print"),
    # A bare print(...) call: NOT preceded by a `.` (a method call on some
    # object, e.g. console.print / self.print) or a word character (part of a
    # longer identifier, e.g. console_print( itself, which lives in the
    # allowed _cli_io.py and must stay callable from everywhere else).
    ("print(", re.compile(r"(?<![\w.])print\s*\("), "echo / echo_err"),
)


def test_no_direct_output_calls_outside_the_output_boundary() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name in _ALLOWED:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for label, pattern, guidance in _CALLS:
                if pattern.search(line):
                    offenders.append(
                        f"{path.relative_to(_SRC)}:{lineno} ({label} -> use {guidance})"
                    )
    assert not offenders, (
        "these call typer.echo / console.print / print directly, bypassing redaction — "
        "route through mylonite._cli_io instead:\n  " + "\n  ".join(offenders)
    )
