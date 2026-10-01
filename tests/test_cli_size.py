"""Keep `cli.py` from re-growing into a fat controller (issue #91).

`cli.py` is the CLI composition root: Typer command definitions and the wiring
that assembles their collaborators. Domain logic (rendering, target-file
scaffolding, the scan-pipeline builder, ...) belongs in the domain packages, not
here. #91 extracted the terminal renderers to `mylonite.report.render` and the
target-file scaffolding to `mylonite.plugins._mcp.scaffold`.

This test caps `cli.py` so the next contributor adds substantial new logic in a
proper module rather than inlining it here. If you're over the cap, that's the
signal to extract, not to raise the number.

The "thin shell" refactor (PR 0 of the #91/#197 follow-up) cut cli.py from
4,749 to ~3,878 LOC: the gate-command closures moved to
`mylonite.gate.wiring`, the generate-command helpers to
`mylonite.generate.wiring`, the `check`-command structural helpers to
`mylonite.scan.control_shim`, and the CLI target-adapter routing to
`mylonite.plugins.cli_targets`.

A later pass moved the `check` command body itself out to
`mylonite.commands.check`, cutting cli.py further to ~3,682 LOC.

`check` and `ablate` were then hidden behind `MYLONITE_EXPERIMENTAL=1` (the
gate itself lives in `mylonite._experimental`, not here): one import, one
registration call, and a two-line docstring fix to `ablate`'s own `--help`
text (what it grades without `control_env`) raised the ceiling by 3 LOC.
"""

from __future__ import annotations

from pathlib import Path

_CLI = Path(__file__).resolve().parents[1] / "src" / "mylonite" / "cli.py"

# Ceiling with modest headroom over the post-`check`-extraction size (~3,682 LOC).
# Lower it as more is extracted; do not raise it to accommodate new inlined
# domain logic.
_MAX_LOC = 3_705


def test_cli_py_stays_under_the_fat_controller_ceiling() -> None:
    loc = len(_CLI.read_text(encoding="utf-8").splitlines())
    assert loc <= _MAX_LOC, (
        f"cli.py is {loc} LOC, over the {_MAX_LOC} ceiling. Extract new domain "
        "logic into a domain package (e.g. report/, plugins/_mcp/, scan/) and "
        "call it from the thin command body, rather than inlining it here."
    )
