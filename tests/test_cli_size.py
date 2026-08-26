"""Keep `cli.py` from re-growing into a fat controller (issue #91).

`cli.py` is the CLI composition root: Typer command definitions and the wiring
that assembles their collaborators. Domain logic (rendering, target-file
scaffolding, the scan-pipeline builder, ...) belongs in the domain packages, not
here. #91 extracted the terminal renderers to `mylonite.report.render` and the
target-file scaffolding to `mylonite.plugins._mcp.scaffold`.

This test caps `cli.py` so the next contributor adds substantial new logic in a
proper module rather than inlining it here. If you're over the cap, that's the
signal to extract, not to raise the number.
"""

from __future__ import annotations

from pathlib import Path

_CLI = Path(__file__).resolve().parents[1] / "src" / "mylonite" / "cli.py"

# Ceiling with modest headroom over the post-#91 size (~4,634 LOC). Lower it as
# more is extracted; do not raise it to accommodate new inlined domain logic.
_MAX_LOC = 4_750


def test_cli_py_stays_under_the_fat_controller_ceiling() -> None:
    loc = len(_CLI.read_text(encoding="utf-8").splitlines())
    assert loc <= _MAX_LOC, (
        f"cli.py is {loc} LOC, over the {_MAX_LOC} ceiling. Extract new domain "
        "logic into a domain package (e.g. report/, plugins/_mcp/, scan/) and "
        "call it from the thin command body, rather than inlining it here."
    )
