"""Characterisation tests for the `mylonite` CLI surface (#91 / PR 0).

These pin the CLI's command tree (every command's params, defaults, help
text -- see ``_command_tree_snapshot`` below), the seed listing of
`scan reference:{vulnerable,guarded} --dry-run`, and the `demo` offline
replay -- output and exit codes -- against golden files recorded from the
CLI BEFORE the `cli.py` "thin shell" refactor. They must stay green across
every commit of that refactor: a diff here is a behaviour change, which the
refactor is not allowed to make.

Fix round 2 (CI failure on Linux and windows-latest): the original goldens
snapshotted Rich's *rendered* `--help` text. That is not portable -- Rich
picks a box-glyph set (safe/square vs. heavy-head/rounded) from
``rich.console.detect_legacy_windows()``, which differs between this
Windows dev machine (legacy console -> safe box, and Rich's width
computation subtracts 1 for the legacy-console quirk) and both CI runners
(non-legacy -> fancy boxes, no width adjustment); Typer/Click's own
`--help` renderer also wraps option text at its own width, independent of
this project's ``COLUMNS`` pin, and that wrapping isn't guaranteed stable
across Typer/Rich/Click versions or platforms either. All 14 goldens failed
in CI while passing locally, exactly because they compared *rendering*
choices neither this project nor this test suite controls.

Two independent fixes:

1. `--help` text is no longer snapshotted at all. Instead,
   ``_command_tree_snapshot`` reads the actual Click command tree Typer
   builds (``typer.main.get_command(app)``) and records, per command: its
   name, full help text and epilog, and per-parameter name, opts/
   secondary_opts, type name, required-ness, default (``repr``'d),
   multiple/is_flag, envvar and help text. That data is what `--help`
   renders *from* -- this still fails on any flag, default or help-text
   change a refactor could introduce, but is entirely independent of
   Rich/Click's terminal width and box-glyph choices, so it renders
   identically on every OS/CI runner/Typer version. Stored as one sorted
   JSON file (``command_tree.json``) for a readable diff.
2. The dry-run and demo goldens stay text-based (they exercise real
   `_cli_io`/`report`/`demo` rendering, which is worth pinning), but
   ``_normalise`` now also maps every Unicode box-drawing character
   (U+2500-U+257F -- covers every line/box-junction glyph Rich's box styles
   use, safe or fancy) to a plain space, and then flattens the whole output
   to a whitespace-separated token sequence rather than comparing line by
   line. A table row's or a paragraph's newline placement is a Rich
   rendering choice exactly like the box glyphs, and turned out to still
   depend on more than the ``COLUMNS`` pin (see ``_normalise``'s own
   docstring) -- flattening the whole output means the comparison covers
   cell/paragraph content and its order, never where a line happened to
   break.

Golden files were captured with ``COLUMNS=120``, ``TERM=dumb``,
``NO_COLOR=1`` (see ``conftest.py``, which sets these via ``monkeypatch``
and so overrides whatever the invoking shell/CI runner had set) and are
proven stable under ``COLUMNS=80``/``TERM=xterm-256color`` set *externally*
(the fixture's own pin must win) and with
``rich.console.detect_legacy_windows`` patched to return ``False`` (this
dev machine's local Windows console is a "legacy" one; CI's Windows and
Linux runners are not, and box style/width computation differ only through
that one function) -- see the fix-round-2 report section for the exact
commands.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import click
from typer.main import get_command
from typer.testing import CliRunner

from mylonite.cli import app

runner = CliRunner()

_GOLDENS_DIR = Path(__file__).parent / "goldens"

_TIME_RE = re.compile(r"\d+\.\d+s")

#: The full Unicode "Box Drawing" block -- every horizontal/vertical/corner/
#: junction glyph any Rich box style (safe, square, heavy-head, rounded, ...)
#: draws a table or panel border with. Mapping the whole block, rather than
#: an enumerated set of "the glyphs this box style happens to use", is what
#: makes this normalisation independent of which style Rich picks.
_BOX_DRAWING_RE = re.compile(r"[─-╿]")


def _normalise(output: str) -> str:
    """Normalise away rendering choices that aren't meaningful content.

    Elapsed-time text changes run to run. Box-drawing glyphs are a Rich
    styling choice (safe/square locally, heavy-head/rounded in CI -- see the
    module docstring), not content, so the whole Unicode block is replaced
    with a space first.

    The result is then flattened to a plain whitespace-separated token
    sequence -- not just per line, across the *whole* output -- rather than
    compared line by line. A table row's newline-vs-space boundaries are a
    Rich rendering choice exactly like the box glyphs, and the paragraph
    prose (e.g. demo's coverage summary) word-wraps at a width that turned
    out to depend on more than the ``COLUMNS`` pin: Rich's own width
    computation subtracts 1 when ``Console.legacy_windows`` is true (this
    dev machine's local console; CI's runners are not), independent of
    ``COLUMNS``, so a phrase can land one word earlier or later in the
    wrapped text depending only on that platform quirk. ``str.split()``
    (no separator) treats a run of any whitespace, including a line break,
    as one token boundary, so this comparison covers cell/paragraph content
    and its order -- not which glyphs drew a border or where Rich chose to
    break a line.
    """
    output = _TIME_RE.sub("<TIME>s", output)
    output = _BOX_DRAWING_RE.sub(" ", output)
    return " ".join(output.split())


def _read_golden_text(name: str) -> str:
    return (_GOLDENS_DIR / f"{name}.txt").read_text(encoding="utf-8")


def _assert_matches_golden(golden_name: str, result, expected_exit_code: int = 0) -> None:
    assert result.exit_code == expected_exit_code, (
        f"{golden_name}: expected exit code {expected_exit_code}, got "
        f"{result.exit_code}\noutput:\n{result.output}"
    )
    actual = _normalise(result.output)
    expected = _normalise(_read_golden_text(golden_name))
    assert actual == expected, (
        f"{golden_name}: CLI output drifted from the golden file "
        f"tests/cli_golden/goldens/{golden_name}.txt.\n"
        f"--- expected ---\n{expected}\n--- actual ---\n{actual}"
    )


# --- command-tree snapshot (replaces rendered --help goldens) ---------------


def _param_snapshot(param: click.Parameter) -> dict[str, Any]:
    """Everything about one Click parameter that ``--help`` is built from."""
    return {
        "name": param.name,
        "opts": sorted(param.opts),
        "secondary_opts": sorted(param.secondary_opts),
        "type": type(param.type).__name__,
        "required": bool(param.required),
        # repr()'d: every default in this CLI is a plain None/bool/int/float/
        # str today (no Path/enum/callable defaults), but repr() keeps this
        # working (and JSON-serialisable) if that ever changes.
        "default": repr(param.default),
        "multiple": bool(getattr(param, "multiple", False)),
        "is_flag": bool(getattr(param, "is_flag", False)),
        "envvar": param.envvar,
        "help": getattr(param, "help", None),
    }


def _command_snapshot(cmd: click.Command) -> dict[str, Any]:
    """Everything about one command that ``--help`` is built from.

    ``hidden`` is tracked explicitly (not just inferred from absence in a
    rendered listing, which this snapshot deliberately doesn't capture) so a
    command silently gaining or losing `hidden=True` -- e.g. `check`/`ablate`,
    hidden behind `MYLONITE_EXPERIMENTAL` -- shows up as a diff here.
    """
    return {
        "name": cmd.name,
        "help": cmd.help,
        "epilog": cmd.epilog,
        "hidden": bool(getattr(cmd, "hidden", False)),
        "params": sorted((_param_snapshot(p) for p in cmd.params), key=lambda p: p["name"]),
    }


def _command_tree_snapshot() -> dict[str, Any]:
    """The whole ``mylonite`` command tree, as data rather than rendering.

    Independent of terminal width, box-glyph style and Typer/Rich/Click
    version -- this is the input those renderers consume, not their output.
    """
    root = get_command(app)
    commands: dict[str, click.Command] = getattr(root, "commands", {})
    return {
        "root": _command_snapshot(root),
        "commands": {name: _command_snapshot(sub) for name, sub in sorted(commands.items())},
    }


def test_command_tree_matches_golden() -> None:
    actual = _command_tree_snapshot()
    expected = json.loads((_GOLDENS_DIR / "command_tree.json").read_text(encoding="utf-8"))
    assert actual == expected, (
        "the mylonite command tree (flags, defaults, help text) drifted from "
        "tests/cli_golden/goldens/command_tree.json -- if this is an intended "
        "CLI change, regenerate it (see test_cli_golden.py's module docstring "
        "for the extraction function) and review the diff."
    )


# --- dry-run seed listings ---------------------------------------------------


def test_scan_reference_vulnerable_dry_run_matches_golden() -> None:
    result = runner.invoke(app, ["scan", "reference:vulnerable", "--dry-run"])
    _assert_matches_golden("scan_reference_vulnerable_dry_run", result)


def test_scan_reference_guarded_dry_run_matches_golden() -> None:
    result = runner.invoke(app, ["scan", "reference:guarded", "--dry-run"])
    _assert_matches_golden("scan_reference_guarded_dry_run", result)


# --- offline demo replay -----------------------------------------------------


def test_demo_offline_replay_matches_golden() -> None:
    result = runner.invoke(app, ["demo"])
    _assert_matches_golden("demo_replay", result)
