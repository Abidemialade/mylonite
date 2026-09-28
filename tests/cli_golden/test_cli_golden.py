"""Characterisation tests for the `mylonite` CLI surface (#91 / PR 0).

These pin `--help` text for every command, the seed listing of
`scan reference:{vulnerable,guarded} --dry-run`, and the `demo` offline
replay -- output and exit codes -- against golden files recorded from the
CLI BEFORE the `cli.py` "thin shell" refactor. They must stay green,
byte-for-byte (module the timing placeholder below), across every commit of
that refactor: a diff here is a behaviour change, which the refactor is not
allowed to make.

Golden files live under ``tests/cli_golden/goldens/`` and were captured with
``COLUMNS=120``, ``TERM=dumb``, ``NO_COLOR=1`` (see ``conftest.py``) so they
render identically on the ubuntu and Windows CI runners. Two things are
normalised away before comparison: elapsed-time text (e.g. ``0.0s``,
``3.7s``), which becomes ``<TIME>s``; and trailing whitespace per line,
which Rich pads box-drawing rows with but the repo's `end-of-file-fixer` /
`trailing-whitespace` pre-commit hooks strip from the committed golden
files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mylonite.cli import app

runner = CliRunner()

_GOLDENS_DIR = Path(__file__).parent / "goldens"

_TIME_RE = re.compile(r"\d+\.\d+s")


def _normalise(output: str) -> str:
    """Normalise away sources of variance that aren't meaningful content.

    Elapsed-time text changes run to run. Trailing per-line whitespace is a
    Rich box-padding artefact that the pre-commit hooks already strip from
    the committed golden files, so it must be stripped here too or every
    golden would fail on a whitespace-only diff.
    """
    output = _TIME_RE.sub("<TIME>s", output)
    lines = "\n".join(line.rstrip() for line in output.splitlines())
    return lines.strip("\n")


def _read_golden(name: str) -> str:
    return (_GOLDENS_DIR / f"{name}.txt").read_text(encoding="utf-8")


def _assert_matches_golden(golden_name: str, result, expected_exit_code: int = 0) -> None:
    assert result.exit_code == expected_exit_code, (
        f"{golden_name}: expected exit code {expected_exit_code}, got "
        f"{result.exit_code}\noutput:\n{result.output}"
    )
    actual = _normalise(result.output)
    expected = _normalise(_read_golden(golden_name))
    assert actual == expected, (
        f"{golden_name}: CLI output drifted from the golden file "
        f"tests/cli_golden/goldens/{golden_name}.txt.\n"
        f"--- expected ---\n{expected}\n--- actual ---\n{actual}"
    )


# --- `--help` text of every command ----------------------------------------


def test_root_help_matches_golden() -> None:
    result = runner.invoke(app, ["--help"])
    _assert_matches_golden("help_root", result)


@pytest.mark.parametrize(
    "command",
    [
        "version",
        "plugins",
        "scan",
        "demo",
        "generate",
        "validate",
        "report",
        "gate",
        "ablate",
        "check",
    ],
)
def test_command_help_matches_golden(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    _assert_matches_golden(f"help_{command}", result)


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
