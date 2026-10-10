"""Terminal control-sequence stripping at the console-output boundary (F3).

A target's tool output, description, or error message is attacker/target
controlled and reaches a real terminal (or a CI log viewer that renders
control bytes) through ``echo``/``console_print``. Before this module's
``_strip_terminal_controls``, those functions only redacted secret-shaped
tokens -- a raw ANSI escape sequence (clear screen, move cursor, rewrite the
window title) or a bare C1 control byte rode through unchanged. Each test
here FAILED before the fix and PASSES after it.
"""

from __future__ import annotations

import typer
from rich.console import Console
from typer.testing import CliRunner

from mylonite._cli_io import _strip_terminal_controls, console_print, echo

runner = CliRunner()


def test_strip_terminal_controls_removes_csi_sequence():
    # ESC [ 2 J -- the classic "clear screen" CSI sequence.
    out = _strip_terminal_controls("before\x1b[2Jafter")
    assert out == "beforeafter"
    assert "\x1b" not in out


def test_strip_terminal_controls_removes_bare_c1_csi_introducer():
    # 0x9b is the 8-bit single-byte equivalent of ESC [ -- some terminals and
    # targets emit it directly instead of the 2-byte form.
    out = _strip_terminal_controls("before\x9bafter")
    assert out == "beforeafter"
    assert "\x9b" not in out


def test_strip_terminal_controls_removes_osc_title_sequence():
    # ESC ] 0 ; <title> BEL -- rewrites the terminal window/tab title.
    out = _strip_terminal_controls("before\x1b]0;pwned\x07after")
    assert out == "beforeafter"
    assert "\x1b" not in out and "\x07" not in out


def test_strip_terminal_controls_keeps_newline_and_tab():
    out = _strip_terminal_controls("line1\nline2\tcol2")
    assert out == "line1\nline2\tcol2"


def test_strip_terminal_controls_removes_carriage_return():
    # A bare CR overwrites the current line on a real terminal -- itself a
    # cursor-manipulation primitive, not something a PR/log line needs.
    out = _strip_terminal_controls("real line\rFAKE: all clear")
    assert "\r" not in out
    assert out == "real lineFAKE: all clear"


def test_echo_strips_ansi_and_c1_controls(capsys):
    echo("before\x1b[2Jafter\x9bmid")
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out
    assert "\x9b" not in captured.out
    assert "beforeafter" in captured.out
    assert "mid" in captured.out


def test_console_print_strips_ansi_and_c1_controls(capsys):
    console = Console(force_terminal=False, no_color=True)
    console_print(console, "before\x1b[2Jafter\x9bmid")
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out
    assert "\x9b" not in captured.out


def test_echo_via_clirunner_strips_escape_sequences():
    """End-to-end through Typer's own output path, not just a direct call."""
    app = typer.Typer()

    @app.command()
    def cmd() -> None:
        echo("before\x1b[2Jafter\x9bmid")

    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\x9b" not in result.output
    assert "beforeafter" in result.output
