"""The single console-output boundary for the CLI.

``install_log_redaction`` only sees ``logging`` records; ``typer.echo`` and
``rich.console.Console.print``/bare ``print`` write straight to the stream.
Before this module, every call site had to remember to redact, and multiple
independently-discovered criticals show they did not — including, in a later
pass, ``console.print`` and bare ``print`` sites this module's own docstring
had not yet covered. Every human-facing string now leaves through here.

Enforced by ``tests/test_cli_output_boundary.py``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from mylonite._redaction import redact, redact_exception
from mylonite.exit_codes import EXIT_CONFIG

__all__ = [
    "_exit_if_missing_kitchen_sink",
    "_exit_if_missing_target_file",
    "console_print",
    "echo",
    "echo_err",
    "echo_exc",
    "missing_target_file_message",
]

# 7-bit ESC-led escape sequences (F3): a CSI (`ESC [ ... final-byte`), an OSC
# (`ESC ] ... BEL` or `... ESC \`), and any other Fe-class escape (`ESC` +
# one byte in 0x40-0x5F) -- the shapes a target's own text could smuggle to
# move the cursor, clear the screen, or rewrite a terminal title in a scan
# log/CI console a human is reading. ``re.DOTALL`` lets an OSC's `.*?` cross
# embedded newlines, matching how real terminals treat OSC.
_ESC_SEQUENCE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\\]^_])", re.DOTALL
)
# Remaining raw C0/C1 control bytes -- including CR (itself a
# cursor-manipulation primitive, overwriting the current line) and the
# single-byte 8-bit equivalents of the CSI (0x9b) and OSC (0x9d) introducers,
# which some terminals/targets emit directly instead of the 2-byte ESC form.
# Deliberately NOT matched as a full 8-bit sequence (introducer + params +
# final byte): the 8-bit CSI/OSC grammar's "final byte" range overlaps
# ordinary ASCII letters, so attempting to consume a whole sequence risks
# eating the start of unrelated following text; stripping just the
# introducer byte already breaks the sequence. ``\n``/``\t`` are kept, since
# they are the only two a human-facing CLI line legitimately needs.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _strip_terminal_controls(text: str) -> str:
    """Remove ANSI escape sequences and C0/C1 control bytes from ``text``.

    A target's tool output, description, or error message can contain raw
    control bytes; printed as-is, they reach a real terminal (or a CI log
    viewer that renders them) and can clear the screen, move the cursor, or
    rewrite the window/tab title (F3) -- the terminal analogue of F9's
    Markdown-injection gap. ``\\n`` and ``\\t`` are kept so ordinary
    multi-line/tab-formatted output is unaffected.
    """
    text = _ESC_SEQUENCE_RE.sub("", text)
    return _CONTROL_RE.sub("", text)


def echo(message: str = "", *, err: bool = False) -> None:
    """Print ``message`` with secret-shaped tokens masked and terminal
    control sequences stripped."""
    typer.echo(_strip_terminal_controls(redact(message)), err=err)


def echo_err(message: str = "") -> None:
    """Print to stderr with redaction — the common case for warnings and errors."""
    echo(message, err=True)


def echo_exc(prefix: str, exc: BaseException) -> None:
    """Print ``prefix`` plus a safely-rendered exception to stderr.

    Uses :func:`mylonite._redaction.redact_exception`, which strips pydantic's
    ``input_value`` — the field that carried the bearer token in DCR-0007 and
    the ``--env`` value in DCR-0011.
    """
    echo(f"{prefix}: {redact_exception(exc)}", err=True)


def console_print(console: Console, renderable: object = "", **kwargs: Any) -> None:
    """``Console.print`` with secret-shaped tokens masked.

    A plain string renderable is redacted before printing — this is the path
    that closes the concrete gap a review found: ``mylonite report`` rendered
    ``render_summary()``'s output via a bare ``console.print(...)`` with no
    redaction, even though ``mylonite scan`` redacts the exact same string.

    A structured renderable (``Table``, ``Panel``, ...) is passed through
    unchanged — ``Console`` has no generic way to redact an arbitrary Rich
    renderable's internal text after construction, and Rich's own column-width
    wrapping can split a token across a line break before it would ever reach
    here. Callers building a ``Table``/``Panel`` from scan/target/validation
    free text must redact each interpolated cell/text value at construction
    time instead (see the ``redact()`` calls at the ``add_row`` sites in
    ``cli.py`` and ``scan/artefacts.py``) — this wrapper is the last line of
    defense for the plain-string case, not the only one.
    """
    if isinstance(renderable, str):
        renderable = _strip_terminal_controls(redact(renderable))
    console.print(renderable, **kwargs)


def missing_target_file_message(path: Path) -> str:
    """A missing ``--target-file`` names the fix (``--scaffold``), not a raw traceback.

    Every ``load_target_file`` catch site in ``cli.py`` shows this instead of
    a bare ``FileNotFoundError`` — hand-writing a target YAML was never the
    intended path; introspecting the real server with ``--scaffold`` is. Pure
    string builder: no I/O, so it is safe to call from an ``except`` block
    that already knows the file does not exist.
    """
    name = path.name
    return (
        f"target file not found: {name}. Create one from your server with:\n"
        f"  mylonite scan --command python --arg server.py --scaffold {name} --scope my-app\n"
        f"(an HTTP agent: --rest-url URL --scaffold {name}). See docs/target-file.md."
    )


def _exit_if_missing_target_file(exc: Exception, target_file: Path) -> None:
    """Exit with the ``--scaffold`` fix when ``exc`` is a missing target file.

    Shared by every ``load_target_file``/``build_target_spec`` catch site
    across the CLI (``scan``, ``generate``, ``validate``, ``gate``, ``ablate``,
    ``check``) so the fix can't drift between them. Returns normally (does
    nothing) for any other exception -- including a missing file the target
    file itself names, such as ``system_prompt_file`` -- so the caller's
    ``echo_exc`` fallback runs.
    """
    if isinstance(exc, FileNotFoundError) and not target_file.exists():
        echo_err(missing_target_file_message(target_file))
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _exit_if_missing_kitchen_sink(exc: BaseException) -> None:
    """Map a missing reference target to a friendly EXIT_CONFIG, else return.

    The deliberately-vulnerable reference target is a separate package (not a
    base dependency): PyPI users get it with ``pip install mcp-kitchen-sink``;
    an editable checkout needs
    ``pip install -e ./reference_targets/mcp_kitchen_sink``. Without it,
    ``scan reference:*`` / ``validate`` / ``check reference:*`` raise
    ``ModuleNotFoundError`` deep in the adapter. Translate that one cause into
    a clear message everywhere (instead of a raw traceback, or the exception
    class name and all, via the generic ``echo_exc`` fallback); re-raise
    anything unrelated by returning.
    """
    if (getattr(exc, "name", "") or "").split(".")[0] == "mcp_kitchen_sink":
        echo_err(
            "the reference app target isn't installed (it's opt-in) — run "
            "`pip install mcp-kitchen-sink`, or from a checkout "
            "`pip install -e ./reference_targets/mcp_kitchen_sink`."
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
