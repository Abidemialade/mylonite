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

from typing import Any

import typer
from rich.console import Console

from mylonite._redaction import redact, redact_exception

__all__ = ["console_print", "echo", "echo_err", "echo_exc"]


def echo(message: str = "", *, err: bool = False) -> None:
    """Print ``message`` with secret-shaped tokens masked."""
    typer.echo(redact(message), err=err)


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
        renderable = redact(renderable)
    console.print(renderable, **kwargs)
