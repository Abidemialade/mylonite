"""The single console-output boundary for the CLI.

``install_log_redaction`` only sees ``logging`` records; ``typer.echo`` writes
straight to the stream. Before this module, every echo call site had to
remember to redact, and six independently-discovered criticals show they did
not. Every human-facing string now leaves through here.

Enforced by ``tests/test_cli_output_boundary.py``.
"""

from __future__ import annotations

import typer

from mylonite._redaction import redact, redact_exception

__all__ = ["echo", "echo_err", "echo_exc"]


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
