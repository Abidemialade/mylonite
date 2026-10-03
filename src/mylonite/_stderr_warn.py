"""A redacted stderr print, for the one caller that cannot depend on ``typer``.

``mylonite._cli_io`` is the general console-output boundary (see its own
docstring), but it imports ``typer`` at module level. ``load_target_file``
(``mylonite.plugins._mcp.target_file``) must keep importing and running with
NOTHING beyond its own module's dependencies (``pydantic``/``yaml``) --
``gate-action/action.yml``'s runtime-detection step calls it from a bare
``python``, before any later step installs ``typer`` (see that function's
docstring and ``gate-action/action.yml``'s "Decide whether the target needs
Node or uv" step).

This module exists ONLY to give that one call site a redacted print without
pulling in ``typer``. It has no other purpose, which is also why
``tests/test_cli_output_boundary.py`` allowlists this whole (one-function)
file instead of widening its exception to cover all of ``target_file.py`` --
the same reason ``_cli_io.py`` itself is allowlisted there.
"""

from __future__ import annotations

import sys

from mylonite._redaction import redact

__all__ = ["warn_stderr"]


def warn_stderr(message: str) -> None:
    """Print ``message`` to stderr with secret-shaped tokens masked.

    Mirrors ``mylonite._cli_io.echo_err``'s redaction guarantee (both call
    the same :func:`mylonite._redaction.redact`), without ``echo_err``'s
    ``typer`` dependency.
    """
    print(redact(message), file=sys.stderr)
