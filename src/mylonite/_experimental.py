"""Gate for CLI commands that are hidden and experimental.

``check`` and ``ablate`` are registered on the Typer app with ``hidden=True``
(so they do not appear in ``mylonite --help``, README.md's command table, or
the mkdocs nav) and only run when ``MYLONITE_EXPERIMENTAL=1`` is set in the
environment. See ``docs/experimental.md`` for why and what still needs work
before either becomes a documented, supported command.

:func:`guard` wraps only the Typer *entry point* -- the callback registered
with ``app.command(...)`` in ``cli.py`` -- never the underlying function
itself. A caller that imports ``mylonite.commands.check.check`` (or any
``mylonite.scan.ablation`` helper) directly, bypassing the CLI, is not
gated: today nothing in the codebase does that, but the split keeps it true
if something ever does.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import wraps
from typing import TypeVar

import typer

from mylonite._cli_io import echo_err
from mylonite.exit_codes import EXIT_CONFIG

__all__ = ["ENV_VAR", "enabled", "guard", "hidden_command"]

#: Set to "1" to run a command gated by :func:`guard`.
ENV_VAR = "MYLONITE_EXPERIMENTAL"

_F = TypeVar("_F", bound=Callable[..., object])


def enabled() -> bool:
    """True when ``MYLONITE_EXPERIMENTAL=1`` is set in the environment."""
    return os.environ.get(ENV_VAR) == "1"


def guard(command_name: str) -> Callable[[_F], _F]:
    """Decorator for a hidden, experimental CLI command's Typer callback.

    Without ``MYLONITE_EXPERIMENTAL=1`` the wrapped callback never runs: this
    prints one line to stderr and exits with :data:`mylonite.exit_codes.
    EXIT_CONFIG` (this project's config/usage-error code) instead. Preserves
    the wrapped function's signature and docstring (``functools.wraps``), so
    Typer still reads the real parameters and help text off it for
    ``mylonite <command> --help``.
    """

    def decorator(fn: _F) -> _F:
        @wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            if not enabled():
                echo_err(f"`mylonite {command_name}` is experimental; set {ENV_VAR}=1 to run it.")
                raise typer.Exit(code=EXIT_CONFIG)
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def hidden_command(app: typer.Typer, command_name: str) -> Callable[[_F], _F]:
    """``app.command(name=command_name, hidden=True)`` + :func:`guard`, in one
    decorator -- one line at each CLI entry point that needs both, instead of
    two."""

    def decorator(fn: _F) -> _F:
        return app.command(name=command_name, hidden=True)(guard(command_name)(fn))

    return decorator
