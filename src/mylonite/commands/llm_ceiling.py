"""The CLI side of the hard LLM request ceiling.

The ceiling itself lives at the LLM chokepoint (``mylonite.scan._llm``). This
module makes sure the CLI reports it the same way whichever command was running
and wherever in the run it tripped:

* ``apply_request_ceiling`` reads ``--max-llm-requests`` / the env var once, at
  startup, so a bad value is a usage error (exit ``2``) before any work starts.
* ``CeilingGuardGroup`` wraps every command. If the ceiling refused a request,
  the process exits ``3`` with one line naming the limit, even when a handler
  deeper in the run swallowed the refusal or the command was about to report a
  pass. A run that hit the ceiling never reads as clean.
"""

from __future__ import annotations

from typing import Any

import typer
from typer.core import TyperGroup

from mylonite import reason_codes
from mylonite._cli_io import echo_err
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG
from mylonite.scan._llm import (
    InvalidRequestCeilingError,
    LLMRequestCeilingError,
    configure_request_ceiling,
    request_ceiling,
    request_ceiling_hit,
    request_ceiling_message,
)


def apply_request_ceiling(limit: int | None) -> None:
    """Set the ceiling from ``--max-llm-requests`` and validate the env var."""
    try:
        configure_request_ceiling(limit)
        request_ceiling()
    except InvalidRequestCeilingError as exc:
        echo_err(f"error: {exc}")
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _abort(limit: int) -> typer.Exit:
    echo_err(
        reason_codes.tag(
            reason_codes.ABT_BUDGET_EXCEEDED, f"error: {request_ceiling_message(limit)}"
        )
    )
    return typer.Exit(code=EXIT_BUDGET)


class CeilingGuardGroup(TyperGroup):
    """The root command group: turns a spent request ceiling into exit ``3``."""

    def invoke(self, ctx: Any) -> Any:  # typer's vendored click Context
        try:
            result = super().invoke(ctx)
        except LLMRequestCeilingError as exc:
            raise _abort(exc.limit) from exc
        except InvalidRequestCeilingError as exc:
            # A ceiling Mylonite cannot enforce (a bad value, or a global
            # LiteLLM retry count it could not count) is a usage error.
            echo_err(f"error: {exc}")
            raise typer.Exit(code=EXIT_CONFIG) from exc
        except typer.Exit as exc:
            limit = request_ceiling_hit()
            if limit is not None:
                raise _abort(limit) from exc
            raise
        except Exception as exc:
            # Anything else that escapes after a refusal (a wrapped refusal, a
            # stage that broke on partial tallies, an ExceptionGroup from a
            # transport task group) is still a run the ceiling cut short.
            limit = request_ceiling_hit()
            if limit is not None:
                raise _abort(limit) from exc
            raise
        limit = request_ceiling_hit()
        if limit is not None:
            raise _abort(limit)
        return result
