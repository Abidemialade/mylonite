"""How ``mylonite validate`` reports a run that could not reach a verdict.

Two failures used to escape the validator as a traceback and exit ``1``, the
code ``check --enforce`` uses for findings:

* the LLM call budget ran out mid-run → exit ``3``, one line;
* the custom target never came up → exit ``2``, one line.

The hard request ceiling is a budget error too, but the root command group
already reports it with its own line and exit ``3``
(:mod:`mylonite.commands.llm_ceiling`), so it is passed through untouched here
rather than reported twice.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import typer

from mylonite import reason_codes
from mylonite._cli_io import echo_err
from mylonite._redaction import redact, redact_exception
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG


@contextmanager
def validate_run_errors() -> Iterator[None]:
    """Turn a budget stop or a launch failure inside ``validate`` into an exit."""
    from mylonite.plugins._reference.reference_validator import TargetLaunchError
    from mylonite.scan._llm import BudgetExceededError, LLMRequestCeilingError

    try:
        yield
    except LLMRequestCeilingError:
        raise
    except BudgetExceededError as exc:
        echo_err(
            reason_codes.tag(
                reason_codes.ABT_BUDGET_EXCEEDED,
                f"error: the LLM call budget ran out during validation, so no verdict "
                f"was reached ({redact_exception(exc)}). Raise the budget or lower "
                "--iterations, then re-run.",
            )
        )
        raise typer.Exit(code=EXIT_BUDGET) from exc
    except TargetLaunchError as exc:
        echo_err(
            reason_codes.tag(
                reason_codes.ABT_DESCRIBE_FAILED,
                f"error: {redact(str(exc))}. No verdict was reached; check the target file's "
                "command or url, then re-run.",
            )
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
