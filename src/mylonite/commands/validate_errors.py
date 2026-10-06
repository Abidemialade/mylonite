"""How ``mylonite validate`` and ``mylonite gate`` report a run that could not
reach a verdict.

Two failures used to escape the validator as a traceback and exit ``1``, the
code ``check --enforce`` uses for findings:

* the LLM call budget ran out mid-run → exit ``3``, one line;
* the custom target did not come up → exit ``2``, one line.

The hard request ceiling is a budget error too, but the root command group
already reports it with its own line and exit ``3``
(:mod:`mylonite.commands.llm_ceiling`), so it is passed through untouched here
rather than reported twice.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from mylonite import reason_codes
from mylonite._cli_io import echo_err
from mylonite._redaction import redact, redact_exception
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG

if TYPE_CHECKING:
    from mylonite.plugins._reference.reference_validator import TargetLaunchError


def target_launch_line(exc: TargetLaunchError, *, gate_out: str | None = None) -> str:
    """The one tagged line for a target that did not come up.

    A target that never came up is most likely misconfigured, so the line points
    at the target file. One that went down after some runs finished is not a
    configuration problem; the line says to re-run once it is stable. Under
    ``gate`` (``gate_out`` set) it also says the remaining findings were not
    validated and where the scan results are.
    """
    if exc.completed_runs:
        advice = "the target went down part-way; re-run once it is stable"
    else:
        advice = "check the target file's command or url, then re-run"
    line = f"error: {redact(str(exc))}. No verdict was reached; {advice}."
    if gate_out is not None:
        line += (
            " The gate stopped at this finding, so any later findings were not "
            f"validated; the scan results are in '{gate_out}'."
        )
    return reason_codes.tag(reason_codes.ABT_DESCRIBE_FAILED, line)


def fixtures_line(exc: Exception) -> str:
    """The one line for replay fixtures that cannot be recorded or read."""
    return (
        f"error: {redact(str(exc))} No verdict was reached and no model call was "
        "made for it; fix the fixtures folder, then re-run."
    )


def check_fixtures_recordable_or_exit(fixtures_dir: Path) -> None:
    """Exit with a config error, before any live call, when record mode
    would refuse ``fixtures_dir`` (an older or unknown replay-key version, a
    damaged ``_meta.json``, or recordings with no sidecar)."""
    from mylonite._replay import FixtureError, check_recordable

    try:
        check_recordable(fixtures_dir)
    except FixtureError as exc:
        echo_err(fixtures_line(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc


@contextmanager
def validate_run_errors() -> Iterator[None]:
    """Turn a budget stop or a launch failure inside ``validate`` into an exit."""
    from mylonite._replay import FixtureError
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
                f"was reached ({redact_exception(exc)}). Lower --iterations, then re-run.",
            )
        )
        raise typer.Exit(code=EXIT_BUDGET) from exc
    except TargetLaunchError as exc:
        echo_err(target_launch_line(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except FixtureError as exc:
        echo_err(
            f"error: recording the replay fixtures failed: {redact(str(exc))} "
            "No verdict was reached; fix the fixtures folder, then re-run."
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
