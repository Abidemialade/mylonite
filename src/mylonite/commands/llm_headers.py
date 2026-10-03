"""The CLI side of ``--llm-header`` / ``MYLONITE_LLM_HEADERS``.

Parsing and storage live in :mod:`mylonite.scan.llm_headers`. This module
turns a malformed entry into a usage error (exit ``2``, one line that never
echoes a header value) before any command starts work.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated

import typer

from mylonite._cli_io import echo_err
from mylonite.exit_codes import EXIT_CONFIG
from mylonite.scan.llm_headers import InvalidLLMHeaderError, configure_llm_headers

#: The root ``--llm-header`` option, declared here so ``cli.py`` stays thin.
LLMHeaderOption = Annotated[
    list[str] | None,
    typer.Option(
        "--llm-header",
        metavar="NAME=VALUE",
        help=(
            "Extra HTTP header on every LLM request, e.g. a workspace id "
            "(repeatable; also MYLONITE_LLM_HEADERS). Values are never logged."
        ),
    ),
]


def apply_llm_headers(values: Sequence[str] | None) -> None:
    """Configure the run's extra LLM headers from the flags and the env var."""
    try:
        configure_llm_headers(values)
    except InvalidLLMHeaderError as exc:
        echo_err(f"error: {exc}")
        raise typer.Exit(code=EXIT_CONFIG) from exc
