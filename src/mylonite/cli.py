"""Typer CLI for Mylonite.

Phase 0 exposes the surface area but only the read-only commands work:

* ``mylonite version`` — print the package version.
* ``mylonite taxonomy list --framework <id>`` — list entries from a bundled
  threat taxonomy.

The ``scan`` / ``generate`` / ``validate`` / ``init`` commands are stubs that
exit non-zero with a "coming in v0.2" message. This lets ``mylonite --help``
advertise the eventual UX without lying about capability.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from mylonite.version import __version__

app = typer.Typer(
    name="mylonite",
    help="AI-layer security testing. Finds AI-agent weaknesses and writes the regression tests that close them.",
    add_completion=False,
    no_args_is_help=True,
)

taxonomy_app = typer.Typer(help="Inspect the bundled threat taxonomy.")
app.add_typer(taxonomy_app, name="taxonomy")

_console = Console()


class _Framework(StrEnum):
    OWASP_LLM = "owasp-llm"
    OWASP_ASI = "owasp-asi"
    ATLAS = "atlas"
    NIST = "nist"


@app.command()
def version() -> None:
    """Print the installed Mylonite version."""
    typer.echo(__version__)


def _not_implemented(name: str) -> None:
    typer.echo(
        f"`{name}` is not implemented in v{__version__}. "
        "It arrives in v0.2 — see ROADMAP.md and the issue tracker.",
        err=True,
    )
    raise typer.Exit(code=2)


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Path to the target AI layer to scan.")],
    authorize: Annotated[
        str | None,
        typer.Option("--authorize", help="Target you assert ownership of. Required."),
    ] = None,
) -> None:
    """[v0.2] Scan a target's AI layer for weaknesses."""
    del target, authorize
    _not_implemented("scan")


@app.command()
def generate() -> None:
    """[v0.2] Generate a regression test from a confirmed exploit."""
    _not_implemented("generate")


@app.command()
def validate() -> None:
    """[v0.2] Run a generated test through the differential-oracle validator."""
    _not_implemented("validate")


@app.command()
def init() -> None:
    """[v0.2] Scaffold a Mylonite config in the current directory."""
    _not_implemented("init")


@taxonomy_app.command("list")
def taxonomy_list(
    framework: Annotated[
        _Framework,
        typer.Option("--framework", help="Which framework to list."),
    ],
) -> None:
    """List entries from a bundled threat-taxonomy framework."""
    # Local import to keep CLI startup fast and to avoid loading YAML at
    # import time.
    from mylonite import taxonomy

    loaders: dict[_Framework, Callable[[], Sequence[Any]]] = {
        _Framework.OWASP_LLM: taxonomy.load_owasp_llm,
        _Framework.OWASP_ASI: taxonomy.load_owasp_asi,
        _Framework.ATLAS: taxonomy.load_atlas,
        _Framework.NIST: taxonomy.load_nist_ai_rmf,
    }
    entries = loaders[framework]()

    table = Table(title=f"Framework: {framework.value}")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Source")
    for entry in entries:
        table.add_row(entry.id, entry.name, entry.source_url)
    _console.print(table)
