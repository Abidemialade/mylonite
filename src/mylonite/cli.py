"""Typer CLI for Mylonite.

Phase 1 (v0.2) lights up ``mylonite scan``:

* ``mylonite version`` — print the package version.
* ``mylonite taxonomy list --framework <id>`` — list entries from a bundled
  threat taxonomy.
* ``mylonite scan <target> [--provider --model --dry-run ...]`` — run the
  exploit-finding loop against a target. Phase 1 ships in-process reference
  targets only (``reference:vulnerable`` / ``reference:guarded``). Real
  out-of-process MCP adapters arrive in Phase 1.5/2.

``generate`` / ``validate`` / ``init`` remain stubs (Phase 2/3 work).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from mylonite.version import __version__

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="mylonite",
    help="AI-layer security testing. Finds AI-agent weaknesses and writes the regression tests that close them.",
    add_completion=False,
    no_args_is_help=True,
)

taxonomy_app = typer.Typer(help="Inspect the bundled threat taxonomy.")
app.add_typer(taxonomy_app, name="taxonomy")

_console = Console()

EXIT_SUCCESS = 0
EXIT_CONFIG = 2
EXIT_BUDGET = 3
EXIT_PROVIDER = 4


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
    raise typer.Exit(code=EXIT_CONFIG)


def _build_adapter_for_reference(target: str, model: str) -> Any:
    from mylonite.plugins._reference.reference_target_adapter import (
        InProcessGuardedReferenceAdapter,
        InProcessReferenceAdapter,
        InProcessVulnerableReferenceAdapter,
    )

    variant = target.split(":", 1)[1] if ":" in target else ""
    if variant == "vulnerable":
        del InProcessVulnerableReferenceAdapter  # 0-arg variant used via entry points
        return InProcessReferenceAdapter(variant="vulnerable", model=model)
    if variant == "guarded":
        del InProcessGuardedReferenceAdapter
        return InProcessReferenceAdapter(variant="guarded", model=model)
    typer.echo(
        f"unknown reference variant {variant!r}; expected reference:vulnerable or reference:guarded",
        err=True,
    )
    raise typer.Exit(code=EXIT_CONFIG)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help=(
                "Target ID. v0.2 supports 'reference:vulnerable' and "
                "'reference:guarded'. Other targets require --authorize and an "
                "adapter (Phase 1.5+)."
            )
        ),
    ],
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LiteLLM provider, e.g. 'anthropic' or 'openai'."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model identifier passed to LiteLLM."),
    ] = None,
    max_llm_calls: Annotated[
        int,
        typer.Option("--max-llm-calls", help="Process-wide LLM call cap for this scan."),
    ] = 50,
    max_concurrent: Annotated[
        int,
        typer.Option("--max-concurrent", help="Max concurrent in-flight seeds."),
    ] = 3,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Root directory for scan artefacts."),
    ] = Path(".mylonite/scans"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Enumerate seeds; skip customisation + invocation."),
    ] = False,
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help="Required for non-reference targets; assert ownership of the target.",
        ),
    ] = None,
) -> None:
    """Run the exploit-finding loop against a target."""
    if not target.startswith("reference:"):
        if not authorize:
            typer.echo(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        typer.echo(
            f"non-reference targets (got {target!r}) are not yet supported in v0.2 — "
            "the MCP-wire and HTTP adapters land in Phase 1.5 / 2.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Resolve provider + model with sensible defaults so dry-run doesn't require
    # a live LLM provider configured.
    effective_provider = provider or "anthropic"
    effective_model = model or "claude-sonnet-4-6"

    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    adapter = _build_adapter_for_reference(target, effective_model)

    try:
        all_modules: list[Any] = discover("mylonite.attack_modules")
    except Exception as exc:
        typer.echo(f"plugin discovery failed: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # v0.2 attack modules: filter to the real prompt-injection family. The
    # reference_example stub is shipped for plugin authors but isn't useful
    # for a real scan.
    _v0_2_ATTACK_FAMILIES = {"prompt-injection-family", "excessive-agency-family"}
    attack_modules = [m for m in all_modules if m.attack_metadata().id in _v0_2_ATTACK_FAMILIES]
    if not attack_modules:
        typer.echo(
            "no usable attack modules discovered "
            "(looking for 'prompt-injection-family' or 'excessive-agency-family')",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    customiser = PayloadCustomiser(model=effective_model)
    judge = SuccessJudge(model=effective_model)

    config = ScanConfig(
        target_id=target,
        provider=effective_provider,
        model=effective_model,
        max_llm_calls=max_llm_calls,
        max_concurrent=max_concurrent,
        output_dir=output_dir,
        dry_run=dry_run,
    )

    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=attack_modules,
        customiser=customiser,
        judge=judge,
    )

    result = asyncio.run(engine.run())

    if not dry_run:
        from mylonite.scan.artefacts import render_summary, write_artefacts

        scan_dir = write_artefacts(result, output_dir)
        typer.echo(render_summary(result))
        typer.echo(f"Artefacts: {scan_dir}")
    else:
        # Dry-run: render summary without writing files.
        from mylonite.scan.artefacts import render_summary

        typer.echo(render_summary(result))

    # C4 / G5: map aborted reason to distinct exit code.
    if result.report.aborted == "budget_exceeded":
        raise typer.Exit(code=EXIT_BUDGET)
    if result.report.aborted == "provider_unreachable":
        raise typer.Exit(code=EXIT_PROVIDER)
    raise typer.Exit(code=EXIT_SUCCESS)


@app.command()
def generate() -> None:
    """[v0.2 Phase 2] Generate a regression test from a confirmed exploit."""
    _not_implemented("generate")


@app.command()
def validate() -> None:
    """[v0.2 Phase 2] Run a generated test through the differential-oracle validator."""
    _not_implemented("validate")


@app.command()
def init() -> None:
    """[v0.3 Phase 3] Scaffold a Mylonite config in the current directory."""
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
