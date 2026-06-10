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
        "It arrives in a later release — see ROADMAP.md and the issue tracker.",
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


def _parse_mcp_target(target: str) -> tuple[str, str | None]:
    """Split ``mcp:<family>`` or ``mcp:<family>:<scope>`` into ``(family, scope)``.

    The scope segment is everything after the second colon — owner/repo for
    github, absolute path for filesystem, optional label for fetch. Splits
    at most twice so scopes carrying their own ``:`` (e.g. Windows
    ``C:\\sandbox``) survive intact.
    """
    parts = target.split(":", 2)
    if len(parts) < 2 or parts[0] != "mcp":
        msg = f"expected mcp:<family>[:<scope>]; got {target!r}"
        raise ValueError(msg)
    family = parts[1]
    scope: str | None = parts[2] if len(parts) == 3 else None
    return family, scope


def _build_adapter_for_mcp(target: str, authorize: str | None, model: str) -> Any:
    """Resolve ``mcp:`` target into a bundled adapter, enforcing scope-matched ``--authorize``.

    Validation order:
    1. Parse ``mcp:<family>[:<scope>]``.
    2. Validate ``--authorize`` matches: scope-required families need
       ``authorize == scope``; stateless families need ``authorize == family``.
    3. Resolve the family in the registry (validates scope shape).
    4. Construct the right bundled subclass.

    Each failure → typer.Exit(EXIT_CONFIG) with a user-actionable message.
    """
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import (
        FetchMCPAdapter,
        FilesystemMCPAdapter,
        GitHubMCPAdapter,
    )

    try:
        family, scope = _parse_mcp_target(target)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Step 2: --authorize scope-match check.
    if family not in target_registry.BUNDLED_TARGETS:
        typer.echo(
            f"unknown MCP target family {family!r}. "
            f"Known families: {sorted(target_registry.BUNDLED_TARGETS)}.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    spec = target_registry.BUNDLED_TARGETS[family]
    if spec.requires_scope:
        if authorize != scope:
            typer.echo(
                f"--authorize must equal the scope segment for {family!r} "
                f"(scope={scope!r}, authorize={authorize!r}).",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
    else:
        if authorize != family:
            typer.echo(
                f"--authorize must equal the family name for stateless target "
                f"{family!r} (got authorize={authorize!r}).",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)

    # Step 3: registry resolution (validates scope shape).
    try:
        target_registry.resolve_target(family, scope)
    except (target_registry.InvalidTargetScope, target_registry.UnknownTargetFamily) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Step 4: construct the right subclass.
    if family == "filesystem":
        return FilesystemMCPAdapter(scope=scope or "", model=model)
    if family == "fetch":
        return FetchMCPAdapter(scope=scope, model=model)
    if family == "github":
        return GitHubMCPAdapter(scope=scope or "", model=model)
    # Unreachable — the registry check above already gated unknown families.
    typer.echo(f"no subclass wired for family {family!r}", err=True)
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
    # Resolve provider + model with sensible defaults so dry-run doesn't require
    # a live LLM provider configured.
    effective_provider = provider or "anthropic"
    effective_model = model or "claude-sonnet-4-6"

    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    if target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_model)
    elif target.startswith("mcp:"):
        if not authorize:
            typer.echo(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_mcp(target, authorize, effective_model)
    else:
        typer.echo(
            f"unknown target shape {target!r}. "
            "Expected 'reference:<variant>' or 'mcp:<family>[:<scope>]'.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

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
def demo(
    live: Annotated[
        bool,
        typer.Option(
            "--live",
            help=(
                "Make real LLM calls instead of replaying recorded fixtures. "
                "Runs the exploit loop twice (vulnerable + guarded), capped at "
                "max_llm_calls=100 per variant. Takes roughly a minute and costs "
                "a few cents on Haiku pricing (well under $0.05). Needs a "
                "provider configured (ANTHROPIC_API_KEY by default)."
            ),
        ),
    ] = False,
    provider: Annotated[
        str | None,
        typer.Option(
            "--provider",
            help="LiteLLM provider for --live runs. Ignored in replay mode (pinned to anthropic).",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help=(
                "Model for --live runs. Ignored in replay mode "
                "(pinned to claude-haiku-4-5-20251001)."
            ),
        ),
    ] = None,
) -> None:
    """Run the zero-config Quarry playground: vulnerable vs guarded differential.

    Default (offline replay) replays recorded fixtures — no network, no API key,
    deterministic. Pass --live to make real LLM calls against the in-process
    reference agent. A --live run executes the exploit loop twice (vulnerable +
    guarded), capped at max_llm_calls=100 per variant; it takes roughly a minute
    and costs a few cents (approximate, well under $0.05 on Haiku pricing).
    """
    from mylonite.demo._replay import CorruptFixtureError, MissingFixtureError
    from mylonite.demo.render import render_demo

    # The runner import transitively pulls in mcp_kitchen_sink (runner ->
    # reference_target_adapter -> mcp_kitchen_sink._store), which installs
    # separately. Map its absence to the same friendly exit-2 message here, at
    # import time, before any of the import's symbols are referenced below.
    try:
        from mylonite.demo.runner import (
            DEMO_MODEL,
            DEMO_PROVIDER,
            DemoFixtureError,
            run_demo,
        )
    except (ModuleNotFoundError, ImportError) as exc:
        if (getattr(exc, "name", "") or "").split(".")[0] == "mcp_kitchen_sink":
            typer.echo(
                "the Quarry reference target isn't installed — run "
                "`pip install -e ./reference_targets/mcp_kitchen_sink` from the checkout.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG) from exc
        raise

    # Replay is pinned to the recorded provider/model — never silently drop the
    # override flags.
    if not live and (provider is not None or model is not None):
        typer.echo(
            "warning: --provider/--model are ignored in replay mode — the demo "
            f"replays fixtures recorded against {DEMO_PROVIDER}/{DEMO_MODEL} "
            "(claude-haiku-4-5-20251001). Pass --live to use a different "
            "provider/model.",
            err=True,
        )

    try:
        result = asyncio.run(run_demo(live=live, provider=provider, model=model))
    except (MissingFixtureError, DemoFixtureError) as exc:
        typer.echo(
            "demo fixtures missing or stale — reinstall mylonite, or run "
            "`mylonite demo --live` with a provider configured. "
            f"{exc}",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except CorruptFixtureError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except (ModuleNotFoundError, ImportError) as exc:
        if getattr(exc, "name", None) == "mcp_kitchen_sink":
            typer.echo(
                "the Quarry reference target isn't installed — run "
                "`pip install -e ./reference_targets/mcp_kitchen_sink` from the checkout.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG) from exc
        raise

    render_demo(
        result.vulnerable,
        result.guarded,
        mode=result.mode,
        elapsed_s=result.elapsed_s,
        console=_console,
    )

    # A --live run can abort cleanly (the engine returns rather than raises);
    # surface those as distinct exit codes. Replay never aborts this way.
    for variant in (result.vulnerable, result.guarded):
        if variant.report.aborted == "provider_unreachable":
            typer.echo(
                "no provider reachable — set ANTHROPIC_API_KEY, or pass "
                "--provider/--model for another LiteLLM provider.",
                err=True,
            )
            raise typer.Exit(code=EXIT_PROVIDER)
        if variant.report.aborted == "budget_exceeded":
            typer.echo(
                "demo budget exceeded before both variants completed "
                "(max_llm_calls=100 per variant).",
                err=True,
            )
            raise typer.Exit(code=EXIT_BUDGET)

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
