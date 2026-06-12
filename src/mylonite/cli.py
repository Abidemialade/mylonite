"""Typer CLI for Mylonite.

Phase 1 (v0.2) lights up ``mylonite scan``:

* ``mylonite version`` — print the package version.
* ``mylonite taxonomy list --framework <id>`` — list entries from a bundled
  threat taxonomy.
* ``mylonite scan <target> [--provider --model --dry-run ...]`` — run the
  exploit-finding loop against a target. Phase 1 ships in-process reference
  targets only (``reference:vulnerable`` / ``reference:guarded``). Real
  out-of-process MCP adapters arrive in Phase 1.5/2.

Phase 2 (v0.2) lights up ``mylonite generate`` and ``mylonite validate``:

* ``mylonite generate [SCAN_PATH] [--latest] [--out DIR]`` — emit a pytest
  regression test from a confirmed exploit (offline, deterministic, no LLM).
* ``mylonite validate TARGET [--iterations N]`` — run a generated test through
  the differential-oracle validator (live by default — real LLM, Haiku).

``init`` remains a stub (Phase 3 work).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
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
EXIT_NOT_KEPT = 5


def _maybe_enable_truststore() -> None:
    """Use the OS trust store for TLS when ``truststore`` is installed.

    Enterprise environments behind a TLS-inspecting proxy present a CA that the
    OS trusts but Python's bundled certifi does not — so provider calls fail
    ``CERTIFICATE_VERIFY_FAILED``. ``truststore`` (an optional ``[enterprise]``
    extra) bridges to the OS trust store without disabling verification. Opt out
    with ``MYLONITE_NO_TRUSTSTORE=1``. Best-effort: absent/failed import is a
    silent no-op (verification stays at certifi defaults).
    """
    if os.environ.get("MYLONITE_NO_TRUSTSTORE"):
        return
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:  # not installed, or injection unsupported → leave defaults
        pass


def _configure_stdio_encoding() -> None:
    """Force UTF-8 on stdout/stderr before any Rich/typer output.

    Rich renders the scan/demo tables with non-ASCII glyphs (✓ ✗ ⚠ —). On a
    Windows console defaulting to cp1252 those raise ``UnicodeEncodeError`` and
    crash the command mid-render. ``errors="replace"`` keeps output alive if a
    stream still can't encode something. No-op where ``reconfigure`` is absent
    (e.g. pytest's captured streams).
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            # stream already detached/closed → leave it as-is rather than crash.
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


@app.callback()
def _root() -> None:
    """Run before every command; normalise stdio + install secret redaction.

    The ``mylonite`` logger tree gets a secret-redacting filter so secret-shaped
    tokens never reach a log line (the ``LoggingConfig.redact_secrets`` default is
    True). The install is idempotent — safe to run on every invocation.
    """
    from mylonite._redaction import install_log_redaction

    _configure_stdio_encoding()
    _maybe_enable_truststore()
    install_log_redaction(enabled=True)


class _Framework(StrEnum):
    OWASP_LLM = "owasp-llm"
    OWASP_ASI = "owasp-asi"
    ATLAS = "atlas"
    NIST = "nist"


@app.command()
def version() -> None:
    """Print the installed Mylonite version."""
    typer.echo(__version__)


@app.command()
def doctor(
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LiteLLM provider to check, e.g. 'anthropic'."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model id to ping (defaults to claude-sonnet-4-6)."),
    ] = None,
) -> None:
    """Diagnose provider connectivity before a live scan.

    Makes one tiny (1-token) completion call and classifies any failure as
    **auth** vs **TLS** vs **network** vs **rate-limit**, each with a concrete
    remedy — so a corporate-proxy cert failure no longer looks like a bad key.
    Exit 0 if reachable, 4 on a provider failure.
    """
    from mylonite._redaction import redact
    from mylonite.scan.diagnostics import classify_provider_error
    from mylonite.scan.providers import provider_from_model

    effective_provider = provider or "anthropic"
    base_model = model or "claude-sonnet-4-6"
    _validate_model_string(base_model)
    routed = _route_model(provider, base_model)
    resolved_provider = provider_from_model(routed, provider)

    import litellm

    try:
        litellm.completion(
            model=routed,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
    except Exception as exc:  # one-shot probe — classify, don't propagate raw
        diag = classify_provider_error(exc, provider=resolved_provider)
        typer.echo(f"provider check FAILED [{diag.category}] for {routed}", err=True)
        typer.echo(f"  detail: {redact(diag.detail)}", err=True)
        typer.echo(f"  remedy: {diag.remedy}", err=True)
        raise typer.Exit(code=EXIT_PROVIDER) from exc
    typer.echo(f"provider OK — {effective_provider}/{base_model} reachable (routed: {routed}).")


def _not_implemented(name: str) -> None:
    typer.echo(
        f"`{name}` is not implemented in v{__version__}. "
        "It arrives in a later release — see ROADMAP.md and the issue tracker.",
        err=True,
    )
    raise typer.Exit(code=EXIT_CONFIG)


def _validate_model_string(model: str) -> None:
    """Reject obviously-malformed model ids before they reach LiteLLM."""
    if not model or not model.strip() or model != model.strip():
        typer.echo(
            f"invalid --model {model!r}: must be a non-empty model id with no "
            "surrounding whitespace, e.g. claude-sonnet-4-6 or claude-haiku-4-5.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)


def _route_model(provider: str | None, model: str) -> str:
    """Apply LiteLLM ``provider/model`` routing when the user set --provider.

    LiteLLM routes by model-string prefix; some Anthropic aliases (e.g.
    ``claude-3-5-haiku-latest``) aren't auto-routed and fail with "LLM Provider
    NOT provided". When the user explicitly passes ``--provider`` and the model
    carries no ``provider/`` prefix yet, prefix it so the alias routes. When
    ``--provider`` is unset we leave the model untouched, preserving the
    auto-routing the bundled ``claude-*`` defaults already rely on.
    """
    if provider and "/" not in model:
        return f"{provider}/{model}"
    return model


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


def _enforce_custom_authorize(
    family: str, scope: str | None, requires_scope: bool, authorize: str | None
) -> None:
    """Apply the same --authorize rule custom targets share with bundled ones."""
    if requires_scope:
        if authorize != scope:
            typer.echo(
                f"--authorize must equal the scope for {family!r} "
                f"(scope={scope!r}, authorize={authorize!r}).",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
    elif authorize != family:
        typer.echo(
            f"--authorize must equal the family name {family!r} for this stateless "
            f"custom target (got authorize={authorize!r}).",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)


def _target_file_from_flags(
    *,
    command: str | None,
    args: list[str] | None,
    env: list[str] | None,
    scope: str | None,
    system_prompt: str | None,
    system_prompt_file: Path | None,
    primary_tools: list[str] | None,
    weakness_classes: list[str] | None,
) -> Any:
    """Assemble a ``TargetFile`` (family='custom') from ``mcp:custom`` CLI flags."""
    from pydantic import ValidationError

    from mylonite.plugins._mcp.target_file import TargetFile

    if not command:
        typer.echo("mcp:custom requires --command (the MCP server launch command).", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    env_map: dict[str, str] = {}
    for item in env or []:
        if "=" not in item:
            typer.echo(f"--env must be KEY=VALUE; got {item!r}.", err=True)
            raise typer.Exit(code=EXIT_CONFIG)
        key, _, value = item.partition("=")
        env_map[key] = value
    try:
        return TargetFile(
            family="custom",
            command=command,
            args=list(args or []),
            env=env_map,
            scope=scope,
            requires_scope=scope is not None,
            system_prompt=system_prompt,
            system_prompt_file=system_prompt_file,
            primary_tools=list(primary_tools or []),
            weakness_classes=list(weakness_classes or []),
        )
    except ValidationError as exc:
        typer.echo(f"invalid custom target: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _build_adapter_for_custom(target_file: Any, authorize: str | None, model: str) -> Any:
    """Register a custom ``TargetFile`` and return a generic ``MCPStdioAdapter``.

    Shared by ``--target-file`` and ``mcp:custom`` flags. Enforces the same
    ``--authorize`` ownership rule as bundled targets, then registers the spec
    so the generic adapter (and seed selection) can resolve it.
    """
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import build_target_spec

    spec = build_target_spec(target_file)
    _enforce_custom_authorize(spec.family, target_file.scope, spec.requires_scope, authorize)
    try:
        # Start from a clean runtime registry so a long-lived/embedding process
        # that calls scan() repeatedly can't accumulate or shadow stale custom
        # specs (each scan registers exactly the target it's running).
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)
        target_registry.resolve_target(spec.family, target_file.scope)
    except (
        target_registry.InvalidTargetScope,
        target_registry.UnknownTargetFamily,
        ValueError,
    ) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    return MCPStdioAdapter(family=spec.family, scope=target_file.scope, model=model)


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
                f"(scope={scope!r}, authorize={authorize!r}). "
                f"Example: mylonite scan mcp:{family}:{scope or '<scope>'} "
                f"--authorize {scope or '<scope>'}",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
    elif authorize != family:
        typer.echo(
            f"--authorize must equal the family name for stateless target "
            f"{family!r} (got authorize={authorize!r}). "
            f"Example: mylonite scan mcp:{family} --authorize {family}",
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
        str | None,
        typer.Argument(
            help=(
                "Target ID: 'reference:vulnerable' / 'reference:guarded', a "
                "bundled 'mcp:<family>[:<scope>]' (filesystem/fetch/github), or "
                "'mcp:custom' with --command/--arg flags. Omit when using "
                "--target-file. Non-reference targets require --authorize."
            )
        ),
    ] = None,
    target_file: Annotated[
        Path | None,
        typer.Option(
            "--target-file",
            help="Path to a custom-target YAML (declares command/args/weakness_classes/seed_arm).",
        ),
    ] = None,
    command: Annotated[
        str | None,
        typer.Option("--command", help="mcp:custom — the MCP server launch command."),
    ] = None,
    arg: Annotated[
        list[str] | None,
        typer.Option("--arg", help="mcp:custom — a server arg (repeatable, in order)."),
    ] = None,
    env: Annotated[
        list[str] | None,
        typer.Option("--env", help="mcp:custom — a KEY=VALUE env var for the server (repeatable)."),
    ] = None,
    scope: Annotated[
        str | None,
        typer.Option("--scope", help="mcp:custom — optional scope label (must match --authorize)."),
    ] = None,
    system_prompt: Annotated[
        str | None,
        typer.Option("--system-prompt", help="mcp:custom — the target's system prompt (inline)."),
    ] = None,
    system_prompt_file: Annotated[
        Path | None,
        typer.Option(
            "--system-prompt-file", help="mcp:custom — read the system prompt from a file."
        ),
    ] = None,
    primary_tool: Annotated[
        list[str] | None,
        typer.Option("--primary-tool", help="mcp:custom — a primary tool name (repeatable)."),
    ] = None,
    weakness_class: Annotated[
        list[str] | None,
        typer.Option(
            "--weakness-class",
            help="mcp:custom — a weakness class the target exposes, e.g. W2/W4 (repeatable).",
        ),
    ] = None,
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
    base_model = model or "claude-sonnet-4-6"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp (both YAML and inline flags converge here).
        if not authorize:
            typer.echo("--authorize is required for custom targets. See SECURITY.md.", err=True)
            raise typer.Exit(code=EXIT_CONFIG)
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:  # YAML / validation errors → exit 2
                typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
                raise typer.Exit(code=EXIT_CONFIG) from exc
        else:
            tf = _target_file_from_flags(
                command=command,
                args=arg,
                env=env,
                scope=scope,
                system_prompt=system_prompt,
                system_prompt_file=system_prompt_file,
                primary_tools=primary_tool,
                weakness_classes=weakness_class,
            )
        adapter = _build_adapter_for_custom(tf, authorize, effective_model)
        report_target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
    elif target is None:
        typer.echo(
            "no target given. Pass a target (e.g. reference:vulnerable) or --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_model)
        report_target_id = target
    elif target.startswith("mcp:"):
        if not authorize:
            typer.echo(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_mcp(target, authorize, effective_model)
        report_target_id = target
    else:
        typer.echo(
            f"unknown target shape {target!r}. "
            "Expected 'reference:<variant>', 'mcp:<family>[:<scope>]', 'mcp:custom', "
            "or --target-file.",
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
        target_id=report_target_id,
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

    from mylonite._redaction import redact

    if not dry_run:
        from mylonite.scan.artefacts import render_summary, write_artefacts

        # Persist artefacts UN-redacted (they are loadable/replayable data); only
        # the console-rendered summary string is redacted before display.
        scan_dir = write_artefacts(result, output_dir)
        typer.echo(redact(render_summary(result)))
        typer.echo(f"Artefacts: {scan_dir}")
    else:
        # Dry-run: render summary without writing files.
        from mylonite.scan.artefacts import render_summary

        typer.echo(redact(render_summary(result)))

    # C4 / G5: map aborted reason to distinct exit code.
    if result.report.aborted == "budget_exceeded":
        raise typer.Exit(code=EXIT_BUDGET)
    if result.report.aborted == "provider_unreachable":
        raise typer.Exit(code=EXIT_PROVIDER)
    if result.report.aborted == "no_payloads":
        # Issue #3: nothing ran — a misconfigured/unknown target must not look
        # like a clean pass. Point the user at the on-ramp for custom targets.
        typer.echo(
            "error: no seeds were applicable to this target, so nothing was scanned. "
            "If this is a custom MCP app, declare which weakness classes it exposes "
            "via --target-file (weakness_classes) or --weakness-class.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if result.report.aborted == "describe_failed":
        # The adapter couldn't describe the target (e.g. the MCP server failed to
        # launch). Zero attempts ran — must not exit 0 and read as a clean pass.
        typer.echo(
            "error: could not describe the target (adapter.describe() failed); "
            "nothing was scanned. Check the target command/scope and connectivity.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
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

    # Build a fresh Console here (not the module-level _console, which was
    # constructed at import before the callback reconfigured stdout to UTF-8).
    render_demo(
        result.vulnerable,
        result.guarded,
        mode=result.mode,
        elapsed_s=result.elapsed_s,
        console=Console(),
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


def _slugify_pattern(pattern_id: str) -> str:
    """Filesystem-safe slug for a default ``--out`` dir (mirrors the generator)."""
    return "".join(ch if ch.isalnum() else "_" for ch in pattern_id).strip("_") or "exploit"


def _find_latest_scan_dir(scans_root: Path) -> Path | None:
    """Return the newest ``<ts>/`` subdir under ``scans_root`` (lexical = chronological).

    Scan dirs are ISO-timestamped (``write_artefacts``), so the lexically-greatest
    name is the most recent. Returns ``None`` if the root is absent or empty.
    """
    if not scans_root.is_dir():
        return None
    candidates = sorted((p for p in scans_root.iterdir() if p.is_dir()), reverse=True)
    return candidates[0] if candidates else None


def _exploit_in_dir(scan_dir: Path) -> Path | None:
    """First (sorted) ``exploit_*.json`` inside ``scan_dir``, or ``None``."""
    matches = sorted(scan_dir.glob("exploit_*.json"))
    return matches[0] if matches else None


def _resolve_exploit_path(scan_path: Path | None, latest: bool, scans_root: Path) -> Path:
    """Resolve the exploit JSON to generate from (F1 — no path archaeology).

    Precedence: an explicit ``scan_path`` (an ``exploit_*.json`` file *or* a scan
    dir containing one), else ``--latest`` (newest scan dir under ``scans_root``).
    Exits 2 with actionable guidance when nothing resolves.
    """
    if scan_path is not None:
        if scan_path.is_file():
            return scan_path
        if scan_path.is_dir():
            found = _exploit_in_dir(scan_path)
            if found is not None:
                return found
            typer.echo(
                f"no exploit_*.json found in {scan_path}. "
                "Run `mylonite scan <target>` first, or pass an exploit_*.json directly.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        typer.echo(
            f"path not found: {scan_path}. Pass a scan dir or an exploit_*.json, "
            "or run `mylonite scan <target>` first.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    if latest:
        scan_dir = _find_latest_scan_dir(scans_root)
        if scan_dir is None:
            typer.echo(
                f"no scans found under {scans_root}. Run `mylonite scan <target>` first.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        found = _exploit_in_dir(scan_dir)
        if found is None:
            typer.echo(
                f"the latest scan ({scan_dir}) found no exploits — nothing to generate. "
                "Run `mylonite scan <target>` against a vulnerable target first.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        return found

    typer.echo(
        "no input given. Pass a SCAN_PATH (an exploit_*.json or a scan dir), or "
        "--latest to use the newest scan under .mylonite/scans/. Run "
        "`mylonite scan <target>` first if you have no scans yet.",
        err=True,
    )
    raise typer.Exit(code=EXIT_CONFIG)


@app.command()
def generate(
    scan_path: Annotated[
        Path | None,
        typer.Argument(
            help=(
                "An exploit_*.json file OR a scan dir containing one. Omit and "
                "pass --latest to use the newest scan under .mylonite/scans/."
            ),
        ),
    ] = None,
    latest: Annotated[
        bool,
        typer.Option("--latest", help="Use the newest scan under .mylonite/scans/."),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            help="Output dir for the emitted test (default .mylonite/generated/<slug>/).",
        ),
    ] = None,
) -> None:
    """Emit a pytest regression test from a confirmed exploit.

    Offline and deterministic — no LLM call. Reads an ``exploit_*.json`` (written
    by ``mylonite scan``), renders a testkit-based pytest file, and writes it next
    to a co-located copy of the exploit plus a ``fixtures/`` placeholder. Prints
    the exact ``mylonite validate`` command to run next.
    """
    import json

    from mylonite import testkit
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
    )

    scans_root = Path(".mylonite/scans")
    exploit_path = _resolve_exploit_path(scan_path, latest, scans_root)

    try:
        exploit = testkit.load_exploit(exploit_path)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"could not load exploit at {exploit_path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    generated = ReferencePytestGenerator().emit(exploit)

    out_dir = (
        out
        if out is not None
        else Path(".mylonite/generated") / _slugify_pattern(exploit.pattern_id)
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    test_path = out_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")

    # Co-locate the exploit under the exact name the emitted test loads
    # (`load_exploit(here / "exploit_<pattern_id>.json")`).
    colocated_exploit = out_dir / f"exploit_{exploit.pattern_id}.json"
    colocated_exploit.write_text(
        json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    fixtures_dir = out_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Wrote test:    {test_path}")
    typer.echo(f"Wrote exploit: {colocated_exploit}")
    typer.echo(f"Fixtures dir:  {fixtures_dir}")
    typer.echo("")
    typer.echo(f"Next: mylonite validate {out_dir}")
    raise typer.Exit(code=EXIT_SUCCESS)


def _validate_custom(
    generated: Any, target_file: Path | None, iterations: int, provider: str, model: str
) -> Any:
    """Validate a custom-target test by re-driving the REAL target (R1/R8)."""
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )

    if target_file is None:
        typer.echo(
            "validating a custom-target test requires --target-file (the same target "
            "YAML you scanned); the validator re-drives the real target.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)

    def _factory() -> Any:
        return MCPStdioAdapter(family=spec.family, scope=tf.scope, model=model)

    typer.echo(
        f"validate re-drives the REAL target {spec.family!r} live — {iterations} runs "
        "+ multi-judge consensus + effect probe (no in-repo twin).",
        err=True,
    )
    validator = DifferentialValidator(
        iterations=iterations,
        provider=provider,
        model=model,
        target_adapter_factory=_factory,
    )
    return validator.validate(generated, _factory(), ReferenceVulnerableOracle())


def _locate_generated(target: Path) -> tuple[Path, Path]:
    """Locate ``(test_security_*.py, exploit_*.json)`` for a validate TARGET.

    ``target`` is the generated dir (or the test file inside it). Both the test
    and the co-located exploit are required. Exits 2 with guidance when either is
    missing.
    """
    if target.is_file():
        gen_dir = target.parent
    elif target.is_dir():
        gen_dir = target
    else:
        typer.echo(
            f"target not found: {target}. Pass the dir (or test file) emitted by "
            "`mylonite generate`.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    exploit_matches = sorted(gen_dir.glob("exploit_*.json"))
    if not exploit_matches:
        typer.echo(
            f"no exploit_*.json found in {gen_dir}. Re-run `mylonite generate` to "
            "emit a test + its co-located exploit.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    test_matches = sorted(gen_dir.glob("test_security_*.py"))
    if not test_matches:
        typer.echo(
            f"no test_security_*.py found in {gen_dir}. Re-run `mylonite generate`.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    return test_matches[0], exploit_matches[0]


def _render_validation_report(report: Any) -> None:
    """Render a per-leg Rich report (F4): one row per ValidationOutcome.

    Uses a FRESH Console (UTF-8 already forced by the root callback). Shows the
    pass/✗ mark, the stage's metric, and its detail; then the mutation-score
    headline and the overall kept verdict; plus a remediation line per failed
    gating leg when the test was rejected.
    """
    console = Console()
    table = Table(
        title=f"Mylonite validate — {report.test_filename}",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("leg", no_wrap=True)
    table.add_column("result", no_wrap=True)
    table.add_column("metric", no_wrap=True)
    table.add_column("detail")

    for outcome in report.outcomes:
        mark = "✓ pass" if outcome.passed else "✗ FAIL"
        metric = f"{outcome.metric:.2f}" if outcome.metric is not None else "-"
        table.add_row(outcome.stage, mark, metric, outcome.detail)

    console.print(table)

    if report.mutation_score is not None:
        console.print(f"mutation score: {report.mutation_score:.2f}")

    if report.kept:
        console.print("[green]verdict: KEPT — the test discriminates and is stable.[/green]")
    else:
        console.print("[red]verdict: REJECTED — the test was not kept.[/red]")
        _remediation = {
            "build": "build fail → emitted test didn't collect; re-run `mylonite generate`.",
            "differential": "differential fail → no discriminating power between the twins.",
            "flakiness": "flakiness fail → exploit too flaky to gate; try a more deterministic seed.",
            "stability": "stability fail → the attack did not reproduce against the real target.",
            "effect": "effect fail → the target's effect probe did not confirm the damage materialised.",
            "consensus": "consensus fail → judges disagreed the effect was real; add an effect_probe.",
        }
        for outcome in report.outcomes:
            if not outcome.passed and outcome.stage in _remediation:
                console.print(f"[red]  remediation: {_remediation[outcome.stage]}[/red]")


def _provider_preflight(provider: str, model: str) -> bool:
    """Cheap reachability probe before the (expensive) live validation loop.

    Runs ONE vulnerable reference scan. If it aborts ``provider_unreachable``,
    the validator's N-iteration loop would too — so we fail fast with a distinct
    exit 4 rather than burning iterations and reporting a misleading non-discrim
    result. Returns True iff the provider is reachable.
    """
    from mylonite.scan.wiring import build_scan, note_id_counter

    engine = build_scan(
        "vulnerable",
        completion_fn=None,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
    )
    result = asyncio.run(engine.run())
    return result.report.aborted != "provider_unreachable"


@app.command()
def validate(
    target: Annotated[
        Path,
        typer.Argument(
            help=(
                "The dir (or test file) emitted by `mylonite generate`. Runs the "
                "differential-oracle validator LIVE by default — real LLM calls "
                "(Haiku): ~5 iterations x 2 twins, roughly a minute and a few "
                "cents. Needs a provider (ANTHROPIC_API_KEY)."
            ),
        ),
    ],
    iterations: Annotated[
        int,
        typer.Option(
            "--iterations",
            help="Differential/flakiness iterations (each runs both twins). Default 5.",
        ),
    ] = 5,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LiteLLM provider for the live validation run."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model for the live validation run."),
    ] = None,
    target_file: Annotated[
        Path | None,
        typer.Option(
            "--target-file",
            help=(
                "Required when validating a test for a CUSTOM target: the same "
                "target YAML you scanned. The validator re-drives the REAL target "
                "(N runs + multi-judge consensus + effect probe) instead of the "
                "bundled twin, so the test fails when YOUR app regresses."
            ),
        ),
    ] = None,
) -> None:
    """Run a generated test through the differential-oracle validator (LIVE).

    Runs LIVE by default: ~``iterations`` iterations x 2 twins against a real LLM
    (Haiku) — roughly a minute and a few cents — and needs a provider
    (ANTHROPIC_API_KEY). Validates the ACTUAL committed test on disk (no
    re-emit), then — on a clean discriminating run — RECORDS the canonical guarded
    fixtures into the generated dir's ``fixtures/`` and runs that on-disk test
    offline as a full-pass build, so the command leaves a ready-to-commit,
    replayable test + fixtures behind. Renders a per-leg report (build /
    differential / flakiness / metamorphic) with the mutation score and the kept
    verdict. Exit 0 when the test is kept, 5 when it is cleanly rejected, 4 with
    no provider.
    """
    from mylonite import testkit

    effective_provider = provider or "anthropic"
    effective_model = model or "claude-haiku-4-5-20251001"

    test_path, exploit_path = _locate_generated(target)

    try:
        exploit = testkit.load_exploit(exploit_path)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"could not load exploit at {exploit_path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # The validator transitively imports mcp_kitchen_sink (via the reference
    # adapter / wiring). Map its absence to the same friendly exit-2 the demo
    # command uses.
    try:
        from mylonite.contracts import GeneratedTest
        from mylonite.plugins._reference.reference_validator import (
            DifferentialValidator,
            ReferenceVulnerableOracle,
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

    # Validate the ACTUAL committed test on disk (NOT a re-render) — so a live
    # `mylonite validate` records canonical fixtures next to it and proves the
    # very file the user will commit passes offline.
    on_disk_source = test_path.read_text(encoding="utf-8")
    generated = GeneratedTest(
        framework="pytest",
        filename=test_path.name,
        source=on_disk_source,
        exploit=exploit,
    )

    is_custom = not exploit.target_id.startswith("reference:")
    if is_custom:
        report = _validate_custom(
            generated, target_file, iterations, effective_provider, effective_model
        )
    else:
        typer.echo(
            f"validate runs ~{iterations} iterations x 2 twins live (Haiku) — roughly a "
            "minute, a few cents; needs a provider (ANTHROPIC_API_KEY).",
            err=True,
        )
        # Fail fast on an unreachable provider with a distinct exit 4 — otherwise
        # the full loop would just report a misleading non-discriminating result.
        try:
            reachable = _provider_preflight(effective_provider, effective_model)
        except (ModuleNotFoundError, ImportError) as exc:
            if (getattr(exc, "name", "") or "").split(".")[0] == "mcp_kitchen_sink":
                typer.echo(
                    "the Quarry reference target isn't installed — run "
                    "`pip install -e ./reference_targets/mcp_kitchen_sink` from the checkout.",
                    err=True,
                )
                raise typer.Exit(code=EXIT_CONFIG) from exc
            raise
        if not reachable:
            typer.echo(
                "no provider reachable — set ANTHROPIC_API_KEY, or pass "
                "--provider/--model for another LiteLLM provider.",
                err=True,
            )
            raise typer.Exit(code=EXIT_PROVIDER)

        validator = DifferentialValidator(
            iterations=iterations,
            provider=effective_provider,
            model=effective_model,
            # Record the canonical guarded fixtures into the gen dir's `fixtures/`
            # and run the on-disk committed test offline as a full-pass build —
            # closing the validate→committed-artefact loop.
            record_fixtures_dir=test_path.parent / "fixtures",
        )
        report = validator.validate(
            generated,
            ReferenceVulnerableOracle().adapter(),
            ReferenceVulnerableOracle(),
        )

    _render_validation_report(report)

    if report.kept:
        raise typer.Exit(code=EXIT_SUCCESS)
    raise typer.Exit(code=EXIT_NOT_KEPT)


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
