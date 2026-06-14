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
    """Inject the OS trust store for TLS (shared with the testkit/library path).

    Thin wrapper over :func:`mylonite._bootstrap.enable_truststore` so the CLI and
    an emitted test running under pytest set up TLS identically. Opt out with
    ``MYLONITE_NO_TRUSTSTORE=1``. Best-effort: a no-op if ``truststore`` is absent.
    """
    from mylonite._bootstrap import enable_truststore

    enable_truststore()


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


def _warn_unsupported_python() -> None:
    """S4: a clear note on Python 3.14+, where litellm has no wheels yet."""
    if sys.version_info >= (3, 14):
        typer.echo(
            "note: Mylonite supports Python 3.11-3.13. litellm has no 3.14 wheels "
            "yet, so live LLM calls may fail to import on this interpreter - use a "
            "3.11-3.13 virtualenv for scan/validate/demo --live.",
            err=True,
        )


def _provider_key_var_names() -> set[str]:
    from mylonite.scan.providers import PROVIDER_ENV_VARS

    return {var for variables in PROVIDER_ENV_VARS.values() for var in variables}


def _load_env_file(path: Path) -> None:
    """Load ONLY known provider API-key vars from a dotenv file — never blanket.

    Reads ``KEY=VALUE`` lines and sets a var when it is a known provider API-key
    env var (``providers.PROVIDER_ENV_VARS``), so a stray ``.env`` can't inject
    arbitrary environment. An explicitly-passed flag OVERRIDES an ambient value
    (standard CLI precedence: explicit > ambient — the exact case the flag exists
    for is a wrong key already in the shell), warning on stderr when it does.
    """
    if not path.exists():
        typer.echo(f"env file {path} not found.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    known = _provider_key_var_names()
    loaded: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip exactly one matching surrounding quote pair (dotenv convention) —
        # not every quote char, which would corrupt a value ending in a quote.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key not in known:
            continue
        if key in os.environ and os.environ[key] != value:
            typer.echo(
                f"warning: overriding ambient {key} with the value from {path}.",
                err=True,
            )
        os.environ[key] = value
        loaded.append(key)
    if loaded:
        typer.echo(f"loaded {', '.join(sorted(loaded))} from {path}.", err=True)


def _infer_key_env_var(key: str) -> str | None:
    """Best-effort provider env var for a bare API key, from its shape only."""
    if key.startswith("sk-ant-"):
        return "ANTHROPIC_API_KEY"
    if key.startswith("sk-"):
        return "OPENAI_API_KEY"
    if key.startswith("AKIA"):
        return "AWS_ACCESS_KEY_ID"
    return None


def _load_api_key_file(path: Path) -> None:
    """Load an API key from a file: a dotenv (KEY=VALUE lines) or a bare key.

    A bare key's provider is inferred from its shape; never printed.
    """
    if not path.exists():
        typer.echo(f"--api-key-file {path} not found.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    content = path.read_text(encoding="utf-8").strip()
    first = content.splitlines()[0] if content else ""
    if "=" in first:
        _load_env_file(path)
        return
    key = content.split()[0] if content else ""
    var = _infer_key_env_var(key)
    if var is None:
        typer.echo(
            "--api-key-file: couldn't infer the provider from the key shape. Use a "
            "dotenv file with a KEY=VALUE line instead (e.g. ANTHROPIC_API_KEY=…), "
            "or pass --env-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if var in os.environ and os.environ[var] != key:
        typer.echo(
            f"warning: overriding ambient {var} with the value from {path}.",
            err=True,
        )
    os.environ[var] = key
    typer.echo(f"loaded {var} from {path}.", err=True)


@app.callback()
def _root(
    api_key_file: Annotated[
        Path | None,
        typer.Option(
            "--api-key-file",
            help="Read an API key from a file (a bare key or a dotenv KEY=VALUE line).",
        ),
    ] = None,
    env_file: Annotated[
        Path | None,
        typer.Option(
            "--env-file",
            help="Load provider API-key vars from a .env file (only known key names).",
        ),
    ] = None,
) -> None:
    """Run before every command; normalise stdio + install secret redaction.

    The ``mylonite`` logger tree gets a secret-redacting filter so secret-shaped
    tokens never reach a log line (the ``LoggingConfig.redact_secrets`` default is
    True). The install is idempotent — safe to run on every invocation.
    """
    from mylonite._redaction import install_log_redaction

    _configure_stdio_encoding()
    _maybe_enable_truststore()
    install_log_redaction(enabled=True)
    _warn_unsupported_python()
    if env_file is not None:
        _load_env_file(env_file)
    if api_key_file is not None:
        _load_api_key_file(api_key_file)


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
    from mylonite._redaction import looks_like_api_key, redact
    from mylonite.scan.diagnostics import classify_provider_error
    from mylonite.scan.providers import env_vars_for, provider_from_model

    effective_provider = provider or "anthropic"
    base_model = model or "claude-sonnet-4-6"
    _validate_model_string(base_model)
    routed = _route_model(provider, base_model)
    resolved_provider = provider_from_model(routed, provider)

    # Warn (don't fail) if the resolved API key clearly isn't key-shaped — a common
    # footgun (placeholder, path, truncated paste). Never print the value itself.
    for var in env_vars_for(resolved_provider):
        val = os.environ.get(var)
        if val and not looks_like_api_key(val):
            typer.echo(
                f"warning: {var} is set but doesn't look like an API key "
                "(too short / contains spaces or path separators). Check it's the "
                "real key, not a placeholder or file path.",
                err=True,
            )

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
    from mylonite.plugins._mcp.target_file import build_target_spec, payload_placement_warnings

    # R7: warn (don't block) if the planted {payload} isn't a bare natural-language
    # leaf, or is missing entirely — a silently-empty/ill-formed plant otherwise
    # reads as a clean scan.
    for warning in payload_placement_warnings(target_file):
        typer.echo(f"warning: {warning}", err=True)

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
    if result.report.aborted == "wall_clock_timeout":
        # The scan hit its wall-clock budget before finishing. Coverage is
        # incomplete, so it must not exit 0 and read as a clean pass (same honesty
        # rule as no_payloads / describe_failed).
        typer.echo(
            "error: scan exceeded its wall-clock budget and stopped early; coverage "
            "is incomplete. Raise the timeout or narrow the scan, then re-run.",
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
    target_file: Annotated[
        Path | None,
        typer.Option(
            "--target-file",
            help=(
                "For a CUSTOM target: the same target YAML you scanned. Co-located "
                "next to the emitted test as target.yaml so the live test can re-drive "
                "your real app out of the box."
            ),
        ),
    ] = None,
) -> None:
    """Emit a pytest regression test from a confirmed exploit.

    Offline and deterministic — no LLM call. Reads an ``exploit_*.json`` (written
    by ``mylonite scan``), renders a testkit-based pytest file, and writes it next
    to a co-located copy of the exploit plus a ``fixtures/`` placeholder. For a
    CUSTOM target, pass ``--target-file`` so the target YAML is co-located as
    ``target.yaml`` (the live test needs it). Prints what to run next.
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

    # A custom-target test re-drives the REAL app, so it needs the target YAML
    # co-located as target.yaml. Co-locate it when given; otherwise warn loudly
    # (the test would fail at runtime without it). Reference tests replay the
    # bundled twin and need no target file.
    is_custom = not exploit.target_id.startswith("reference:")
    colocated_target: Path | None = None
    if target_file is not None:
        from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

        try:
            build_target_spec(load_target_file(target_file))  # validate before copying
        except Exception as exc:
            typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        colocated_target = out_dir / "target.yaml"
        # Copy the text verbatim so the operator's comments/structure survive.
        colocated_target.write_text(target_file.read_text(encoding="utf-8"), encoding="utf-8")
        typer.echo(f"Wrote target:  {colocated_target}")
    elif is_custom:
        typer.echo("")
        typer.echo(
            f"warning: {exploit.target_id} is a custom target - the emitted test re-drives "
            "your real app and needs a co-located target.yaml. Re-run with "
            "`--target-file <your-target>.yaml`, or copy your scan's target YAML into "
            f"{out_dir} as target.yaml. Without it the test errors at runtime.",
            err=True,
        )

    typer.echo("")
    if is_custom:
        # The custom test is LIVE (gated behind MYLONITE_LIVE_TARGET=1): it needs
        # pytest, a provider key, a runnable MCP server, and the co-located YAML.
        typer.echo("Next - this is a LIVE custom-target test. To run it you need:")
        typer.echo("  - pytest + mylonite installed in the consuming environment")
        typer.echo("  - your provider API key set (e.g. ANTHROPIC_API_KEY)")
        typer.echo("  - your target's MCP server runnable, and target.yaml co-located")
        typer.echo("Then:")
        typer.echo(f"  MYLONITE_LIVE_TARGET=1 pytest {out_dir}")
        typer.echo(f"  mylonite validate {out_dir} --target-file {out_dir / 'target.yaml'}")
    else:
        typer.echo(f"Next: mylonite validate {out_dir}")
    raise typer.Exit(code=EXIT_SUCCESS)


def _validate_custom(
    generated: Any,
    target_file: Path | None,
    iterations: int,
    provider: str,
    model: str,
    iteration_timeout_s: float | None = None,
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
        iteration_timeout_s=iteration_timeout_s,
        progress_cb=lambda msg: typer.echo(f"  … {msg}", err=True),
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
    iteration_timeout: Annotated[
        float | None,
        typer.Option(
            "--iteration-timeout",
            help=(
                "Per-scan wall-clock budget (seconds) for a CUSTOM-target run. A "
                "stuck or slow real target aborts that run cleanly instead of "
                "hanging open-ended; the loop still completes and reports."
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
            generated,
            target_file,
            iterations,
            effective_provider,
            effective_model,
            iteration_timeout_s=iteration_timeout,
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
            progress_cb=lambda msg: typer.echo(f"  … {msg}", err=True),
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


def _suggest_weakness_classes(tools: list[Any]) -> list[str]:
    """Heuristic weakness-class HINTS from a target's live tool surface.

    These are SUGGESTIONS for the operator to confirm/edit - never authoritative.
    Grounded in the bundled W1-W4 taxonomy and derived from the tool *schemas*
    (param shapes) first, with the tool name/description as a fallback hint only
    (no English keyword is load-bearing for a verdict — that lives in the scan's
    structural signals and the operator-declared effect probe).

    * W1 (tool-description instruction smuggling) + W2 (indirect injection):
      baseline for any tool-using agent that ingests external content.
    * W3 (SSRF / unrestricted egress): a tool taking a URL/endpoint-shaped input.
    * W4 (unconfirmed consequential action): a tool that mutates external state.
    """
    suggestions: set[str] = set()
    if tools:
        suggestions.update({"W1", "W2"})
    egress_hints = ("url", "uri", "endpoint", "fetch", "http", "request", "webhook")
    action_hints = (
        "send",
        "email",
        "post",
        "create",
        "delete",
        "write",
        "execute",
        "pay",
        "transfer",
        "purchase",
        "publish",
        "update",
        "remove",
        "issue",
        "commit",
    )
    for t in tools:
        blob = f"{getattr(t, 'name', '')} {getattr(t, 'description', '')}".lower()
        schema_text = str(getattr(t, "json_schema", "")).lower()
        if any(k in blob or k in schema_text for k in egress_hints):
            suggestions.add("W3")
        if any(k in blob for k in action_hints):
            suggestions.add("W4")
    return sorted(suggestions)


def _relative_sqlite_env_keys(env: dict[str, str]) -> list[str]:
    """Env keys whose value looks like a SQLite DB referenced by a NON-absolute
    path — the #18 Windows footgun (a relative sqlite path silently opens a
    different/empty DB, making a vulnerable agent look clean)."""
    flagged: list[str] = []
    for key, val in env.items():
        low = val.lower()
        if not ("sqlite" in low or low.endswith((".db", ".sqlite", ".sqlite3"))):
            continue
        if "://" in val:
            # URL form. The single '/' after the authority separator is NOT part
            # of the path, so `sqlite:///data.db` is RELATIVE `data.db` while
            # `sqlite:////abs/x.db` is absolute `/abs/x.db` — the exact #18 trap.
            after = val.split("://", 1)[1]
            path = after[1:] if after.startswith("/") else after
        else:
            path = val
        is_posix_abs = path.startswith("/")
        is_win_abs = len(path) >= 2 and path[1] == ":"  # C:\… or C:/…
        if not (is_posix_abs or is_win_abs):
            flagged.append(key)
    return flagged


@app.command(name="init-target")
def init_target(
    command: Annotated[
        str,
        typer.Option("--command", help="The MCP server launch command (e.g. 'python', 'node')."),
    ],
    arg: Annotated[
        list[str] | None,
        typer.Option("--arg", help="A server arg (repeatable, in order)."),
    ] = None,
    env: Annotated[
        list[str] | None,
        typer.Option("--env", help="A KEY=VALUE env var for the server (repeatable)."),
    ] = None,
    scope: Annotated[
        str | None,
        typer.Option("--scope", help="Optional scope label (must later match --authorize)."),
    ] = None,
    family: Annotated[
        str,
        typer.Option("--family", help="A short name for your target (used in report ids)."),
    ] = "custom",
    system_prompt_file: Annotated[
        Path | None,
        typer.Option("--system-prompt-file", help="Read the target's system prompt from a file."),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Where to write the scaffolded target YAML."),
    ] = Path("target.yaml"),
    model: Annotated[
        str | None,
        typer.Option(
            "--model", help="Model id used only to construct the adapter (no LLM call is made)."
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite the output file if it already exists."),
    ] = False,
) -> None:
    """Scaffold a custom-target YAML by launching your MCP server and listing its tools.

    Launches the server once (NO LLM call), introspects its tools, and writes a
    commented ``target.yaml`` starter with SUGGESTED ``weakness_classes`` /
    ``primary_tools`` and a ``seed_arm`` + ``effect_probe`` template for you to
    fill in. The suggestions are hints grounded in the bundled OWASP-LLM/ASI
    taxonomy — you own the consequential-capability + effect-probe declarations,
    so review and edit before scanning.
    """
    import yaml

    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import build_target_spec

    if output.exists() and not force:
        typer.echo(f"{output} already exists — pass --force to overwrite.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)

    tf = _target_file_from_flags(
        command=command,
        args=arg,
        env=env,
        scope=scope,
        system_prompt=None,
        system_prompt_file=system_prompt_file,
        primary_tools=None,
        weakness_classes=None,
    )
    # Allow a custom --family (the flag helper hardcodes 'custom').
    tf = tf.model_copy(update={"family": family})

    try:
        spec = build_target_spec(tf)
    except Exception as exc:
        typer.echo(f"invalid target flags: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    adapter = MCPStdioAdapter(
        family=spec.family, scope=tf.scope, model=model or "claude-haiku-4-5-20251001"
    )

    typer.echo(f"launching {command!r} to introspect its tools (no LLM call)…", err=True)
    try:
        descriptor = asyncio.run(adapter.describe())
    except Exception as exc:
        typer.echo(
            f"could not launch / introspect the MCP server: {exc}\n"
            "check --command/--arg/--env and that the server speaks MCP over stdio.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc

    tools = list(descriptor.tools)
    tool_names = [t.name for t in tools]
    suggested_weaknesses = _suggest_weakness_classes(tools)

    # #18 footgun: warn (do not block) on a relative SQLite DB path.
    for key in _relative_sqlite_env_keys(tf.env):
        typer.echo(
            f"warning: env {key}={tf.env[key]!r} looks like a relative SQLite path. "
            "On Windows a relative/ambiguous sqlite URL can open a DIFFERENT or empty "
            "DB, making a vulnerable agent look clean (#18). Prefer an absolute path.",
            err=True,
        )

    yaml_text = _render_target_scaffold(
        tf=tf,
        tool_names=tool_names,
        suggested_weaknesses=suggested_weaknesses,
        system_prompt_file=system_prompt_file,
    )

    # Round-trip-validate the scaffold we are about to write so it never lands broken.
    from mylonite.plugins._mcp.target_file import TargetFile

    try:
        TargetFile.model_validate(yaml.safe_load(yaml_text))
    except Exception as exc:  # pragma: no cover - defensive; the scaffold is fixed-shape
        typer.echo(f"internal error: scaffolded YAML failed validation: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    output.write_text(yaml_text, encoding="utf-8")
    typer.echo(f"wrote {output} — {len(tool_names)} tools discovered.")
    typer.echo(
        "  suggested weakness_classes "
        f"{suggested_weaknesses or '[]'} (hints — confirm/edit before scanning).",
        err=True,
    )
    typer.echo(
        "  next: fill in the seed_arm (how to plant untrusted content) and the "
        "effect_probe (how to confirm damage), then run "
        f"`mylonite scan mcp:custom --target-file {output} --authorize {family}`.",
        err=True,
    )


def _render_target_scaffold(
    *,
    tf: Any,
    tool_names: list[str],
    suggested_weaknesses: list[str],
    system_prompt_file: Path | None,
) -> str:
    """Render a commented, ready-to-edit ``target.yaml`` starter."""
    import yaml

    def _yaml_list(items: list[str]) -> str:
        return yaml.safe_dump(items, default_flow_style=True).strip()

    args_line = _yaml_list(list(tf.args)) if tf.args else "[]"
    env_block = ""
    if tf.env:
        # Dump as a proper YAML mapping so values with ':' (e.g. sqlite URLs) are
        # quoted/escaped correctly — never hand-roll per-value scalars.
        env_block = yaml.safe_dump({"env": dict(tf.env)}, default_flow_style=False)
    prompt_line = (
        f"system_prompt_file: {system_prompt_file}\n"
        if system_prompt_file is not None
        else '# system_prompt_file: prompt.txt   # or set system_prompt: "..." inline\n'
    )
    scope_line = f"scope: {tf.scope}\n" if tf.scope is not None else "# scope: my-scope\n"
    return f"""\
# Mylonite custom-target scaffold — generated by `mylonite init-target`.
# Review and EDIT before scanning: the suggestions below are hints, not gospel.
family: {tf.family}
command: {tf.command}
args: {args_line}
{env_block}{scope_line}{prompt_line}
# Discovered tools: {", ".join(tool_names) or "(none)"}.
# primary_tools narrows seed selection to your consequential tools (optional).
primary_tools: {_yaml_list(tool_names) if tool_names else "[]"}

# Weakness classes this target exposes (SUGGESTED — confirm/edit):
#   W1 tool-description instruction smuggling · W2 indirect injection
#   W3 unrestricted egress / SSRF · W4 unconfirmed consequential action
weakness_classes: {_yaml_list(suggested_weaknesses) if suggested_weaknesses else "[]"}

# How to plant untrusted content for indirect-injection (W2) seeds. Point this
# at the tool that ingests external content; {{payload}} is replaced per attempt.
# seed_arm:
#   tool: <tool that stores/accepts untrusted content>
#   args_template: {{ body: "{{payload}}" }}   # {{payload}} at a bare string leaf
#   id_key: id                                 # JSON field holding the new handle
#                                              # (or id_pattern: a regex; or id_from)

# How to CONFIRM the damage materialised end-to-end (the effect probe). After the
# attack, re-query the target and check the damaging side effect is present.
# effect_probe:
#   verify_tool: <tool that reports the side effect>
#   verify_args_template: {{}}
#   expect_marker: "<a string proving the effect, e.g. the attacker recipient>"
#   deferred_markers: ["queued for approval", "pending review"]  # mark a DEFENDED result
"""


@app.command()
def gate(
    target: Annotated[
        str | None,
        typer.Argument(
            help=(
                "Target ID: 'reference:vulnerable' / 'reference:guarded', a "
                "bundled 'mcp:<family>[:<scope>]', or 'mcp:custom'. "
                "Omit when using --target-file. Non-reference targets require --authorize."
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
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help="Required for non-reference targets; assert ownership of the target.",
        ),
    ] = None,
    open_pr: Annotated[
        bool,
        typer.Option(
            "--open-pr",
            help="Push a branch and open the gating PR via gh (opt-in).",
        ),
    ] = False,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LiteLLM provider, e.g. 'anthropic' or 'openai'."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model identifier passed to LiteLLM."),
    ] = None,
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory for gate artefacts."),
    ] = Path(".mylonite/gate"),
    max_llm_calls: Annotated[
        int,
        typer.Option("--max-llm-calls", help="Process-wide LLM call cap for the scan phase."),
    ] = 50,
    llm_enrich: Annotated[
        bool,
        typer.Option(
            "--llm-enrich",
            help="Append a labelled, unverified LLM fix suggestion to the PR body.",
        ),
    ] = False,
) -> None:
    """Scan -> generate -> validate -> (optionally) open a gating PR. The magic moment."""
    from mylonite.gate import pr as pr_mod
    from mylonite.gate import run_gate
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )

    effective_provider = provider or "anthropic"
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    # v0.2 attack families — same filter as the scan command.
    _v0_2_ATTACK_FAMILIES = {"prompt-injection-family", "excessive-agency-family"}

    # --- resolve adapter (mirrors scan command routing) ---
    is_reference = bool(target and target.startswith("reference:"))
    tf = None

    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp — enforce --authorize BEFORE loading the file,
        # exactly as scan does.
        if not authorize:
            typer.echo("--authorize is required for custom targets. See SECURITY.md.", err=True)
            raise typer.Exit(code=EXIT_CONFIG)
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:
                typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
                raise typer.Exit(code=EXIT_CONFIG) from exc
        else:
            # mcp:custom with inline flags — not supported via gate (no --command etc.)
            typer.echo(
                "gate --target-file <yaml> is the custom-target path; "
                "inline mcp:custom flags are not wired in `gate`. "
                "Pass a target YAML via --target-file.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_custom(tf, authorize, effective_model)
    elif target is None:
        typer.echo(
            "no target given. Pass a target (e.g. reference:vulnerable) or --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    elif is_reference:
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
            "Expected 'reference:<variant>', 'mcp:<family>[:<scope>]', or --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # --- closures injected into run_gate ---

    def scan_fn() -> list[Any]:
        from mylonite.plugins.registry import discover
        from mylonite.scan.customiser import PayloadCustomiser
        from mylonite.scan.engine import ScanConfig, ScanEngine
        from mylonite.scan.judge import SuccessJudge

        try:
            all_modules: list[Any] = discover("mylonite.attack_modules")
        except Exception as exc:
            typer.echo(f"plugin discovery failed: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        attack_modules = [m for m in all_modules if m.attack_metadata().id in _v0_2_ATTACK_FAMILIES]
        if not attack_modules:
            typer.echo(
                "no usable attack modules discovered "
                "(looking for 'prompt-injection-family' or 'excessive-agency-family')",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)

        config = ScanConfig(
            target_id=target if target is not None else f"mcp:{tf.family if tf else 'custom'}",
            provider=effective_provider,
            model=effective_model,
            max_llm_calls=max_llm_calls,
        )
        engine = ScanEngine(
            config=config,
            adapter=adapter,
            attack_modules=attack_modules,
            customiser=PayloadCustomiser(model=effective_model),
            judge=SuccessJudge(model=effective_model),
        )
        result = asyncio.run(engine.run())
        return result.exploits

    def generate_fn(exploit: Any) -> Any:
        return ReferencePytestGenerator().emit(exploit)

    def validate_fn(generated: Any) -> Any:
        if is_reference:
            validator = DifferentialValidator(
                provider=effective_provider,
                model=effective_model,
                record_fixtures_dir=out / "fixtures",
            )
            return validator.validate(
                generated,
                ReferenceVulnerableOracle().adapter(),
                ReferenceVulnerableOracle(),
            )
        # Custom target: mirror _validate_custom — re-drive the REAL target.
        if tf is None:
            typer.echo(
                "internal: expected a loaded TargetFile for custom validate_fn",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
        from mylonite.plugins._mcp.target_file import build_target_spec

        spec = build_target_spec(tf)
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)

        def _factory() -> Any:
            return MCPStdioAdapter(family=spec.family, scope=tf.scope, model=effective_model)

        validator = DifferentialValidator(
            iterations=1,
            provider=effective_provider,
            model=effective_model,
            target_adapter_factory=_factory,
        )
        return validator.validate(generated, _factory(), ReferenceVulnerableOracle())

    def open_pr_fn(*, out_dir: Path, exploit: Any, report: Any, body: str, open_pr: bool) -> Any:
        if target_file is not None:
            (out_dir / "target.yaml").write_text(
                target_file.read_text(encoding="utf-8"), encoding="utf-8"
            )
        repo_root = Path.cwd()
        paths = pr_mod.GatePaths(repo_root=repo_root, gate_dir=out_dir, workflow_files=[])
        return pr_mod.open_or_print_pr(
            paths,
            branch=f"mylonite/gate-{exploit.pattern_id}",
            pr_title=f"Mylonite gate: {exploit.pattern_id}",
            pr_body=body,
            open_pr=open_pr,
        )

    result = run_gate(
        out_dir=out,
        scan_fn=scan_fn,
        generate_fn=generate_fn,
        validate_fn=validate_fn,
        open_pr_fn=open_pr_fn,
        open_pr=open_pr,
        llm_enrich=llm_enrich,
    )
    raise typer.Exit(code=result.exit_code)


@app.command()
def init() -> None:
    """Deprecated alias — use `mylonite init-target` to scaffold a target YAML."""
    typer.echo(
        "`mylonite init` is now `mylonite init-target` — it scaffolds a custom-target "
        "YAML by launching your MCP server. Run `mylonite init-target --help`.",
        err=True,
    )
    raise typer.Exit(code=EXIT_CONFIG)


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
