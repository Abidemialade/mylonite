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

from mylonite.scan.tool_roles import _classify_tools, _ToolRoles
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

_V0_2_ATTACK_FAMILIES = frozenset({"prompt-injection-family", "excessive-agency-family"})


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
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config. Fills provider/model when "
                "you omit the flags, so `doctor` pings the SAME model your scan will "
                "use; an explicit flag always wins."
            ),
        ),
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

    # Mirror `scan`: fill provider/model from mylonite.yaml when the flags are
    # omitted, so `doctor` checks the same model the scan will actually use
    # rather than silently falling back to the default.
    if run_config_path is not None:
        from mylonite.config import load_run_config

        try:
            rc = load_run_config(run_config_path)
        except Exception as exc:
            typer.echo(f"invalid --config {run_config_path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        provider = provider or rc.provider
        model = model or rc.model

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


#: Default LLM-call budget for an active ``--adaptive`` scan. The single-shot
#: default (50) aborts a multi-seed adaptive run mid-way — each seed can spend
#: ~10-15 calls across its retry budget (customise + plant/drive/judge, then up
#: to DEFAULT_MAX_ATTEMPTS strategist refinements). 200 clears a full 8-seed run.
ADAPTIVE_DEFAULT_MAX_LLM_CALLS = 200

#: The untouched default of the ``--max-llm-calls`` option; only this exact value
#: is treated as "not set by the user" (an explicit value, even 50, is honoured).
_DEFAULT_MAX_LLM_CALLS = 50


def _adaptive_budget(max_llm_calls: int, *, adaptive_active: bool) -> tuple[int, bool]:
    """Auto-size the LLM-call budget for an active adaptive run.

    Returns ``(budget, raised)``. When the adaptive loop is active and the budget
    is the untouched default, raise it to ``ADAPTIVE_DEFAULT_MAX_LLM_CALLS`` so the
    run doesn't silently abort partway through; any explicit value (flag or
    mylonite.yaml) — including a deliberately low one — is respected unchanged.
    """
    if adaptive_active and max_llm_calls == _DEFAULT_MAX_LLM_CALLS:
        return ADAPTIVE_DEFAULT_MAX_LLM_CALLS, True
    return max_llm_calls, False


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


def _run_synthesis(
    *,
    target: str | None,
    target_file: Path | None = None,
    authorize: str | None = None,
    provider: str,
    model: str,
    planner_model: str,
    customiser_model: str,
    judge_model: str,
    output_dir: Path,
) -> None:
    """Driver 2 flow: synthesize a tool-chain and differentially validate it, then
    write the validated finding as scan artefacts.

    For a reference target the differential uses the bundled twins; for a custom
    ``--target-file`` it uses the SYNTHETIC guarded twin (raw vs a W2 boundary-
    guarded variant via the control shim), reusing the control-efficacy machinery.
    Uses the live provider for the planner/strategist/synthesizer.
    """
    is_reference = bool(target and target.startswith("reference:"))
    if not is_reference and target_file is None:
        typer.echo(
            "--synthesize needs a reference twin target (e.g. reference:vulnerable) or a "
            "custom --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    from mylonite.contracts._types import ScanAttempt, ScanReport
    from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
    from mylonite.scan.artefacts import render_summary, write_artefacts
    from mylonite.scan.chain_synth import ChainSynthesizer
    from mylonite.scan.chain_validator import ChainDifferentialValidator
    from mylonite.scan.engine import ScanResult
    from mylonite.scan.judge import SuccessJudge
    from mylonite.scan.synthesis_runner import SynthesisRunner

    if is_reference:
        report_target = target or "reference:vulnerable"

        def factory(variant: str) -> Any:
            return InProcessReferenceAdapter(variant=variant, model=planner_model)  # type: ignore[arg-type]

        descriptor = asyncio.run(InProcessReferenceAdapter(variant="vulnerable").describe())
    else:
        if not authorize:
            typer.echo("--authorize is required to synthesize against a custom target.", err=True)
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
        from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

        try:
            tf = load_target_file(target_file)  # type: ignore[arg-type]
            spec = build_target_spec(tf)
        except Exception as exc:
            typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)
        report_target = target or f"mcp:{spec.family}"
        typer.echo(
            f"--synthesize on custom target {spec.family!r}: validating the chain raw vs a "
            "W2 boundary-guarded twin (the synthetic guarded side).",
            err=True,
        )

        if spec.vulnerable_launch is not None:
            typer.echo(
                f"--synthesize: the raw side launches the DELIBERATELY-UNGUARDED variant of "
                f"{spec.family!r} (vulnerable_launch) — ensure you are authorized. "
                "Env values are never logged.",
                err=True,
            )

        def factory(variant: str) -> Any:
            if variant == "vulnerable":
                return _vulnerable_adapter(spec, tf.scope, planner_model)
            return MCPStdioAdapter(
                family=spec.family,
                scope=tf.scope,
                model=planner_model,
                controls=[_boundary_control("W2", spec)],
            )

        descriptor = asyncio.run(
            MCPStdioAdapter(family=spec.family, scope=tf.scope, model=planner_model).describe()
        )

    runner = SynthesisRunner(
        synthesizer=ChainSynthesizer(model=customiser_model),
        validator=ChainDifferentialValidator(
            adapter_factory=factory,
            judge=SuccessJudge(model=judge_model),
            strategist_model=customiser_model,
        ),
        target_id=report_target,
    )
    try:
        result = asyncio.run(runner.run(descriptor))
    finally:
        if not is_reference:
            from mylonite.plugins._mcp import target_registry

            target_registry.clear_runtime_targets()

    exploits = [result.exploit] if result.exploit is not None else []
    if result.chain is None:
        attempts = [
            ScanAttempt(
                seed_id="tool-chaining-synthesis",
                pattern_id="tool-chaining-synthesis",
                outcome="no_finding",
                verdict_reason="no plant+sink pair discoverable on the tool surface",
            )
        ]
    else:
        pid = f"synthesized-chain-{result.chain.sink_tool}"
        attempts = [
            ScanAttempt(
                seed_id=pid,
                pattern_id=pid,
                outcome="finding" if result.exploit is not None else "no_finding",
                verdict_reason=(
                    result.exploit.success_reason
                    if result.exploit is not None
                    else "synthesized chain did not differentially validate"
                ),
            )
        ]
    report = ScanReport(
        target_id=report_target,
        attack_modules=["tool-chaining-synthesis"],
        provider=provider,
        model=model,
        elapsed_seconds=0.0,
        attempts=attempts,
        findings_count=len(exploits),
        inconclusive_attempts=0,
        fallback_breakdown={},
        aborted=None,
        single_run=False,
        mylonite_version=__version__,
    )
    scan_result = ScanResult(report=report, exploits=exploits)

    from mylonite._redaction import redact

    scan_dir = write_artefacts(scan_result, output_dir)
    typer.echo(redact(render_summary(scan_result)))
    typer.echo(f"Artefacts: {scan_dir}")
    if exploits:
        typer.echo("")
        typer.echo(f"Next: mylonite generate {scan_dir}")


def _run_memory_poison(
    *,
    target: str | None,
    target_file: Path | None = None,
    authorize: str | None = None,
    provider: str,
    model: str,
    planner_model: str,
    judge_model: str,
    output_dir: Path,
) -> None:
    """T1 flow: plant poison, let it PERSIST across a benign turn, then drive a later
    retrieval that surfaces and acts on it — differentially validated against the twins.

    Mirrors ``--synthesize``: a reference target uses the bundled twins; a custom
    ``--target-file`` uses the SYNTHETIC W2 boundary-guarded twin (the control shim),
    so the differential proves the *memory* control — quarantining recalled content —
    is load-bearing. The poison is planted once and retrieved a turn later, modelling
    the cross-session slow-drip ("zombie agent") shape single-turn scans miss.
    """
    is_reference = bool(target and target.startswith("reference:"))
    if not is_reference and target_file is None:
        typer.echo(
            "--memory needs a reference twin target (e.g. reference:vulnerable) or a "
            "custom --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    from mylonite.contracts._types import ScanAttempt, ScanReport
    from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
    from mylonite.scan.artefacts import render_summary, write_artefacts
    from mylonite.scan.engine import ScanResult
    from mylonite.scan.judge import SuccessJudge
    from mylonite.scan.memory_poison import MemoryPoisonRunner
    from mylonite.scan.seeds import SEED_CATALOGUE

    seed = next(s for s in SEED_CATALOGUE if s.pattern_id == "indirect-injection-note-body-direct")
    # One innocent turn between the plant and the retrieval, so the poison is acted on
    # in a later turn than it was planted (the defining memory-poisoning separation).
    benign_turns = ("Please give me a brief status update on my recent activity.",)

    if is_reference:
        report_target = target or "reference:vulnerable"

        def factory(variant: str) -> Any:
            return InProcessReferenceAdapter(variant=variant, model=planner_model)  # type: ignore[arg-type]

        descriptor = asyncio.run(InProcessReferenceAdapter(variant="vulnerable").describe())
    else:
        if not authorize:
            typer.echo(
                "--authorize is required to test memory poisoning against a custom target.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
        from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

        try:
            tf = load_target_file(target_file)  # type: ignore[arg-type]
            spec = build_target_spec(tf)
        except Exception as exc:
            typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)
        report_target = target or f"mcp:{spec.family}"
        typer.echo(
            f"--memory on custom target {spec.family!r}: validating raw vs a W2 boundary-"
            "guarded twin (the synthetic guarded side quarantines recalled memory).",
            err=True,
        )
        if spec.vulnerable_launch is not None:
            typer.echo(
                f"--memory: the raw side launches the DELIBERATELY-UNGUARDED variant of "
                f"{spec.family!r} (vulnerable_launch) — ensure you are authorized. "
                "Env values are never logged.",
                err=True,
            )

        def factory(variant: str) -> Any:
            if variant == "vulnerable":
                return _vulnerable_adapter(spec, tf.scope, planner_model)
            return MCPStdioAdapter(
                family=spec.family,
                scope=tf.scope,
                model=planner_model,
                controls=[_boundary_control("W2", spec)],
            )

        descriptor = asyncio.run(
            MCPStdioAdapter(family=spec.family, scope=tf.scope, model=planner_model).describe()
        )

    runner = MemoryPoisonRunner(
        adapter_factory=factory,
        judge=SuccessJudge(model=judge_model),
        seed=seed,
        target_id=report_target,
        benign_turns=benign_turns,
    )
    try:
        result = asyncio.run(runner.run(descriptor))
    finally:
        if not is_reference:
            from mylonite.plugins._mcp import target_registry

            target_registry.clear_runtime_targets()

    exploits = [result.exploit] if result.exploit is not None else []
    if result.plan is None:
        attempts = [
            ScanAttempt(
                seed_id="memory-poisoning",
                pattern_id="memory-poisoning",
                outcome="no_finding",
                verdict_reason=(
                    "no plant+retrieve surface discoverable for cross-turn memory poisoning"
                ),
            )
        ]
    else:
        pid = result.exploit.pattern_id if result.exploit is not None else "memory-poisoning"
        attempts = [
            ScanAttempt(
                seed_id=pid,
                pattern_id=pid,
                outcome="finding" if result.exploit is not None else "no_finding",
                verdict_reason=(
                    result.exploit.success_reason
                    if result.exploit is not None
                    else "cross-turn memory poisoning did not differentially validate"
                ),
            )
        ]
    report = ScanReport(
        target_id=report_target,
        attack_modules=["memory-poisoning"],
        provider=provider,
        model=model,
        elapsed_seconds=0.0,
        attempts=attempts,
        findings_count=len(exploits),
        inconclusive_attempts=0,
        fallback_breakdown={},
        aborted=None,
        single_run=False,
        mylonite_version=__version__,
    )
    scan_result = ScanResult(report=report, exploits=exploits)

    from mylonite._redaction import redact

    scan_dir = write_artefacts(scan_result, output_dir)
    typer.echo(redact(render_summary(scan_result)))
    typer.echo(f"Artefacts: {scan_dir}")
    if exploits:
        typer.echo("")
        typer.echo(f"Next: mylonite generate {scan_dir}")


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
    planner_model: Annotated[
        str | None,
        typer.Option(
            "--planner-model",
            help=(
                "Override the model that DRIVES the agent-under-test (the planner). "
                "Defaults to --model. An aligned planner refuses injection even on a "
                "vulnerable target; point this at a representatively exploitable model "
                "to keep the attack class testable."
            ),
        ),
    ] = None,
    customiser_model: Annotated[
        str | None,
        typer.Option(
            "--customiser-model",
            help="Override the model that crafts/refines attack payloads. Defaults to --model.",
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help="Override the model for the LLM-judge verdict. Defaults to --model.",
        ),
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
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config (target_file / authorize / "
                "provider / model / max_llm_calls). Fills any flag you omit; an "
                "explicit flag always wins."
            ),
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Enumerate seeds; skip customisation + invocation."),
    ] = False,
    allow_no_seed_arm: Annotated[
        bool,
        typer.Option(
            "--allow-no-seed-arm",
            help=(
                "Scan a custom target that declares an indirect-injection weakness "
                "class (e.g. W2) without a seed_arm. Those seeds will report NOT "
                "TESTED rather than block the scan. Off by default so a misconfig "
                "never reads as clean."
            ),
        ),
    ] = False,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive",
            help=(
                "Opt-in adaptive attack loop: for indirect-injection seeds, plant "
                "the payload, drive the planner, and on failure re-craft the "
                "injection and retry within a budget (needs a session-capable "
                "target, e.g. reference:*). Off by default; the single-shot path "
                "is unchanged."
            ),
        ),
    ] = False,
    verbose_strategist: Annotated[
        bool,
        typer.Option(
            "--verbose-strategist",
            help=(
                "With --adaptive, echo each refinement round live (the injection "
                "tried, the planner's tool calls, and why it failed) so the "
                "strategist's reasoning is observable, not just an attempt count. "
                "Payloads are redacted before display."
            ),
        ),
    ] = False,
    synthesize: Annotated[
        bool,
        typer.Option(
            "--synthesize",
            help=(
                "Opt-in Driver 2 tool-chaining synthesis: synthesize an "
                "app-specific multi-tool exploit chain from the tool surface, then "
                "differentially validate it against the twins (needs a reference "
                "twin target, e.g. reference:vulnerable). Off by default."
            ),
        ),
    ] = False,
    memory: Annotated[
        bool,
        typer.Option(
            "--memory",
            help=(
                "Opt-in stateful memory-poisoning test: plant poison, let it persist "
                "across a benign turn, then drive a later retrieval that surfaces and "
                "acts on it — the cross-session slow-drip ('zombie agent') shape. "
                "Differentially validated against the twins (reference, or a custom "
                "--target-file's synthetic W2-guarded twin). Off by default."
            ),
        ),
    ] = False,
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help="Required for non-reference targets; assert ownership of the target.",
        ),
    ] = None,
) -> None:
    """Run the exploit-finding loop against a target.

    Exit codes: 0 ok; 2 config/usage error (incl. nothing scanned); 3 budget
    exceeded; 4 provider unreachable. A clean exit 0 means the scan ran - an
    aborted/empty scan exits non-zero so it never reads as a clean pass.
    """
    # Declarative run config (mylonite.yaml): fill any flag the user omitted so a
    # custom-target run isn't a wall of repeated flags. An explicit flag wins.
    if run_config_path is not None:
        from mylonite.config import load_run_config

        try:
            rc = load_run_config(run_config_path)
        except Exception as exc:
            typer.echo(f"invalid --config {run_config_path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        if max_llm_calls == 50 and rc.max_llm_calls is not None:
            # 50 is the option default; only the config overrides an untouched flag.
            max_llm_calls = rc.max_llm_calls

    # Resolve provider + model with sensible defaults so dry-run doesn't require
    # a live LLM provider configured.
    effective_provider = provider or "anthropic"
    base_model = model or "claude-sonnet-4-6"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    # Role-separated models: each defaults to the base model. Validate + route
    # any explicit override exactly like --model.
    def _resolve_role_model(override: str | None) -> str:
        if not override:
            return effective_model
        _validate_model_string(override)
        return _route_model(provider, override)

    effective_planner_model = _resolve_role_model(planner_model)
    effective_customiser_model = _resolve_role_model(customiser_model)
    effective_judge_model = _resolve_role_model(judge_model)

    # Driver 2: tool-chaining synthesis is a distinct flow (synthesize -> twin
    # differential validation), not the per-seed engine. Branch early and return.
    if synthesize and memory:
        typer.echo("--synthesize and --memory are distinct flows; pass only one.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)
    if synthesize:
        _run_synthesis(
            target=target,
            target_file=target_file,
            authorize=authorize,
            provider=effective_provider,
            model=effective_model,
            planner_model=effective_planner_model,
            customiser_model=effective_customiser_model,
            judge_model=effective_judge_model,
            output_dir=output_dir,
        )
        return

    # T1: stateful cross-turn memory poisoning is a distinct flow (plant -> persist ->
    # retrieve, twin-differentially validated), not the per-seed engine. Branch and return.
    if memory:
        _run_memory_poison(
            target=target,
            target_file=target_file,
            authorize=authorize,
            provider=effective_provider,
            model=effective_model,
            planner_model=effective_planner_model,
            judge_model=effective_judge_model,
            output_dir=output_dir,
        )
        return

    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    # For a custom target we persist the resolved target YAML next to the scan
    # (below, after artefacts are written) so `generate`/`validate` can re-resolve
    # it without the operator re-passing --target-file at every step.
    custom_target_yaml: str | None = None
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
        from mylonite.plugins._mcp.target_file import (
            dump_target_file,
            infer_seed_arm,
            needs_seed_arm_autowire,
            validate_for_scan,
        )

        # M3: auto-wire the seed_arm from the LIVE tool surface when a W2 target omits
        # it, so a real app needs near-zero config instead of the hard block below.
        # Only when a no-id recall path exists (else the plant wouldn't be delivered —
        # the "plants but never lands" trap). Best-effort: a describe failure leaves the
        # pre-flight block to handle it. Skipped on --dry-run / --allow-no-seed-arm.
        if needs_seed_arm_autowire(tf) and not dry_run and not allow_no_seed_arm:
            try:
                _probe = _build_adapter_for_custom(tf, authorize, effective_planner_model)
                _descriptor = asyncio.run(asyncio.wait_for(_probe.describe(), timeout=20))
            except Exception as exc:
                _descriptor = None
                typer.echo(
                    f"auto-wire: could not describe the target to infer a seed_arm "
                    f"({type(exc).__name__}); falling back to the pre-flight check.",
                    err=True,
                )
            if _descriptor is not None:
                _spec, _note = infer_seed_arm(_descriptor.tools)
                typer.echo(f"auto-wire: {_note}", err=True)
                if _spec is not None:
                    tf = tf.model_copy(update={"seed_arm": _spec})

        # Blocking pre-flight (PR3): a target declaring an indirect-injection-only
        # weakness class with no seed_arm would silently skip those seeds and read
        # as clean. Block a REAL scan with a fix hint unless --allow-no-seed-arm is
        # set (or M3 auto-wired one above). A --dry-run only enumerates seeds (no
        # clean/finding verdict to mislead), so there we downgrade the block to a warning.
        preflight_errors = validate_for_scan(tf, allow_no_seed_arm=allow_no_seed_arm)
        if preflight_errors:
            for err in preflight_errors:
                level = "warning" if dry_run else "error"
                typer.echo(f"{level}: {err}", err=True)
            if not dry_run:
                raise typer.Exit(code=EXIT_CONFIG)

        # Copy the source YAML verbatim (preserves operator comments/structure)
        # when given a file; otherwise serialise the inline mcp:custom flags so the
        # exact target is reproducible from the scan dir alone.
        custom_target_yaml = (
            target_file.read_text(encoding="utf-8")
            if target_file is not None
            else dump_target_file(tf)
        )
        adapter = _build_adapter_for_custom(tf, authorize, effective_planner_model)
        report_target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
    elif target is None:
        typer.echo(
            "no target given. Pass a target (e.g. reference:vulnerable) or --target-file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_planner_model)
        report_target_id = target
    elif target.startswith("mcp:"):
        if not authorize:
            typer.echo(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_mcp(target, authorize, effective_planner_model)
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
    attack_modules = [m for m in all_modules if m.attack_metadata().id in _V0_2_ATTACK_FAMILIES]
    if not attack_modules:
        typer.echo(
            "no usable attack modules discovered "
            "(looking for 'prompt-injection-family' or 'excessive-agency-family')",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    customiser = PayloadCustomiser(model=effective_customiser_model)
    judge = SuccessJudge(model=effective_judge_model)

    # Adaptive loop is opt-in. Build the driver only when asked; warn (don't
    # fail) if the chosen target can't open sessions, so --adaptive degrades to
    # the single-shot path instead of erroring.
    from mylonite.contracts.target_adapter import SupportsAttackSession

    attack_driver = None
    if adaptive:
        if isinstance(adapter, SupportsAttackSession):
            from mylonite._redaction import redact
            from mylonite.scan.attack_loop import AdaptiveAttackDriver, AttemptStep

            def _echo_step(step: AttemptStep) -> None:
                status = "FOUND" if step.success else "failed"
                typer.echo(
                    f"  strategist round {step.attempt}: {status} — "
                    f"{redact(step.reason)[:160]} | tools={list(step.tool_calls)} | "
                    f"injection={redact(step.injection)[:120]}",
                    err=True,
                )

            attack_driver = AdaptiveAttackDriver(
                judge=judge,
                strategist_model=effective_customiser_model,
                on_step=_echo_step if verbose_strategist else None,
            )
        else:
            typer.echo(
                "note: --adaptive ignored — this target does not support multi-step "
                "sessions; using the single-shot path.",
                err=True,
            )

    # Auto-size the budget for an active adaptive run so it doesn't abort mid-way
    # on the single-shot default (the assessment's seed-3-of-8 abort). An explicit
    # --max-llm-calls (or mylonite.yaml) always wins.
    max_llm_calls, _budget_raised = _adaptive_budget(
        max_llm_calls, adaptive_active=adaptive and attack_driver is not None
    )
    if _budget_raised:
        typer.echo(
            f"--adaptive: raised the LLM-call budget to {max_llm_calls} (the default "
            f"{_DEFAULT_MAX_LLM_CALLS} aborts a multi-seed adaptive run mid-way). "
            "Pass --max-llm-calls to override.",
            err=True,
        )

    config = ScanConfig(
        target_id=report_target_id,
        provider=effective_provider,
        model=effective_model,
        planner_model=effective_planner_model if planner_model else None,
        customiser_model=effective_customiser_model if customiser_model else None,
        judge_model=effective_judge_model if judge_model else None,
        max_llm_calls=max_llm_calls,
        max_concurrent=max_concurrent,
        output_dir=output_dir,
        dry_run=dry_run,
        adaptive=adaptive and attack_driver is not None,
    )

    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=attack_modules,
        customiser=customiser,
        judge=judge,
        attack_driver=attack_driver,
    )

    result = asyncio.run(engine.run())

    from mylonite._redaction import redact

    if not dry_run:
        from mylonite.scan.artefacts import render_summary, write_artefacts

        # Persist artefacts UN-redacted (they are loadable/replayable data); only
        # the console-rendered summary string is redacted before display.
        scan_dir = write_artefacts(result, output_dir)
        # Co-locate the resolved target YAML so `generate`/`validate` auto-resolve
        # it from the scan dir — the custom-target journey needs the path ONCE.
        if custom_target_yaml is not None:
            (scan_dir / "target.yaml").write_text(custom_target_yaml, encoding="utf-8")
        typer.echo(redact(render_summary(result)))
        typer.echo(f"Artefacts: {scan_dir}")
        # "Next:" hint — point at the very next command so the flow is self-guiding.
        if result.report.findings_count > 0:
            typer.echo("")
            typer.echo(f"Next: mylonite generate {scan_dir}")
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


def _exploits_in_dir(scan_dir: Path) -> list[Path]:
    """All (sorted) ``exploit_*.json`` inside ``scan_dir``."""
    return sorted(scan_dir.glob("exploit_*.json"))


def _resolve_exploit_paths(scan_path: Path | None, latest: bool, scans_root: Path) -> list[Path]:
    """Resolve ALL exploit JSONs to generate from (F1 — no path archaeology).

    Precedence: an explicit ``scan_path`` (an ``exploit_*.json`` file *or* a scan
    dir), else ``--latest`` (newest scan dir under ``scans_root``). A scan dir
    yields *every* ``exploit_*.json`` it contains — so a multi-finding scan emits
    one test per finding instead of silently dropping all but the
    alphabetically-first. Exits 2 with actionable guidance when nothing resolves.
    """
    if scan_path is not None:
        if scan_path.is_file():
            return [scan_path]
        if scan_path.is_dir():
            found = _exploits_in_dir(scan_path)
            if found:
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
        found = _exploits_in_dir(scan_dir)
        if not found:
            typer.echo(
                f"the latest scan ({scan_dir}) found no exploits — nothing to generate. "
                "A no-finding scan is a PASS, not an error: it usually means the target "
                "is clean or guarded. To generate from an earlier scan that DID find "
                "something, pass that scan dir explicitly, e.g. "
                "`mylonite generate .mylonite/scans/<earlier-run>`.",
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


def _map_compliance(exploit: Any) -> Any:
    """Enrich a finding's compliance tags via the reference mapper (derives NIST
    from the OWASP tags using the bundled taxonomy cross-refs)."""
    from mylonite.plugins._reference.reference_compliance_mapper import ReferenceComplianceMapper

    return exploit.model_copy(update={"compliance": ReferenceComplianceMapper().map(exploit)})


def _emit_generated_test(
    exploit: Any,
    exploit_path: Path,
    out_dir: Path,
    target_file: Path | None,
    *,
    json_mod: Any,
) -> None:
    """Emit one regression test (+ co-located exploit/fixtures/target) for one
    exploit, echoing the per-test ``Wrote …`` lines and next-step guidance.

    Factored out of :func:`generate` so a multi-finding scan dir can emit one
    test per finding into per-pattern subdirs. The single-exploit output is
    unchanged.
    """
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
    )

    # Enrich compliance ONCE (derives NIST from the OWASP cross-refs) and use the
    # SAME enriched record for both the emitted test's marks and the co-located
    # exploit JSON. Writing the raw record here left the persisted exploit (what
    # `mylonite report` reads) without the NIST tags the marks carried — the
    # marks-vs-report inconsistency from the v0.7.0 assessment.
    enriched = _map_compliance(exploit)
    generated = ReferencePytestGenerator().emit(enriched)
    out_dir.mkdir(parents=True, exist_ok=True)

    test_path = out_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")

    # Co-locate the exploit under the exact name the emitted test loads
    # (`load_exploit(here / "exploit_<pattern_id>.json")`).
    colocated_exploit = out_dir / f"exploit_{enriched.pattern_id}.json"
    colocated_exploit.write_text(
        json_mod.dumps(enriched.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
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
    # Auto-resolve the target YAML co-located with the scan (written by `scan`) so
    # the operator needn't re-pass --target-file at every step. An explicit
    # --target-file always wins.
    if target_file is None and is_custom:
        candidate = exploit_path.parent / "target.yaml"
        if candidate.is_file():
            target_file = candidate
            typer.echo(f"Using target:  {candidate} (from the scan dir)")
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
        # validate auto-resolves the co-located target.yaml — no --target-file needed.
        typer.echo(f"  mylonite validate {out_dir}")
    else:
        typer.echo(f"Next: mylonite validate {out_dir}")


def _tag_control_for_generate(exploit: Any) -> Any:
    """Stamp ``synthetic_control`` so the generator emits an ``assert_control_holds``
    test (``generate --prove-control``), turning the control-efficacy oracle's
    verdict into a committable CI gate.

    Passes the exploit through unchanged (with a notice) for a reference target or
    a weakness with no boundary control — those can't be emitted as a committable
    custom-target control test. Mirrors the tagging ``gate --prove-control`` does.
    """
    from mylonite.gate.mitigation import weakness_class_for
    from mylonite.scan.control_shim import make_control

    if exploit.target_id.startswith("reference:"):
        typer.echo(
            f"--prove-control: {exploit.pattern_id} targets a reference twin; emitting "
            "the standard guard test instead.",
            err=True,
        )
        return exploit
    cw = weakness_class_for(exploit)
    try:
        make_control(cw)
    except ValueError:
        typer.echo(
            f"--prove-control: no boundary control for weakness {cw!r} "
            f"({exploit.pattern_id}); emitting the standard target-resists test instead.",
            err=True,
        )
        return exploit
    meta = {**exploit.payload.metadata, "synthetic_control": cw}
    return exploit.model_copy(
        update={"payload": exploit.payload.model_copy(update={"metadata": meta})}
    )


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
    prove_control: Annotated[
        bool,
        typer.Option(
            "--prove-control",
            help=(
                "Emit a control-efficacy test (assert_control_holds) that proves the "
                "control blocking this finding is load-bearing — the attack lands "
                "without it and is resisted with it — instead of the standard "
                "resists/guard test. Custom targets only (needs --target-file); a "
                "reference or non-controllable finding falls back to the standard test."
            ),
        ),
    ] = False,
) -> None:
    """Emit a pytest regression test from a confirmed exploit.

    Offline and deterministic — no LLM call. Reads an ``exploit_*.json`` (written
    by ``mylonite scan``), renders a testkit-based pytest file, and writes it next
    to a co-located copy of the exploit plus a ``fixtures/`` placeholder. For a
    CUSTOM target, pass ``--target-file`` so the target YAML is co-located as
    ``target.yaml`` (the live test needs it). With ``--prove-control`` the emitted
    test asserts the control is load-bearing (``assert_control_holds``) rather than
    just that the target resists. Prints what to run next.
    """
    import json

    from mylonite import testkit

    scans_root = Path(".mylonite/scans")
    exploit_paths = _resolve_exploit_paths(scan_path, latest, scans_root)
    multi = len(exploit_paths) > 1

    if multi:
        typer.echo(f"Found {len(exploit_paths)} findings - emitting one test each.")
        typer.echo("")

    for index, exploit_path in enumerate(exploit_paths):
        try:
            exploit = testkit.load_exploit(exploit_path)
        except (FileNotFoundError, ValueError) as exc:
            typer.echo(f"could not load exploit at {exploit_path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        if prove_control:
            exploit = _tag_control_for_generate(exploit)

        # With multiple findings, give each its own subdir so tests don't clobber
        # each other; a single finding keeps the exact dir the operator chose.
        if out is not None:
            this_out = out / _slugify_pattern(exploit.pattern_id) if multi else out
        else:
            this_out = Path(".mylonite/generated") / _slugify_pattern(exploit.pattern_id)

        if multi and index > 0:
            typer.echo("")
        _emit_generated_test(exploit, exploit_path, this_out, target_file, json_mod=json)

    raise typer.Exit(code=EXIT_SUCCESS)


def _boundary_control(weakness: str, spec: Any) -> Any:
    """Build a boundary control for ``weakness``, applying the target's ControlConfig
    hints (declared egress / consequential tools, URL param, allowlist) when present;
    falls back to the control's name heuristics otherwise."""
    from mylonite.scan.control_shim import make_control

    cfg = getattr(spec, "control_config", None)
    if cfg is None:
        return make_control(weakness)
    return make_control(
        weakness,
        egress_tools=frozenset(cfg.egress_tools) or None,
        url_param=cfg.egress_url_param,
        fetch_allowlist=tuple(cfg.fetch_allowlist),
        consequential_tools=frozenset(cfg.consequential_tools) or None,
    )


def _vulnerable_adapter(spec: Any, scope: str | None, model: str) -> Any:
    """Adapter for the RAW/vulnerable side of a differential.

    Honors a target's ``vulnerable_launch`` (its declared, deliberately-unguarded
    variant) so the raw side of a SERVER-LAYER-controlled target is genuinely
    unguarded — otherwise the "raw" side would launch the guarded server and the
    differential would never fire. When ``vulnerable_launch`` is undeclared this is
    byte-for-byte the default adapter (today's behaviour). SECURITY: launching the
    unguarded variant is announced loudly by the caller; env values are never logged.
    """
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter

    if getattr(spec, "vulnerable_launch", None) is None:
        return MCPStdioAdapter(family=spec.family, scope=scope, model=model)
    return MCPStdioAdapter(
        family=spec.family,
        scope=scope,
        model=model,
        launch_env=spec.launch_env(vulnerable=True),
        launch_command=spec.launch_command(vulnerable=True),
        launch_args=spec.launch_args(scope, vulnerable=True),
    )


def _differential_plan(exploit: Any, *, fast: bool) -> tuple[bool, str | None, str]:
    """Decide whether the differential leg gates a real-target finding (M1).

    The differential — re-driving a boundary-guarded twin to prove the *safeguard*,
    not the model, carries the security — is the moat. It now runs BY DEFAULT for a
    custom/real target whenever a boundary control can be built for the finding's
    weakness; ``--fast`` opts out (it doubles the live runs per finding). When no
    control is inferable we run WITHOUT it, loudly (never a silently weaker gate).

    Returns ``(run, control_weakness, note)`` — pure (``make_control`` is
    deterministic), so it is unit-tested without a live target.
    """
    if fast:
        return (
            False,
            None,
            "--fast: skipping the differential leg "
            "(weaker guarantee: kept = build ∧ stability ∧ effect ∧ consensus).",
        )
    from mylonite.gate.mitigation import weakness_class_for
    from mylonite.scan.control_shim import make_control

    cw = weakness_class_for(exploit)
    try:
        make_control(cw)
    except ValueError:
        return (
            False,
            None,
            f"no boundary control implemented for weakness {cw!r} — running WITHOUT the "
            "differential leg (weaker guarantee: kept = build ∧ stability ∧ effect ∧ "
            "consensus). Add a control for this weakness, or pass --fast to silence.",
        )
    return (
        True,
        cw,
        f"differential ON (default): proving control {cw} is load-bearing — "
        "the differential gates `kept` (the safeguard, not the model, carries the security).",
    )


def _validate_custom(
    generated: Any,
    target_file: Path | None,
    iterations: int,
    provider: str,
    model: str,
    iteration_timeout_s: float | None = None,
    prove_control: bool = False,
    randomize_exfil: bool = False,
    adaptive: bool = False,
    fast: bool = False,
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

    if spec.vulnerable_launch is not None:
        typer.echo(
            f"validate: the raw side launches the DELIBERATELY-UNGUARDED variant of "
            f"{spec.family!r} (vulnerable_launch) — ensure you are authorized to run it. "
            "Env values are never logged.",
            err=True,
        )

    def _factory() -> Any:
        return _vulnerable_adapter(spec, tf.scope, model)

    # M1: the differential leg (re-driving a boundary-guarded twin of the SAME real
    # target, model held constant) gates `kept` BY DEFAULT — proving the *safeguard*,
    # not the model, carries the security. `--fast` opts out (it doubles the live runs
    # per finding); a weakness with no inferable control falls back loudly to the
    # stability/effect/consensus gate. `--prove-control` is now the default behaviour
    # and kept only for back-compat.
    del prove_control
    run_diff, control_weakness, diff_note = _differential_plan(generated.exploit, fast=fast)
    typer.echo(f"validate: {diff_note}", err=True)
    guarded_factory: Any = None
    control_context: str | None = None
    if run_diff and control_weakness is not None:
        from mylonite.gate.mitigation import _snippet

        cw = control_weakness
        # Feed the strategist what control it is up against (adaptive-aware oracle).
        control_context = f"Control {cw}: {_snippet(cw)}"

        def _guarded() -> Any:
            return MCPStdioAdapter(
                family=spec.family,
                scope=tf.scope,
                model=model,
                controls=[_boundary_control(cw, spec)],
            )

        guarded_factory = _guarded
        if adaptive:
            typer.echo(
                f"--adaptive: grading control {cw} UNDER ADAPTIVE PRESSURE "
                "(the strategist tries to evade it).",
                err=True,
            )

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
        guarded_adapter_factory=guarded_factory,
        control_weakness=control_weakness,
        randomize_exfil=randomize_exfil,
        adaptive_guarded=adaptive and guarded_factory is not None,
        control_context=control_context,
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


def _render_validation_report(report: Any, console: Console | None = None) -> None:
    """Render a per-leg Rich report (F4): one row per ValidationOutcome.

    This is the moat's SHOWCASE surface, so it is made ASCII-safe independently
    of the root callback's UTF-8 forcing: a legacy cp1252 Windows console must
    never crash on the pass/fail marks or the title dash (Issue #9). Shows the
    per-leg result + metric + detail; the gating formula with live per-leg marks,
    the fires/resists reproducibility counts, the per-seed kill matrix and the
    mutation-score headline; the overall kept verdict; plus a remediation line
    per failed gating leg when the test was rejected.
    """
    # ASCII-aware marks/separators so the showcase surface never crashes on a
    # legacy cp1252 console — independent of the root callback's UTF-8 forcing.
    from mylonite.scan.artefacts import _stdout_is_ascii_only

    ascii_safe = _stdout_is_ascii_only()

    def _mark(ok: bool) -> str:
        # NB: avoid '[...]' tokens — Rich would parse them as console markup.
        if ascii_safe:
            return "+" if ok else "x"
        return "✓" if ok else "✗"

    sep = " | " if ascii_safe else " · "
    dash = "-" if ascii_safe else "—"

    if console is None:
        console = Console()
    table = Table(
        title=f"Mylonite validate {dash} {report.test_filename}",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("leg", no_wrap=True)
    table.add_column("result", no_wrap=True)
    table.add_column("metric", no_wrap=True)
    table.add_column("detail")

    for outcome in report.outcomes:
        mark = f"{_mark(outcome.passed)} {'pass' if outcome.passed else 'FAIL'}"
        metric = f"{outcome.metric:.2f}" if outcome.metric is not None else "-"
        table.add_row(outcome.stage, mark, metric, outcome.detail)

    console.print(table)

    # --- the differential-oracle EVIDENCE (PR2: make the moat legible) --------
    # The gating formula with live per-leg marks, the fires/resists counts, and
    # the per-seed kill matrix were previously buried in report.notes (rendered
    # nowhere). Surface them so a "KEPT" verdict shows WHY it's trustworthy.
    # Metric legend — what the bare decimals in the table's metric column mean.
    console.print(
        "metric legend: "
        + sep.join(
            ["differential=agreement", "flakiness=reproducibility", "metamorphic=robustness (0-1)"]
        )
    )

    # The gate itself, with LIVE per-leg marks — this is what makes a verdict
    # legible: kept = build [ok] AND differential [ok] AND flakiness [x].
    legs_by_stage = {o.stage: o for o in report.outcomes}
    if getattr(report, "gating_legs", None):
        rendered = " AND ".join(
            f"{leg} {_mark(legs_by_stage[leg].passed)}"
            for leg in report.gating_legs
            if leg in legs_by_stage
        )
        verdict = "KEPT" if report.kept else "REJECTED"
        console.print(f"gate: kept = {rendered}  =>  {verdict}")

    # Reproducibility counts (fires/resists) behind differential + flakiness.
    repro = getattr(report, "reproducibility", None)
    if repro is not None:
        if repro.guard_resisted is not None:
            console.print(
                f"reproducibility: vulnerable fired {repro.vuln_fired}/{repro.iterations}, "
                f"guarded resisted {repro.guard_resisted}/{repro.iterations}"
            )
        else:
            console.print(
                f"reproducibility: reproduced {repro.vuln_fired}/{repro.iterations} "
                "against the real target (no in-repo guarded twin)"
            )

    if report.mutation_score is not None:
        console.print(f"mutation score: {report.mutation_score:.2f}")

    # Per-seed kill matrix — the oracle's discrimination, seed by seed.
    matrix = getattr(report, "mutation_matrix", None) or []
    if matrix:
        killed = sum(1 for s in matrix if s.killed)
        console.print(
            f"kill matrix ({killed}/{len(matrix)} seeds killed = "
            "fired-on-vulnerable, resisted-on-guarded):"
        )
        for seed in matrix:
            console.print(f"  {_mark(seed.killed)} {seed.weakness}:{seed.pattern_id}")

    # Metamorphic is report-only — say so explicitly so a failing metamorphic row
    # is never read as a gate failure.
    if any(o.stage == "metamorphic" for o in report.outcomes):
        console.print("note: metamorphic robustness is report-only - it does not gate kept.")

    if report.kept:
        console.print(f"[green]verdict: KEPT {dash} the test discriminates and is stable.[/green]")
    else:
        console.print(f"[red]verdict: REJECTED {dash} the test was not kept.[/red]")
        _remediation = {
            "build": "build fail: emitted test didn't collect; re-run `mylonite generate`.",
            "differential": "differential fail: no discriminating power between the twins.",
            "flakiness": "flakiness fail: exploit too flaky to gate; try a more deterministic seed.",
            "stability": "stability fail: the attack did not reproduce against the real target.",
            "effect": "effect fail: the target's effect probe did not confirm the damage materialised.",
            "consensus": "consensus fail: judges disagreed the effect was real; add an effect_probe.",
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


def _run_cross_model_validation(
    generated: Any, models_csv: str, iterations: int, provider: str, test_path: Path
) -> None:
    """Re-prove the reference differential across several models; flag re-emergence (T2).

    Runs the full differential oracle once per model and writes a durability table +
    ``cross_model_report.json``. Exits non-zero if ANY model fails to keep the test —
    that model is one a team could upgrade to and silently re-introduce the weakness.
    """
    import json as _json

    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )
    from mylonite.scan.cross_model import row_from_report, summarize_cross_model

    model_list = [m.strip() for m in models_csv.split(",") if m.strip()]
    if not model_list:
        typer.echo("--models was empty; pass e.g. --models m1,m2", err=True)
        raise typer.Exit(code=EXIT_CONFIG)

    rows = []
    for m in model_list:
        typer.echo(f"Cross-model durability: re-validating against {m} …", err=True)
        if not _provider_preflight(provider, m):
            typer.echo(
                f"model {m!r} is unreachable — set the provider/key or drop it from "
                "--models. Aborting rather than reporting a misleading durability result.",
                err=True,
            )
            raise typer.Exit(code=EXIT_PROVIDER)
        validator = DifferentialValidator(iterations=iterations, provider=provider, model=m)
        report = validator.validate(
            generated, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
        )
        rows.append(row_from_report(m, report))

    all_durable, summary = summarize_cross_model(rows)
    typer.echo("")
    typer.echo(summary)

    out_path = test_path.parent / "cross_model_report.json"
    out_path.write_text(
        _json.dumps(
            {
                "all_durable": all_durable,
                "models": [
                    {
                        "model": r.model,
                        "kept": r.kept,
                        "vuln_fired": r.vuln_fired,
                        "guard_resisted": r.guard_resisted,
                        "iterations": r.iterations,
                    }
                    for r in rows
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    typer.echo(f"Cross-model report: {out_path}")
    raise typer.Exit(code=EXIT_SUCCESS if all_durable else EXIT_NOT_KEPT)


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
    models: Annotated[
        str | None,
        typer.Option(
            "--models",
            help=(
                "Cross-model durability (T2): comma-separated models to RE-PROVE the "
                "differential across (e.g. 'claude-haiku-4-5,claude-sonnet-4-6'). Flags "
                "any model where the weakness re-emerges / the control fails — a fix can "
                "silently reappear on a model upgrade. Reference targets only; exits "
                "non-zero if any model fails. Overrides --model."
            ),
        ),
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
    prove_control: Annotated[
        bool,
        typer.Option(
            "--prove-control",
            help=(
                "Deprecated/back-compat: the differential leg now runs BY DEFAULT for a "
                "real target, so this flag is a no-op. Pass --fast to skip the differential."
            ),
        ),
    ] = False,
    fast: Annotated[
        bool,
        typer.Option(
            "--fast",
            help=(
                "Skip the differential leg (the boundary-guarded twin). Faster/cheaper "
                "(~half the live runs) but a WEAKER guarantee: kept = build ∧ stability ∧ "
                "effect ∧ consensus, without proving the safeguard carries the security."
            ),
        ),
    ] = False,
    randomize_exfil: Annotated[
        bool,
        typer.Option(
            "--randomize-exfil",
            help=(
                "Mint a unique exfil destination per run instead of the demo address, so "
                "the run proves the control/target stops exfil to ANY attacker destination "
                "(generalizes) rather than blocking one literal."
            ),
        ),
    ] = False,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive",
            help=(
                "Adaptive-aware oracle (use with --prove-control): drive the guarded twin "
                "with the adaptive loop so the strategist tries to EVADE the control, "
                "grading whether it holds under adaptive pressure vs falls to it."
            ),
        ),
    ] = False,
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

    # T2: cross-model durability is a distinct flow — re-prove the differential across
    # several models and flag any where the weakness re-emerges. Reference twins only
    # (the differential needs the bundled guarded twin). Branch early and return.
    if models is not None:
        if is_custom:
            typer.echo(
                "--models (cross-model durability) needs a reference target — the "
                "differential re-runs against the bundled twins across each model. A "
                "custom target has no in-repo guarded twin to re-prove.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        _run_cross_model_validation(generated, models, iterations, effective_provider, test_path)
        return

    # Auto-resolve the target YAML co-located with the test (written by `generate`)
    # so the operator needn't re-pass --target-file. Explicit --target-file wins.
    if target_file is None and is_custom:
        candidate = test_path.parent / "target.yaml"
        if candidate.is_file():
            target_file = candidate
            typer.echo(f"Using target: {candidate} (co-located with the test)", err=True)
    if is_custom:
        if adaptive and fast:
            typer.echo(
                "--adaptive grades the control under adaptive pressure, which needs the "
                "differential twin — but --fast skips it. Drop --fast to use --adaptive.",
                err=True,
            )
            raise typer.Exit(code=EXIT_CONFIG)
        report = _validate_custom(
            generated,
            target_file,
            iterations,
            effective_provider,
            effective_model,
            iteration_timeout_s=iteration_timeout,
            prove_control=prove_control,
            randomize_exfil=randomize_exfil,
            adaptive=adaptive,
            fast=fast,
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

    # T2: stamp the model the differential was proven against, so the committed
    # regression is honest about which model version it gates (a fix can silently
    # re-emerge on a model upgrade — see `validate --models`).
    _stamp = f"validated against model: {effective_model}"
    report = report.model_copy(
        update={"notes": (f"{report.notes}\n{_stamp}" if report.notes else _stamp)}
    )

    # Persist the full ValidationReport (incl. the PR2 structured evidence) next
    # to the test so `mylonite report` can re-render the trust panel offline and
    # the JSON artefact carries the oracle's discrimination, not just a verdict.
    report_path = test_path.parent / "validation_report.json"
    report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")

    _render_validation_report(report)

    if report.kept:
        typer.echo("")
        typer.echo(
            "Next: commit the generated test + fixtures so CI can gate on it "
            "(see `mylonite gate --help`)."
        )
        raise typer.Exit(code=EXIT_SUCCESS)
    raise typer.Exit(code=EXIT_NOT_KEPT)


def _compliance_tags_line(compliance: Any) -> str:
    """One-line compliance summary from a ComplianceTags (OWASP/ATLAS/NIST)."""
    parts = []
    if compliance.owasp_llm:
        parts.append("OWASP-LLM " + ", ".join(compliance.owasp_llm))
    if compliance.owasp_asi:
        parts.append("OWASP-ASI " + ", ".join(compliance.owasp_asi))
    if compliance.mitre_atlas:
        parts.append("MITRE ATLAS " + ", ".join(compliance.mitre_atlas))
    if compliance.nist_ai_rmf:
        parts.append("NIST " + ", ".join(compliance.nist_ai_rmf))
    return " | ".join(parts) if parts else "(no compliance tags)"


def _locate_report_artefact(target: Path) -> tuple[str, Path]:
    """Resolve a ``report`` TARGET to a ('validation'|'scan', path) pair.

    Prefers a persisted ``validation_report.json`` (the oracle verdict + evidence)
    over a ``scan_report.json`` when a dir holds both. Exits 2 with guidance when
    nothing loadable is found.
    """
    if target.is_file():
        if target.name == "validation_report.json":
            return "validation", target
        if target.name == "scan_report.json":
            return "scan", target
        typer.echo(
            f"don't know how to report on {target.name}. Pass a scan dir, a "
            "generated/validated dir, or a scan_report.json / validation_report.json.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if target.is_dir():
        vr = target / "validation_report.json"
        if vr.is_file():
            return "validation", vr
        sr = target / "scan_report.json"
        if sr.is_file():
            return "scan", sr
        typer.echo(
            f"no validation_report.json or scan_report.json found in {target}. "
            "Run `mylonite scan` or `mylonite validate` first.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    typer.echo(
        f"path not found: {target}. Pass a scan/validated dir or a report JSON.",
        err=True,
    )
    raise typer.Exit(code=EXIT_CONFIG)


@app.command()
def report(
    target: Annotated[
        Path,
        typer.Argument(
            help=(
                "A scan dir, a generated/validated dir, or a scan_report.json / "
                "validation_report.json. Renders the trust panel for whichever it finds."
            ),
        ),
    ],
    html: Annotated[
        Path | None,
        typer.Option(
            "--html",
            help=(
                "Also write a standalone, shareable HTML report. Takes a file "
                "PATH argument, e.g. --html report.html (not a bare flag)."
            ),
        ),
    ] = None,
    html_style: Annotated[
        str,
        typer.Option(
            "--html-style",
            help=(
                "HTML style: 'dashboard' (structured exec summary + per-finding "
                "severity + compliance + collapsible evidence, default) or 'terminal' "
                "(the raw trust-panel export). Both are self-contained (no JS/CDN)."
            ),
        ),
    ] = "dashboard",
    sarif: Annotated[
        Path | None,
        typer.Option(
            "--sarif",
            help=(
                "Also write a SARIF 2.1.0 file for GitHub code scanning (the Security "
                "tab + PR checks). Each result carries severity, compliance tags, and "
                "the differential proof (fired N/N, resisted M/M). Takes a PATH."
            ),
        ),
    ] = None,
    json_bundle: Annotated[
        Path | None,
        typer.Option(
            "--json",
            help=(
                "Also write a machine-readable JSON finding bundle (severity, "
                "compliance, localization, differential proof, proven control) for "
                "dashboards / SIEM / bots. Takes a PATH."
            ),
        ),
    ] = None,
) -> None:
    """Render a saved scan or validation as a trust panel (offline, no LLM).

    A clean, screenshot-able "why you can trust this" readout. For a validation it
    shows the verdict, the gating formula with
    live per-leg marks, the fires/resists reproducibility counts, the per-seed
    kill matrix, and the compliance tags. For a scan it shows the findings,
    coverage (incl. any NOT TESTED gap), and compliance tags. Exit 2 if no
    loadable artefact is found.
    """
    from rich.console import Console as _Console

    if html is not None and html_style not in ("dashboard", "terminal"):
        typer.echo(
            f"--html-style {html_style!r} is not valid; choose 'dashboard' or 'terminal'.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    kind, path = _locate_report_artefact(target)
    # A recording console only when exporting the terminal HTML style.
    record = html is not None and html_style == "terminal"
    console = _Console(record=record)

    # Captured for the dashboard renderer (enriched so NIST is present everywhere).
    vreport: Any = None
    sreport: Any = None
    dashboard_exploit: Any = None
    dashboard_exploits: list[Any] = []

    if kind == "validation":
        from mylonite import testkit
        from mylonite.contracts import ValidationReport

        try:
            vreport = ValidationReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            typer.echo(f"could not load {path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        _render_validation_report(vreport, console=console)
        # Compliance tags from the co-located exploit, if present.
        exploit_matches = sorted(path.parent.glob("exploit_*.json"))
        if exploit_matches:
            try:
                # Enrich on read (derive NIST from the OWASP cross-refs) so the
                # report's compliance line matches the emitted test's marks even
                # for artefacts whose persisted exploit predates enrichment. Captured
                # for the dashboard renderer.
                dashboard_exploit = _map_compliance(testkit.load_exploit(exploit_matches[0]))
                console.print(f"compliance: {_compliance_tags_line(dashboard_exploit.compliance)}")
                console.print(
                    f"target: {dashboard_exploit.target_id}  "
                    f"pattern: {dashboard_exploit.pattern_id}"
                )
            except (FileNotFoundError, ValueError):
                pass
        console.print(f"artefacts: {path.parent}")
    else:
        from mylonite import testkit
        from mylonite.contracts._types import ScanReport
        from mylonite.scan.artefacts import render_summary
        from mylonite.scan.engine import ScanResult

        try:
            sreport = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            typer.echo(f"could not load {path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        result = ScanResult(report=sreport, exploits=[])
        # render_summary already returns a fully-rendered, ASCII-aware string.
        console.print(render_summary(result), markup=False)
        # Compliance tags aggregated across the co-located exploit files, enriched
        # on read (derive NIST from the OWASP cross-refs) so the report matches the
        # emitted test's marks even for scan dirs whose persisted exploits predate
        # enrichment.
        tags: set[str] = set()
        target_id = sreport.target_id
        for exploit_file in sorted(path.parent.glob("exploit_*.json")):
            try:
                exploit = _map_compliance(testkit.load_exploit(exploit_file))
            except (FileNotFoundError, ValueError, OSError):
                continue
            dashboard_exploits.append(exploit)
            c = exploit.compliance
            for ids in (c.owasp_llm, c.owasp_asi, c.mitre_atlas, c.nist_ai_rmf):
                tags.update(ids)
        if tags:
            console.print(f"compliance: {', '.join(sorted(tags))}")
        console.print(f"target: {target_id}  artefacts: {path.parent}")

    if html is not None:
        if html_style == "dashboard":
            from mylonite.report import render_scan_html, render_validation_html

            page = (
                render_validation_html(vreport, dashboard_exploit)
                if kind == "validation"
                else render_scan_html(sreport, dashboard_exploits)
            )
            html.write_text(page, encoding="utf-8")
        else:
            html.write_text(console.export_html(inline_styles=True), encoding="utf-8")
        typer.echo(f"Wrote HTML report: {html} (style: {html_style})")

    if sarif is not None or json_bundle is not None:
        import json as _json

        # The same finding set feeds both machine-readable exports: a validation
        # carries its differential-proof report; a scan has exploits with no report.
        if kind == "validation":
            findings = [(dashboard_exploit, vreport)] if dashboard_exploit is not None else []
        else:
            findings = [(e, None) for e in dashboard_exploits]

        if sarif is not None:
            from mylonite.report import to_sarif

            sarif.write_text(_json.dumps(to_sarif(findings), indent=2) + "\n", encoding="utf-8")
            typer.echo(f"Wrote SARIF (GitHub code scanning): {sarif}")
        if json_bundle is not None:
            from mylonite.report import to_bundle

            json_bundle.write_text(
                _json.dumps(to_bundle(findings), indent=2) + "\n", encoding="utf-8"
            )
            typer.echo(f"Wrote JSON finding bundle: {json_bundle}")
    raise typer.Exit(code=EXIT_SUCCESS)


def _exploit_for_export(target: Path) -> Path:
    """Resolve an export TARGET (a dir or an exploit_*.json) to an exploit file."""
    if target.is_file():
        return target
    if target.is_dir():
        matches = sorted(target.glob("exploit_*.json"))
        if matches:
            return matches[0]
        typer.echo(
            f"no exploit_*.json found in {target}. Run `mylonite scan`/`generate` first.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)
    typer.echo(
        f"path not found: {target}. Pass a scan/generated dir or an exploit_*.json.", err=True
    )
    raise typer.Exit(code=EXIT_CONFIG)


@app.command(name="export")
def export_cmd(
    target: Annotated[
        Path,
        typer.Argument(
            help=(
                "A validated/generated dir, a scan dir, or an exploit_*.json. "
                "The validated finding to export."
            ),
        ),
    ],
    fmt: Annotated[
        str,
        typer.Option("--format", help="Export format. Currently 'eval-yaml' (the default)."),
    ] = "eval-yaml",
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write to this file instead of stdout."),
    ] = None,
) -> None:
    """Export a validated finding into a portable eval format (offline, no LLM).

    Mylonite is the validation layer; this hands a differential-oracle-validated
    finding to the eval/CI harness a team already runs. ``--format eval-yaml``
    emits a portable eval test case (the attack as input + a rubric assert that
    the agent must resist it) carrying the compliance tags and a provenance
    marker, so the team gets a Mylonite-validated regression in their suite.
    """
    from mylonite import testkit
    from mylonite.export import SUPPORTED_FORMATS, to_eval_config

    if fmt not in SUPPORTED_FORMATS:
        typer.echo(
            f"unknown --format {fmt!r}. Supported: {', '.join(SUPPORTED_FORMATS)}.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    exploit_path = _exploit_for_export(target)
    try:
        exploit = testkit.load_exploit(exploit_path)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"could not load exploit at {exploit_path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    rendered = to_eval_config(exploit)
    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        typer.echo(f"Wrote {fmt} export: {out}")
        typer.echo("Next: wire your agent under `providers`, then run it in your eval/CI harness.")
    else:
        typer.echo(rendered)
    raise typer.Exit(code=EXIT_SUCCESS)


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
    roles = _classify_tools(tools)

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
        roles=roles,
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
    if roles.seed_arm_tool is not None:
        typer.echo(
            f"  seed_arm candidate: {roles.seed_arm_tool}(...{roles.seed_arm_param}='{{payload}}') "
            f"+ retrieval via {roles.retrieve_tool!r}."
            if roles.retrieve_tool is not None
            else (
                f"  seed_arm candidate: {roles.seed_arm_tool} — but NO id-free retrieval tool was "
                "found to surface what it stores. The planner never learns a new record's id, so a "
                "store whose only readback needs that id (the save_note/read_note trap) will never "
                "deliver the poison. Confirm a list/recall/search-style tool exists, or expect those "
                "seeds to report NOT TESTED."
            ),
            err=True,
        )
    elif "W2" in suggested_weaknesses:
        typer.echo(
            "  no obvious content-storing tool found for the seed_arm — fill it in by hand "
            "(the tool that ingests untrusted content), or W2 seeds will report NOT TESTED.",
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
    roles: _ToolRoles | None = None,
) -> str:
    """Render a commented, ready-to-edit ``target.yaml`` starter.

    When ``roles`` is supplied, the ``seed_arm`` and ``effect_probe`` blocks are
    pre-filled with concrete candidates auto-detected from the tool schemas
    (still commented — the operator confirms and uncomments), instead of blank
    placeholders.
    """
    import yaml

    roles = roles or _ToolRoles(None, None, None, None, [])

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

    # Pre-fill seed_arm/effect_probe from the detected roles (commented — confirm
    # then uncomment). Concrete tool + param names beat blank placeholders.
    sa_tool = roles.seed_arm_tool or "<tool that stores/accepts untrusted content>"
    sa_param = roles.seed_arm_param or "body"
    if roles.seed_arm_tool is not None and roles.retrieve_tool is not None:
        sa_status = (
            f"# CANDIDATE (auto-detected): {roles.seed_arm_tool} stores content; "
            f"{roles.retrieve_tool} surfaces it without an id."
        )
    elif roles.seed_arm_tool is not None:
        sa_status = (
            f"# CANDIDATE (auto-detected): {roles.seed_arm_tool} — WARNING: no id-free retrieval "
            "tool detected, so the planted poison may never be readable back (save_note trap)."
        )
    else:
        sa_status = (
            "# (no content-storing tool auto-detected — fill in the tool that ingests content)"
        )
    verify_tool = roles.verify_tool or "<tool that reports the side effect>"
    ep_status = (
        f"# CANDIDATE verify_tool (auto-detected): {roles.verify_tool}."
        if roles.verify_tool is not None
        else "# (no side-effect-reporting tool auto-detected — point this at one)"
    )
    sink_hint = (
        f"# Consequential-action tools detected (W4 candidates): {', '.join(roles.sink_tools)}.\n"
        if roles.sink_tools
        else ""
    )
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

# How to plant untrusted content for indirect-injection (W2) seeds. {{payload}}
# is replaced per attempt and must sit at a BARE string leaf (not nested JSON).
{sa_status}
# seed_arm:
#   tool: {sa_tool}
#   args_template: {{ {sa_param}: "{{payload}}" }}
#   id_key: id                                 # JSON field holding the new handle
#                                              # (or id_pattern: a regex; or id_from)

# How to CONFIRM the damage materialised end-to-end (the effect probe). After the
# attack, re-query the target and check the damaging side effect is present.
{ep_status}
{sink_hint}# effect_probe:
#   verify_tool: {verify_tool}
#   verify_args_template: {{}}
#   expect_marker: "<a string proving the effect, e.g. the attacker recipient>"
#   deferred_markers: ["queued for approval", "pending review"]  # mark a DEFENDED result
"""


def _post_gate_annotations(
    repo_root: Path, exploit: Any, report: Any, target_file: Path | None, pr_mod: Any
) -> None:
    """Best-effort GitHub check-run annotation for a finding that maps to a committed
    prompt line (R4). Untestable live glue (needs a real PR + ``checks:write``); the
    payload assembly and localization it calls are unit-tested. Never raises."""
    try:
        from mylonite.gate.annotate import (
            annotations_from_findings,
            check_run_payload,
            post_check_run,
        )

        sp_path: str | None = None
        sp_text: str | None = None
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            tf = load_target_file(target_file)
            if tf.system_prompt_file is not None:
                spf = Path(tf.system_prompt_file)
                sp_text = spf.read_text(encoding="utf-8")
                try:
                    sp_path = str(spf.resolve().relative_to(repo_root.resolve()))
                except ValueError:
                    sp_path = str(spf)

        anns = annotations_from_findings(
            [(exploit, report)], system_prompt=sp_path, system_prompt_text=sp_text
        )
        if not anns:
            return
        head = pr_mod._default_run(["git", "rev-parse", "HEAD"], cwd=str(repo_root))
        head_sha = (getattr(head, "stdout", "") or "").strip()
        if not head_sha:
            return
        payload = check_run_payload(
            head_sha=head_sha,
            annotations=anns,
            title="Mylonite AI-layer findings",
            summary=f"{len(anns)} finding(s) localized to a source line.",
        )
        post_check_run(repo_root, payload, _run=pr_mod._default_run)
    except Exception:  # live glue must never break the gate
        return


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
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config (target_file / authorize / "
                "provider / model / budget) — the same one `scan` reads. Auto-discovered "
                "from ./mylonite.yaml when present; an explicit flag always wins."
            ),
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
    runs_on: Annotated[
        str,
        typer.Option(
            "--runs-on",
            help="GitHub runner label for the scaffolded workflows; use a self-hosted label for in-perimeter MCP backends.",
        ),
    ] = "ubuntu-latest",
    workflows: Annotated[
        bool,
        typer.Option(
            "--workflows/--no-workflows",
            help="Scaffold .github/workflows/ gate + discovery templates.",
        ),
    ] = True,
    llm_enrich: Annotated[
        bool,
        typer.Option(
            "--llm-enrich",
            help="Append a labelled, unverified LLM fix suggestion to the PR body.",
        ),
    ] = False,
    prove_control: Annotated[
        bool,
        typer.Option(
            "--prove-control",
            help=(
                "Deprecated/back-compat: for a custom target the differential now runs BY "
                "DEFAULT (the emitted test is the control-verified one). Pass --fast to skip it."
            ),
        ),
    ] = False,
    fast: Annotated[
        bool,
        typer.Option(
            "--fast",
            help=(
                "Skip the differential leg for a custom target (no boundary-guarded twin). "
                "Faster/cheaper but a WEAKER guarantee — the kept test no longer proves the "
                "safeguard, not the model, carries the security."
            ),
        ),
    ] = False,
    randomize_exfil: Annotated[
        bool,
        typer.Option(
            "--randomize-exfil",
            help=(
                "Mint a unique exfil destination per run so the finding proves the "
                "control/target stops exfil to ANY attacker destination, not just the "
                "demo address."
            ),
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

    # Declarative run config (mylonite.yaml): mirror `scan` so `gate` fills any flag
    # the user omitted (target_file / authorize / provider / model / budget) from a
    # project config. Auto-discovered from ./mylonite.yaml when present and no
    # --config is passed; an explicit flag always wins. Closes the parity gap where
    # `gate` required --target-file even though the project's mylonite.yaml set it.
    config_path = run_config_path
    if config_path is None and Path("mylonite.yaml").is_file():
        config_path = Path("mylonite.yaml")
    if config_path is not None:
        from mylonite.config import load_run_config

        try:
            rc = load_run_config(config_path)
        except Exception as exc:
            typer.echo(f"invalid config {config_path}: {exc}", err=True)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        if run_config_path is None:
            typer.echo(f"gate: using {config_path} (auto-discovered).", err=True)
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        if max_llm_calls == 50 and rc.max_llm_calls is not None:
            # 50 is the option default; only the config overrides an untouched flag.
            max_llm_calls = rc.max_llm_calls

    effective_provider = provider or "anthropic"
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

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

        attack_modules = [m for m in all_modules if m.attack_metadata().id in _V0_2_ATTACK_FAMILIES]
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
        # Enrich compliance (derive NIST) once so both the emitted test and the PR
        # carry it.
        exploits = [_map_compliance(ex) for ex in result.exploits]
        # M1: tag each controllable CUSTOM finding BY DEFAULT so generate_fn emits the
        # control test and validate_fn runs the differential (the safeguard, not the
        # model, carries the security). --fast opts out; reference targets use the
        # in-repo differential and are not tagged here. --prove-control is now the
        # default behaviour and kept for back-compat.
        if fast or is_reference:
            return exploits
        from mylonite.gate.mitigation import weakness_class_for
        from mylonite.scan.control_shim import make_control

        tagged: list[Any] = []
        for ex in exploits:
            cw = weakness_class_for(ex)
            try:
                make_control(cw)
            except ValueError:
                tagged.append(ex)
                continue
            meta = {**ex.payload.metadata, "synthetic_control": cw}
            tagged.append(
                ex.model_copy(update={"payload": ex.payload.model_copy(update={"metadata": meta})})
            )
        return tagged

    def generate_fn(exploit: Any) -> Any:
        return ReferencePytestGenerator().emit(exploit)

    def validate_fn(generated: Any) -> Any:
        if is_reference:
            validator = DifferentialValidator(
                provider=effective_provider,
                model=effective_model,
                record_fixtures_dir=out / "fixtures",
                progress_cb=lambda msg: typer.echo(f"  … {msg}", err=True),
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

        # --prove-control: a controllable finding (tagged in scan_fn) gets a
        # boundary-guarded twin so the differential leg proves the control is
        # load-bearing (model held constant).
        guarded_factory: Any = None
        control_weakness = generated.exploit.payload.metadata.get("synthetic_control")
        if control_weakness:
            cw: str = control_weakness

            def _guarded() -> Any:
                return MCPStdioAdapter(
                    family=spec.family,
                    scope=tf.scope,
                    model=effective_model,
                    controls=[_boundary_control(cw, spec)],
                )

            guarded_factory = _guarded

        # gate is the fast magic-moment path: one re-drive that must FIRE at least once
        # (vuln_threshold=1, not the default iterations-1=0). Deeper multi-iteration
        # rigor lives in nightly discovery + the committed test's regression assert.
        validator = DifferentialValidator(
            iterations=1,
            vuln_threshold=1,
            provider=effective_provider,
            model=effective_model,
            target_adapter_factory=_factory,
            guarded_adapter_factory=guarded_factory,
            control_weakness=control_weakness,
            randomize_exfil=randomize_exfil,
            progress_cb=lambda msg: typer.echo(f"  … {msg}", err=True),
        )
        return validator.validate(generated, _factory(), ReferenceVulnerableOracle())

    def open_pr_fn(*, out_dir: Path, exploit: Any, report: Any, body: str, open_pr: bool) -> Any:
        from mylonite.gate.workflows import write_workflows

        repo_root = Path.cwd()
        wf_files = write_workflows(repo_root, runs_on=runs_on) if workflows else []
        if target_file is not None:
            (out_dir / "target.yaml").write_text(
                target_file.read_text(encoding="utf-8"), encoding="utf-8"
            )
        paths = pr_mod.GatePaths(repo_root=repo_root, gate_dir=out_dir, workflow_files=wf_files)
        pr = pr_mod.open_or_print_pr(
            paths,
            branch=f"mylonite/gate-{exploit.pattern_id}",
            pr_title=f"Mylonite gate: {exploit.pattern_id}",
            pr_body=body,
            open_pr=open_pr,
        )
        # R4: best-effort inline check-run annotation on the exact prompt line, when
        # the AI layer is a committed file GitHub can render against. Tool loci (a
        # remote MCP description/handler/return path) have no source line and ride in
        # the PR body + SARIF instead. Live-only glue; never fails the gate.
        if open_pr and getattr(pr, "opened", False):
            _post_gate_annotations(repo_root, exploit, report, target_file, pr_mod)
        return pr

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


def _render_ablation_matrix(results: list[Any], console: Console | None = None) -> None:
    """Render the control-ablation matrix (ASCII-safe for a legacy cp1252 console)."""
    from mylonite.scan.artefacts import _stdout_is_ascii_only

    dash = "-" if _stdout_is_ascii_only() else "—"
    if console is None:
        console = Console()
    table = Table(
        title=f"Mylonite control ablation {dash} marginal contribution",
        title_justify="left",
        show_lines=False,
    )
    table.add_column("control", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("contribution", no_wrap=True)
    table.add_column("raw/guarded fired", no_wrap=True)
    for r in results:
        table.add_row(
            r.weakness,
            r.status,
            f"{r.contribution:+.0%}",
            f"{r.raw_fired}/{r.guarded_fired} of {r.total}",
        )
    console.print(table)
    load_bearing = [r.weakness for r in results if r.load_bearing]
    redundant = [r.weakness for r in results if r.status == "redundant"]
    theater = [r.weakness for r in results if r.status == "theater"]
    if load_bearing:
        console.print(f"load-bearing: {', '.join(load_bearing)}")
    if redundant:
        console.print(f"redundant (another control covers it): {', '.join(redundant)}")
    if theater:
        console.print(f"security theater (no marginal contribution): {', '.join(theater)}")


@app.command()
def ablate(
    target_file: Annotated[
        Path | None,
        typer.Option("--target-file", help="Custom-target YAML (required): the app to ablate."),
    ] = None,
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize", help="Required: assert ownership of the target. See SECURITY.md."
        ),
    ] = None,
    controls: Annotated[
        str | None,
        typer.Option(
            "--controls",
            help=(
                "Comma-separated weakness classes to ablate (e.g. W2,W3,W4). Default: the "
                "target's declared controls, else all implemented controls matching its "
                "weakness_classes."
            ),
        ),
    ] = None,
    iterations: Annotated[
        int,
        typer.Option("--iterations", help="Scans per control per side (raw/guarded). Default 1."),
    ] = 1,
    provider: Annotated[str | None, typer.Option("--provider")] = None,
    model: Annotated[str | None, typer.Option("--model")] = None,
    redundancy: Annotated[
        bool,
        typer.Option(
            "--redundancy",
            help=(
                "Toggle each control OFF against the FULL set (all-minus-c) instead of "
                "on-vs-off, so the matrix tells 'redundant' (another control covers the "
                "weakness) from 'theater'."
            ),
        ),
    ] = False,
    max_seeds: Annotated[
        int,
        typer.Option(
            "--max-seeds", help="Max kitchen-sink seeds per weakness to probe. Default 2."
        ),
    ] = 2,
) -> None:
    """Score each AI safeguard's marginal contribution (load-bearing / theater / redundant).

    For each control, toggle it (on vs off, or all-minus-c with --redundancy)
    against its weakness's attack (model held constant) and report whether it
    actually carries the security. LIVE: launches the target's MCP server + provider.
    """
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.scan.ablation import (
        REP_SEED_BY_WEAKNESS,
        run_control_ablation,
        scan_target_fires,
        seeds_for_weaknesses,
    )
    from mylonite.scan.control_shim import make_control

    if target_file is None:
        typer.echo(
            "ablate requires --target-file (the app whose controls you want to score).", err=True
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if not authorize:
        typer.echo("--authorize is required to ablate a custom target. See SECURITY.md.", err=True)
        raise typer.Exit(code=EXIT_CONFIG)

    effective_provider = provider or "anthropic"
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        typer.echo(f"invalid --target-file {target_file}: {exc}", err=True)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Server-layer mode: the target bakes its guards into the server (toggled by
    # env / a security profile), so the differential's "raw" side is produced by
    # DISABLING them via control_env — not by emptying the adapter shim, which
    # cannot reach a server-layer guard. This is what lets ablation classify
    # load-bearing/theater on the common real architecture instead of returning
    # no-attack for every control.
    server_layer = bool(spec.control_env)

    if controls:
        chosen = [c.strip().upper() for c in controls.split(",") if c.strip()]
    elif spec.control_config and spec.control_config.declared:
        chosen = list(spec.control_config.declared)
    elif spec.control_config and spec.control_config.synthetic:
        chosen = list(spec.control_config.synthetic)
    elif server_layer:
        chosen = list(spec.control_env)
    else:
        chosen = [w for w in tf.weakness_classes if w in REP_SEED_BY_WEAKNESS]

    usable: list[str] = []
    for c in chosen:
        if server_layer:
            if c not in spec.control_env:
                typer.echo(f"skipping {c}: no control_env toggle declared", err=True)
                continue
        else:
            try:
                make_control(c)
            except ValueError:
                typer.echo(f"skipping {c}: no boundary control implemented", err=True)
                continue
        if c not in REP_SEED_BY_WEAKNESS:
            typer.echo(f"skipping {c}: no representative seed", err=True)
            continue
        usable.append(c)
    if not usable:
        typer.echo(
            "no ablatable controls. Pass --controls W2,W3,W4 or declare weakness_classes / "
            "control_config in the target file.",
            err=True,
        )
        raise typer.Exit(code=EXIT_CONFIG)

    seeds_by_weakness = seeds_for_weaknesses(usable, max_per_weakness=max_seeds)
    sides = 3 if redundancy else 2
    total_scans = sum(len(seeds_by_weakness.get(c, [])) for c in usable) * iterations * sides

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    mode = "all-minus-c (redundancy)" if redundancy else "on/off"
    layer = "server-layer (env toggles)" if server_layer else "adapter-shim"
    typer.echo(
        f"ablate re-drives {spec.family!r} live, toggling {', '.join(usable)} {mode} "
        f"via {layer} ({iterations} run(s) each) — ~{total_scans} scoped scans.",
        err=True,
    )

    def scan_fires(applied: tuple[str, ...], pattern_id: str) -> bool:
        if server_layer:
            # ``applied`` = controls currently ON. The raw side (applied=()) turns
            # them all OFF; the "only C" side leaves only C on. Translate to the
            # complement and disable those server-layer guards via the launch env.
            disable = tuple(c for c in usable if c not in applied)
            adapter = MCPStdioAdapter(
                family=spec.family,
                scope=tf.scope,
                model=effective_model,
                launch_env=spec.launch_env(disable_controls=disable),
            )
        else:
            adapter = MCPStdioAdapter(
                family=spec.family,
                scope=tf.scope,
                model=effective_model,
                controls=[_boundary_control(w, spec) for w in applied],
            )
        return scan_target_fires(
            adapter,
            pattern_id,
            provider=effective_provider,
            model=effective_model,
            customiser_model=effective_model,
            judge_model=effective_model,
        )

    try:
        results = run_control_ablation(
            controls=usable,
            seeds_by_weakness=seeds_by_weakness,
            scan_fires=scan_fires,
            iterations=iterations,
            progress=lambda msg: typer.echo(f"  … {msg}", err=True),
            redundancy=redundancy,
            all_controls=usable,
        )
    finally:
        target_registry.clear_runtime_targets()

    _render_ablation_matrix(results)
    if server_layer and results and all(r.status == "no-attack" for r in results):
        typer.echo(
            "hint: every control classified 'no-attack' — the raw side never fired. "
            "Check that control_env actually disables the server's guard for these "
            "weakness classes, and that the representative seeds reach the surface.",
            err=True,
        )


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
        typer.Option(
            "--framework",
            help="Which framework to list (required): owasp-llm | owasp-asi | atlas | nist.",
        ),
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
