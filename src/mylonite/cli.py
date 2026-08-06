"""Typer CLI for Mylonite.

The end-to-end pipeline (each command also documented via ``--help``):

* ``mylonite scan <target>`` — run the exploit-finding loop against a target
  (the in-process reference twins or your own app via ``--target-file``); pass
  ``--scaffold app.yaml`` (with ``--command``) to introspect a server and write
  a starter target.yaml instead of scanning.
* ``mylonite generate`` — emit a pytest regression test from a confirmed exploit
  (offline, deterministic, no LLM).
* ``mylonite validate`` — run a generated test through the differential-oracle
  validator (live).
* ``mylonite gate`` — scan → generate → validate → optional gating PR, in one command.
* ``mylonite report`` — render a scan/validation as a terminal panel, SARIF, or JSON.
* ``mylonite ablate`` — score which controls are load-bearing vs. theater.
* ``mylonite demo`` / ``doctor`` / ``taxonomy`` / ``version`` — the reference-app
  playground, diagnostics, and supporting utilities.

See the documentation site for guides and the full reference.
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
from typing import Annotated, Any, Final, TypeVar

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print, echo, echo_err, echo_exc
from mylonite._paths import safe_slug
from mylonite.layout import Layout, resolve_layout
from mylonite.scan.tool_roles import _classify_tools, _ToolRoles
from mylonite.version import __version__

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="mylonite",
    help=(
        "Mylonite -- AI-layer security testing.\n\n"
        "Finds app-specific weaknesses in your AI agent's attack surface (system prompt, "
        "tool/function schemas, MCP tools), proves each one with a differential "
        "oracle, and writes the pytest regression test that gates CI."
    ),
    epilog=(
        "Examples:\n\n"
        "`mylonite demo` -- try it on the bundled vulnerable agent (no setup).\n\n"
        "`mylonite scan reference:vulnerable` -- run the attack suite against a target.\n\n"
        "`mylonite scan --command python --arg server.py --scaffold app.yaml` -- "
        "scaffold a target.yaml.\n\n"
        "`mylonite gate --target-file app.yaml --authorize custom --open-pr` -- scan to a gating PR.\n\n"
        "Docs: https://abidemialade.github.io/mylonite/ -- "
        "run 'mylonite COMMAND --help' for any command."
    ),
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

#: The built-in --max-llm-calls default. A Typer option default of ``50`` is
#: indistinguishable from an explicit ``--max-llm-calls 50`` — comparing the
#: resolved value against this literal (``if max_llm_calls == 50``) is exactly
#: the DCR-0004/0012/0015 bug. The option default is ``None`` (see scan()/
#: gate()); this constant is the actual fallback, applied via
#: :func:`_resolve_option`, and is also what ``--help`` displays via
#: ``show_default``.
_DEFAULT_MAX_LLM_CALLS = 50

#: Sane non-None default for ``validate --iteration-timeout`` (DCR-0010): a
#: stuck/slow real custom target must not be able to block a CI job
#: indefinitely just because the flag was left unset. 120s comfortably covers
#: a real subprocess spawn + a multi-turn planner run; pass a larger value
#: explicitly for a target known to need more headroom.
_DEFAULT_ITERATION_TIMEOUT_S: Final = 120.0

_T = TypeVar("_T")


class _CliState:
    """Carried on ``ctx.obj``: the artefact :class:`Layout` resolved once by the
    root callback (``--output-dir``/``--out``/config ``root:`` unavailable yet at
    that point — just the ``MYLONITE_ROOT`` env var and the built-in default).

    A command with its own ``--config``/explicit-flag knowledge re-resolves via
    :func:`_layout_for` instead of reading ``layout`` directly whenever it has a
    more specific ``config_root`` to apply — see ``scan``/``gate``.
    """

    def __init__(self, layout: Layout) -> None:
        self.layout = layout


def _layout_for(ctx: typer.Context, *, config_root: Path | None = None) -> Layout:
    """The effective :class:`Layout` for a command: ``config_root`` (when given)
    re-resolves against the env/default fallback; otherwise reuse the Layout the
    root callback already resolved on ``ctx.obj`` (``isinstance`` guards a ``ctx``
    whose ``obj`` was never populated, e.g. a command invoked directly in a test
    without going through the Typer app).
    """
    if config_root is not None:
        return resolve_layout(config_root=config_root)
    state = ctx.obj
    if isinstance(state, _CliState):
        return state.layout
    return resolve_layout()


def _resolve_option(explicit: _T | None, from_config: _T | None, default: _T) -> _T:
    """Apply the precedence every command's ``--config`` help text promises:
    explicit flag > config file > built-in default.

    A ``None`` sentinel default on the Typer option is what makes "omitted"
    distinguishable from "explicitly set to the default value"; comparing the
    resolved value against the literal default (``if x == 50``) cannot
    (DCR-0004, DCR-0012, DCR-0015, DCR-0005) — 50 IS a valid, meaningful thing
    to explicitly pass.
    """
    if explicit is not None:
        return explicit
    if from_config is not None:
        return from_config
    return default


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
        echo_err(
            "note: Mylonite supports Python 3.11-3.13. litellm has no 3.14 wheels "
            "yet, so live LLM calls may fail to import on this interpreter - use a "
            "3.11-3.13 virtualenv for scan/validate/demo --live."
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
        echo_err(f"env file {path} not found.")
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
            echo_err(f"warning: overriding ambient {key} with the value from {path}.")
        os.environ[key] = value
        loaded.append(key)
    if loaded:
        echo_err(f"loaded {', '.join(sorted(loaded))} from {path}.")


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
        echo_err(f"--api-key-file {path} not found.")
        raise typer.Exit(code=EXIT_CONFIG)
    content = path.read_text(encoding="utf-8").strip()
    first = content.splitlines()[0] if content else ""
    if "=" in first:
        _load_env_file(path)
        return
    key = content.split()[0] if content else ""
    var = _infer_key_env_var(key)
    if var is None:
        echo_err(
            "--api-key-file: couldn't infer the provider from the key shape. Use a "
            "dotenv file with a KEY=VALUE line instead (e.g. ANTHROPIC_API_KEY=…), "
            "or pass --env-file."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if var in os.environ and os.environ[var] != key:
        echo_err(f"warning: overriding ambient {var} with the value from {path}.")
    os.environ[var] = key
    echo_err(f"loaded {var} from {path}.")


@app.callback()
def _root(
    ctx: typer.Context,
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

    Also resolves the artefact :class:`~mylonite.layout.Layout` ONCE here (from
    ``MYLONITE_ROOT`` and the built-in default — a per-command ``--config``'s
    ``root:`` field and an explicit ``--output-dir``/``--out`` flag aren't in
    scope yet at this point) and carries it on ``ctx.obj`` so every command
    reads it from there (via ``_layout_for``) instead of each re-resolving —
    and, critically, instead of any command hardcoding ``.mylonite/...`` itself.
    """
    from mylonite._redaction import install_log_redaction

    _configure_stdio_encoding()
    _maybe_enable_truststore()
    install_log_redaction(enabled=True)
    _warn_unsupported_python()
    ctx.obj = _CliState(layout=resolve_layout())
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
    echo(__version__)


@app.command()
def init(
    output: Annotated[
        Path, typer.Argument(help="Where to write the target.yaml (default: ./target.yaml).")
    ] = Path("target.yaml"),
    transport: Annotated[
        str | None,
        typer.Option(
            "--transport", help="'rest' (HTTP agent) or 'mcp' (stdio server). Prompted if omitted."
        ),
    ] = None,
    url: Annotated[
        str | None, typer.Option("--url", help="For rest: the agent endpoint URL.")
    ] = None,
    command: Annotated[
        str | None, typer.Option("--command", help="For mcp: the server launch command.")
    ] = None,
    arg: Annotated[
        list[str] | None, typer.Option("--arg", help="For mcp: a launch arg (repeatable).")
    ] = None,
    rest_body: Annotated[
        str | None,
        typer.Option("--rest-body", help="For rest: request body template containing {prompt}."),
    ] = None,
    rest_response_path: Annotated[
        str | None,
        typer.Option(
            "--rest-response-path", help="For rest: dotted path into the JSON reply (e.g. reply)."
        ),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite the output file if it exists.")
    ] = False,
) -> None:
    """Guided setup: write a runnable target.yaml for your app (HTTP agent or MCP server).

    An interactive front-end over ``scan --scaffold``: it prompts for what it needs, then
    writes a ready-to-scan target file. A plain HTTP agent needs nothing to introspect; an
    MCP server is launched once to list its tools (no attack, no LLM call). Pass the options
    to skip the prompts (scriptable); omit them to be guided.
    """
    t = (
        (
            transport
            or typer.prompt(
                "Transport — 'rest' (HTTP agent) or 'mcp' (stdio server)", default="rest"
            )
        )
        .strip()
        .lower()
    )
    if t in ("rest", "http", "http-agent"):
        endpoint = url or typer.prompt("Agent endpoint URL (e.g. https://my-agent/v1/chat)")
        _scaffold_rest_target_file(
            output=output,
            rest_url=endpoint,
            rest_body=rest_body,
            rest_response_path=rest_response_path,
            force=force,
        )
    elif t == "mcp":
        cmd = command or typer.prompt("MCP server launch command (e.g. python)")
        _scaffold_target_file(
            output=output,
            command=cmd,
            arg=arg,
            env=None,
            scope=None,
            system_prompt=None,
            system_prompt_file=None,
            model=None,
            force=force,
        )
    else:
        echo_err(f"unknown transport {t!r}; expected 'rest' or 'mcp'.")
        raise typer.Exit(code=EXIT_CONFIG)


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
            echo_exc(f"invalid --config {run_config_path}", exc)
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
            echo_err(
                f"warning: {var} is set but doesn't look like an API key "
                "(too short / contains spaces or path separators). Check it's the "
                "real key, not a placeholder or file path."
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
        echo_err(f"provider check FAILED [{diag.category}] for {routed}")
        echo_err(f"  detail: {redact(diag.detail)}")
        echo_err(f"  remedy: {diag.remedy}")
        raise typer.Exit(code=EXIT_PROVIDER) from exc
    echo(f"provider OK — {effective_provider}/{base_model} reachable (routed: {routed}).")


def _validate_model_string(model: str) -> None:
    """Reject obviously-malformed model ids before they reach LiteLLM."""
    if not model or not model.strip() or model != model.strip():
        echo_err(
            f"invalid --model {model!r}: must be a non-empty model id with no "
            "surrounding whitespace, e.g. claude-sonnet-4-6 or claude-haiku-4-5."
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


def _exit_if_missing_kitchen_sink(exc: BaseException) -> None:
    """Map a missing reference target to a friendly EXIT_CONFIG, else return.

    The deliberately-vulnerable reference target is opt-in (not a base dependency):
    PyPI users get it with ``pip install "mylonite[demo]"``; an editable checkout
    needs ``pip install -e ./reference_targets/mcp_kitchen_sink``. Without it,
    ``demo`` / ``scan reference:*`` / ``validate`` raise ``ModuleNotFoundError`` deep
    in the adapter. Translate that one cause into a clear message everywhere (instead
    of a raw traceback on the scan path); re-raise anything unrelated by returning.
    """
    if (getattr(exc, "name", "") or "").split(".")[0] == "mcp_kitchen_sink":
        echo_err(
            "the reference app target isn't installed (it's opt-in) — run "
            '`pip install "mylonite[demo]"`, or from a checkout '
            "`pip install -e ./reference_targets/mcp_kitchen_sink`."
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc


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
    echo_err(
        f"unknown reference variant {variant!r}; expected reference:vulnerable or reference:guarded"
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
    family: str,
    scope: str | None,
    requires_scope: bool,
    authorize: str | None,
    *,
    command: str = "scan",
) -> None:
    """CLI shim over :func:`mylonite._authz.check_authorization`.

    ``requires_scope`` is accepted for signature compatibility and deliberately
    NOT consulted — the required token is derived from the scope itself
    (DCR-0008: trusting the flag let a target file declare a sensitive scope
    while leaving ``requires_scope: false`` and be authorized with the
    guessable literal family name).
    """
    del requires_scope
    from mylonite._authz import AuthorizationRefused, check_authorization

    try:
        check_authorization(family=family, scope=scope, authorize=authorize, command=command)
    except AuthorizationRefused as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc


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
        echo_err("mcp:custom requires --command (the MCP server launch command).")
        raise typer.Exit(code=EXIT_CONFIG)
    env_map: dict[str, str] = {}
    for item in env or []:
        if "=" not in item:
            echo_err(f"--env must be KEY=VALUE; got {item!r}.")
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
        echo_exc("invalid custom target", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _build_adapter_for_custom(
    target_file: Any, authorize: str | None, model: str, *, command: str = "scan"
) -> Any:
    """Register a custom ``TargetFile`` and return the transport-matched adapter.

    Shared by ``--target-file`` and ``mcp:custom`` flags. Enforces the same
    ``--authorize`` ownership rule as bundled targets, then registers the spec
    so the generic adapter (and seed selection) can resolve it.
    """
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec, payload_placement_warnings

    # R7: warn (don't block) if the planted {payload} isn't a bare natural-language
    # leaf, or is missing entirely — a silently-empty/ill-formed plant otherwise
    # reads as a clean scan.
    for warning in payload_placement_warnings(target_file):
        echo_err(f"warning: {warning}")

    spec = build_target_spec(target_file)
    _enforce_custom_authorize(
        spec.family, target_file.scope, spec.requires_scope, authorize, command=command
    )
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
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc
    return build_mcp_adapter(family=spec.family, scope=target_file.scope, model=model)


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
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Step 2: --authorize scope-match check.
    if family not in target_registry.BUNDLED_TARGETS:
        echo_err(
            f"unknown MCP target family {family!r}. "
            f"Known families: {sorted(target_registry.BUNDLED_TARGETS)}."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    spec = target_registry.BUNDLED_TARGETS[family]
    if spec.requires_scope:
        if authorize != scope:
            echo_err(
                f"--authorize must equal the scope segment for {family!r} "
                f"(scope={scope!r}, authorize={authorize!r}). "
                f"Example: mylonite scan mcp:{family}:{scope or '<scope>'} "
                f"--authorize {scope or '<scope>'}"
            )
            raise typer.Exit(code=EXIT_CONFIG)
    elif authorize != family:
        echo_err(
            f"--authorize must equal the family name for stateless target "
            f"{family!r} (got authorize={authorize!r}). "
            f"Example: mylonite scan mcp:{family} --authorize {family}"
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Step 3: registry resolution (validates scope shape).
    try:
        target_registry.resolve_target(family, scope)
    except (target_registry.InvalidTargetScope, target_registry.UnknownTargetFamily) as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Step 4: construct the right subclass.
    if family == "filesystem":
        return FilesystemMCPAdapter(scope=scope or "", model=model)
    if family == "fetch":
        return FetchMCPAdapter(scope=scope, model=model)
    if family == "github":
        return GitHubMCPAdapter(scope=scope or "", model=model)
    # Unreachable — the registry check above already gated unknown families.
    echo_err(f"no subclass wired for family {family!r}")
    raise typer.Exit(code=EXIT_CONFIG)


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite scan reference:vulnerable` -- attack the bundled vulnerable twin.\n\n"
        "`mylonite scan --target-file app.yaml --authorize my-app` -- attack YOUR MCP app.\n\n"
        "`mylonite scan --command python --arg server.py --scaffold app.yaml` -- introspect\n"
        "a server and write a starter target.yaml (no LLM call, no attack).\n\n"
        "Exit codes: 0 ok | 2 config/usage | 3 budget exceeded | 4 provider unreachable."
    )
)
def scan(
    ctx: typer.Context,
    target: Annotated[
        str | None,
        typer.Argument(
            help=(
                "Target ID: 'reference:vulnerable' / 'reference:guarded' (the "
                "bundled twins), or 'mcp:custom' with --command/--arg flags. "
                "Omit when using --target-file (your own MCP app). Non-reference "
                "targets require --authorize."
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
    scaffold: Annotated[
        Path | None,
        typer.Option(
            "--scaffold",
            help=(
                "Scaffold mode: introspect the MCP server (via --command, no LLM call, "
                "no attack) and write a commented starter target.yaml to this PATH "
                "instead of scanning. Fill in seed_arm/effect_probe, then scan with "
                "--target-file."
            ),
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="With --scaffold, overwrite the output file if it exists."),
    ] = False,
    rest_url: Annotated[
        str | None,
        typer.Option(
            "--rest-url",
            help=(
                "With --scaffold: write a RUNNABLE HTTP-agent (transport: rest) target "
                "for this endpoint instead of introspecting an MCP server. No --command "
                "needed. Pair with --rest-body / --rest-response-path. See docs/http-agent.md."
            ),
        ),
    ] = None,
    rest_body: Annotated[
        str | None,
        typer.Option(
            "--rest-body",
            help=(
                "With --scaffold --rest-url: the request body template (must contain a "
                '{prompt} placeholder). Default: \'{"prompt": "{prompt}"}\'.'
            ),
        ),
    ] = None,
    rest_response_path: Annotated[
        str | None,
        typer.Option(
            "--rest-response-path",
            help=(
                "With --scaffold --rest-url: dotted path into the JSON reply to extract the "
                "agent's response (e.g. choices.0.message.content). Omit to use the whole body."
            ),
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
            help=(
                "Override the model that CRAFTS/REFINES attack payloads (the red-team / "
                "attacker side). Defaults to --model. Mylonite separates "
                "three model roles: planner (the agent under test), customiser (the attacker), "
                "and judge (the verdict) -- set them independently to mix a strong attacker "
                "against a cheaper target, etc."
            ),
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help=(
                "Override the model that JUDGES whether an attack landed (the LLM-judge leg, "
                "used only when the deterministic predicate is inconclusive). Defaults to --model."
            ),
        ),
    ] = None,
    max_llm_calls: Annotated[
        int | None,
        typer.Option(
            "--max-llm-calls",
            help="Process-wide LLM call cap for this scan.",
            show_default=str(_DEFAULT_MAX_LLM_CALLS),
        ),
    ] = None,
    max_concurrent: Annotated[
        int,
        typer.Option("--max-concurrent", help="Max concurrent in-flight seeds."),
    ] = 3,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            help=(
                "Root directory for scan artefacts (default: the resolved layout's "
                "scans dir, normally .mylonite/scans — see mylonite.yaml `root:` / "
                "MYLONITE_ROOT)."
            ),
        ),
    ] = None,
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
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help="Required for non-reference targets; assert ownership of the target.",
        ),
    ] = None,
    purpose: Annotated[
        str | None,
        typer.Option(
            "--purpose",
            help=(
                "One-line description of what the app is for (e.g. 'an email-triage "
                "assistant that can send replies'). Tailors the probes to the app's "
                "domain. Overrides 'purpose' in the target file; persisted for a custom "
                "target so generate/validate reuse it."
            ),
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
    config_root: Path | None = None
    if run_config_path is not None:
        from mylonite.config import load_run_config

        try:
            rc = load_run_config(run_config_path)
        except Exception as exc:
            echo_exc(f"invalid --config {run_config_path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        max_llm_calls = _resolve_option(max_llm_calls, rc.max_llm_calls, _DEFAULT_MAX_LLM_CALLS)
        config_root = rc.root
    else:
        max_llm_calls = _resolve_option(max_llm_calls, None, _DEFAULT_MAX_LLM_CALLS)

    # The resolved artefact Layout: an explicit --output-dir always wins outright
    # (below); absent that, mylonite.yaml's `root:` / MYLONITE_ROOT / the built-in
    # default decide where scan artefacts land — and, by construction, where
    # `generate --latest` later looks for them (both read mylonite.layout.Layout).
    layout = _layout_for(ctx, config_root=config_root)
    effective_output_dir = output_dir if output_dir is not None else layout.scans

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
    # Effective app purpose: the --purpose flag, else the target file's declared
    # purpose (resolved in the custom-target branch below). None for a reference
    # target unless the flag is set.
    effective_purpose = purpose
    effective_judge_model = _resolve_role_model(judge_model)

    # Scaffold mode: introspect a custom MCP server and write a starter target.yaml
    # instead of scanning. No LLM call and no attack, so it does NOT require
    # --authorize (this folds the former `init-target` command into `scan`).
    if scaffold is not None:
        if rest_url is not None:
            _scaffold_rest_target_file(
                output=scaffold,
                rest_url=rest_url,
                rest_body=rest_body,
                rest_response_path=rest_response_path,
                force=force,
            )
            return
        _scaffold_target_file(
            output=scaffold,
            command=command,
            arg=arg,
            env=env,
            scope=scope,
            system_prompt=system_prompt,
            system_prompt_file=system_prompt_file,
            model=model,
            force=force,
        )
        return

    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    # 'reference:*' + --target-file is never meaningful — the reference targets
    # are bundled in-process twins with no target file of their own. The custom-
    # target branch below (`target_file is not None or target == "mcp:custom"`)
    # is checked BEFORE the reference branch, so passing both would silently
    # ignore the 'reference:...' positional argument entirely and scan
    # --target-file instead — surprising for an operator who typed a
    # 'reference:' target expecting the bundled twin, and who would now hit an
    # unexpected --authorize requirement. (Unlike `gate`'s #24 fix, `scan` never
    # computed a separate `is_reference`-style variable read downstream —
    # `report_target_id` is always set INSIDE the branch that actually ran, so
    # there is no oracle/routing-divergence bug here, just this silent-argument-
    # ignoring footgun.) Reject the combination up front with a clear message.
    if target is not None and target.startswith("reference:") and target_file is not None:
        echo_err(
            "scan: 'reference:*' targets are bundled in-process twins and don't take "
            "--target-file. Pass a custom target via --target-file alone (drop the "
            "'reference:' target argument), or drop --target-file to scan the "
            "reference twin."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # For a custom target we persist the resolved target YAML next to the scan
    # (below, after artefacts are written) so `generate`/`validate` can re-resolve
    # it without the operator re-passing --target-file at every step.
    custom_target_yaml: str | None = None
    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp (both YAML and inline flags converge here).
        if not authorize:
            echo_err("--authorize is required for custom targets. See SECURITY.md.")
            raise typer.Exit(code=EXIT_CONFIG)
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:  # YAML / validation errors → exit 2
                echo_exc(f"invalid --target-file {target_file}", exc)
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
            effect_probe_warnings,
            infer_seed_arm,
            needs_seed_arm_autowire,
            validate_for_scan,
        )

        # The persisted target.yaml must describe the target that ACTUALLY ran.
        # Copying the source verbatim after M3 auto-wires a seed_arm (or --purpose
        # overrides the target's declared purpose) would produce a scan dir whose
        # target.yaml is missing the seed_arm the findings depended on, contradicting
        # the adjacent "reproducible from the scan dir alone" guarantee
        # (DCR-0005/0016/0006).
        tf_mutated = False

        # M3: auto-wire the seed_arm from the LIVE tool surface when a W2 target omits
        # it, so a real app needs near-zero config instead of the hard block below.
        # Only when a no-id recall path exists (else the plant wouldn't be delivered —
        # the "plants but never lands" trap). Best-effort: a describe failure leaves the
        # pre-flight block to handle it. Skipped on --dry-run / --allow-no-seed-arm.
        # When no plantable store->recall pair exists, a content-processing tool
        # (e.g. process_document) makes W2 testable via the direct_content channel
        # (descriptor synthesis), so the seed-arm pre-flight must NOT block.
        synth_covers_indirect = False
        # A rest (HTTP-agent) target has no tool surface to introspect or plant into;
        # W2 rides in as direct prompt injection (seed_synth), so skip seed_arm
        # auto-wiring and let the (rest-exempt) pre-flight pass.
        if (
            tf.transport != "rest"
            and needs_seed_arm_autowire(tf)
            and not dry_run
            and not allow_no_seed_arm
        ):
            try:
                _probe = _build_adapter_for_custom(tf, authorize, effective_planner_model)
                _descriptor = asyncio.run(asyncio.wait_for(_probe.describe(), timeout=20))
            except Exception as exc:
                _descriptor = None
                echo_err(
                    f"auto-wire: could not describe the target to infer a seed_arm "
                    f"({type(exc).__name__}); falling back to the pre-flight check."
                )
            if _descriptor is not None:
                _spec, _note = infer_seed_arm(_descriptor.tools)
                echo_err(f"auto-wire: {_note}")
                if _spec is not None:
                    tf = tf.model_copy(update={"seed_arm": _spec})
                    tf_mutated = True
                else:
                    from mylonite.scan.tool_roles import content_processor_tools

                    if content_processor_tools(_descriptor.tools):
                        synth_covers_indirect = True
                        echo_err(
                            "auto-wire: no store->recall pair, but a content-processing "
                            "tool exposes the direct_content channel — W2 is tested via "
                            "descriptor synthesis (no seed_arm needed)."
                        )

        # Blocking pre-flight (PR3): a target declaring an indirect-injection-only
        # weakness class with no seed_arm would silently skip those seeds and read
        # as clean. Block a REAL scan with a fix hint unless --allow-no-seed-arm is
        # set (or M3 auto-wired one above). A --dry-run only enumerates seeds (no
        # clean/finding verdict to mislead), so there we downgrade the block to a warning.
        preflight_errors = validate_for_scan(
            tf, allow_no_seed_arm=allow_no_seed_arm or synth_covers_indirect
        )
        if preflight_errors:
            for err in preflight_errors:
                level = "warning" if dry_run else "error"
                echo_err(f"{level}: {err}")
            if not dry_run:
                raise typer.Exit(code=EXIT_CONFIG)

        # Non-fatal: a W3/W4 (side-effecting) target with no effect_probe can't
        # confirm the effect on a real target, so a vulnerable target may read as
        # clean. Warn loudly (the scan still runs) — never a silent under-detection.
        for warn in effect_probe_warnings(tf):
            echo_err(f"warning: {warn}")

        # Resolve the effective purpose: an explicit --purpose flag wins and is
        # persisted into the target so generate/validate reuse it; otherwise the
        # target file's declared purpose is used.
        if purpose is not None:
            tf = tf.model_copy(update={"purpose": purpose})
            tf_mutated = True
        effective_purpose = tf.purpose

        # Copy the source YAML verbatim (preserves operator comments/structure)
        # when given a file AND nothing mutated it since; otherwise serialise the
        # (possibly-mutated) target so the persisted YAML matches the target that
        # ACTUALLY ran — a --purpose override, an M3 seed_arm auto-wire, or an
        # inline mcp:custom target must all be reflected here (DCR-0005/0016/0006).
        custom_target_yaml = (
            target_file.read_text(encoding="utf-8")
            if target_file is not None and not tf_mutated
            else dump_target_file(tf)
        )
        adapter = _build_adapter_for_custom(tf, authorize, effective_planner_model)
        report_target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
    elif target is None:
        echo_err("no target given. Pass a target (e.g. reference:vulnerable) or --target-file.")
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_planner_model)
        report_target_id = target
    elif target.startswith("mcp:"):
        if not authorize:
            echo_err(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_mcp(target, authorize, effective_planner_model)
        report_target_id = target
    else:
        echo_err(
            f"unknown target shape {target!r}. "
            "Expected 'reference:<variant>', 'mcp:<family>[:<scope>]', 'mcp:custom', "
            "or --target-file."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    try:
        all_modules: list[Any] = discover("mylonite.attack_modules")
    except Exception as exc:
        echo_exc("plugin discovery failed", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # v0.2 attack modules: filter to the real prompt-injection family. The
    # reference_example stub is shipped for plugin authors but isn't useful
    # for a real scan.
    attack_modules = [m for m in all_modules if m.attack_metadata().id in _V0_2_ATTACK_FAMILIES]
    if not attack_modules:
        echo_err(
            "no usable attack modules discovered "
            "(looking for 'prompt-injection-family' or 'excessive-agency-family')"
        )
        raise typer.Exit(code=EXIT_CONFIG)

    customiser = PayloadCustomiser(model=effective_customiser_model, purpose=effective_purpose)
    judge = SuccessJudge(model=effective_judge_model)

    config = ScanConfig(
        target_id=report_target_id,
        provider=effective_provider,
        model=effective_model,
        planner_model=effective_planner_model if planner_model else None,
        customiser_model=effective_customiser_model if customiser_model else None,
        judge_model=effective_judge_model if judge_model else None,
        max_llm_calls=max_llm_calls,
        max_concurrent=max_concurrent,
        output_dir=effective_output_dir,
        dry_run=dry_run,
    )

    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=attack_modules,
        customiser=customiser,
        judge=judge,
    )

    try:
        result = asyncio.run(engine.run())
    except (ModuleNotFoundError, ImportError) as exc:
        # `scan reference:*` lazily imports the bundled reference target inside the
        # adapter; on an editable checkout without it this surfaces here. Fail with
        # the same friendly message `demo` gives, not a raw traceback.
        _exit_if_missing_kitchen_sink(exc)
        raise

    from mylonite._redaction import redact, redact_target_yaml

    if not dry_run:
        from mylonite.scan.artefacts import render_summary, write_artefacts

        # Persist artefacts UN-redacted (they are loadable/replayable data); only
        # the console-rendered summary string is redacted before display.
        scan_dir = write_artefacts(result, effective_output_dir)
        # Co-locate the resolved target YAML so `generate`/`validate` auto-resolve
        # it from the scan dir — the custom-target journey needs the path ONCE.
        # Never persist it verbatim: request.headers and env may carry live
        # credentials, and the scan dir is one the operator is told to commit
        # (DCR-0006).
        if custom_target_yaml is not None:
            (scan_dir / "target.yaml").write_text(
                redact_target_yaml(custom_target_yaml), encoding="utf-8"
            )
        echo(redact(render_summary(result)))
        echo(f"Artefacts: {scan_dir}")
        # "Next:" hint — point at the very next command so the flow is self-guiding.
        if result.report.findings_count > 0:
            echo("")
            echo(f"Next: mylonite generate {scan_dir}")
    else:
        # Dry-run: render summary without writing files.
        from mylonite.scan.artefacts import render_summary

        echo(redact(render_summary(result)))

    # C4 / G5 / A1: the exit code is derived from ScanOutcome — the single
    # "did this scan actually work" authority (mylonite.scan.coverage) — rather
    # than hand-matching `result.report.aborted` here. That hand-matching used
    # to fall through to EXIT_SUCCESS for any report that wasn't formally
    # `aborted`, which missed the case where every attempt errored (e.g.
    # missing/invalid provider credentials) without ever tripping the
    # consecutive-failures threshold that sets `aborted="provider_unreachable"`
    # (too few applicable attempts to reach it) — `scan` would print a summary
    # and exit 0, indistinguishable from a genuine clean pass. ScanOutcome
    # closes that gap (it was already closed for `gate` — see coverage.py).
    # For the 5 previously-handled abort reasons this is behaviour-identical:
    # ScanOutcome's exit-code mapping and operator_message text were extracted
    # verbatim from this exact block.
    from mylonite.scan.coverage import ScanOutcome

    outcome = ScanOutcome.from_report(result.report)
    if outcome.operator_message:
        echo_err(outcome.operator_message)
    raise typer.Exit(code=outcome.exit_code)


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
    """Run the zero-config reference-app playground: vulnerable vs guarded differential.

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
        _exit_if_missing_kitchen_sink(exc)
        raise

    # Replay is pinned to the recorded provider/model — never silently drop the
    # override flags.
    if not live and (provider is not None or model is not None):
        echo_err(
            "warning: --provider/--model are ignored in replay mode — the demo "
            f"replays fixtures recorded against {DEMO_PROVIDER}/{DEMO_MODEL} "
            "(claude-haiku-4-5-20251001). Pass --live to use a different "
            "provider/model."
        )

    try:
        result = asyncio.run(run_demo(live=live, provider=provider, model=model))
    except (MissingFixtureError, DemoFixtureError) as exc:
        echo_exc(
            "demo fixtures missing or stale — reinstall mylonite, or run "
            "`mylonite demo --live` with a provider configured",
            exc,
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except CorruptFixtureError as exc:
        echo_exc("demo", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except (ModuleNotFoundError, ImportError) as exc:
        _exit_if_missing_kitchen_sink(exc)
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
            echo_err(
                "no provider reachable — set ANTHROPIC_API_KEY, or pass "
                "--provider/--model for another LiteLLM provider."
            )
            raise typer.Exit(code=EXIT_PROVIDER)
        if variant.report.aborted == "budget_exceeded":
            echo_err(
                "demo budget exceeded before both variants completed "
                "(max_llm_calls=100 per variant)."
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
            echo_err(
                f"no exploit_*.json found in {scan_path}. "
                "Run `mylonite scan <target>` first, or pass an exploit_*.json directly."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        echo_err(
            f"path not found: {scan_path}. Pass a scan dir or an exploit_*.json, "
            "or run `mylonite scan <target>` first."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    if latest:
        scan_dir = _find_latest_scan_dir(scans_root)
        if scan_dir is None:
            echo_err(f"no scans found under {scans_root}. Run `mylonite scan <target>` first.")
            raise typer.Exit(code=EXIT_CONFIG)
        found = _exploits_in_dir(scan_dir)
        if not found:
            echo_err(
                f"the latest scan ({scan_dir}) found no exploits — nothing to generate. "
                "A no-finding scan is a PASS, not an error: it usually means the target "
                "is clean or guarded. To generate from an earlier scan that DID find "
                "something, pass that scan dir explicitly, e.g. "
                "`mylonite generate .mylonite/scans/<earlier-run>`."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        return found

    echo_err(
        "no input given. Pass a SCAN_PATH (an exploit_*.json or a scan dir), or "
        "--latest to use the newest scan under .mylonite/scans/. Run "
        "`mylonite scan <target>` first if you have no scans yet."
    )
    raise typer.Exit(code=EXIT_CONFIG)


def _map_compliance(exploit: Any, mapper: Any | None = None) -> Any:
    """Enrich a finding's compliance tags via the reference mapper (derives NIST
    from the OWASP tags using the bundled taxonomy cross-refs).

    ``mapper``, when supplied, is reused instead of constructing a fresh
    ``ReferenceComplianceMapper()`` — a caller looping over many findings (e.g.
    ``report``'s per-exploit-file loop) can build one and pass it in (DCR-0014
    perf) instead of paying construction + import overhead per finding.
    """
    if mapper is None:
        from mylonite.plugins._reference.reference_compliance_mapper import (
            ReferenceComplianceMapper,
        )

        mapper = ReferenceComplianceMapper()
    return exploit.model_copy(update={"compliance": mapper.map(exploit)})


def _emit_generated_test(
    exploit: Any,
    exploit_path: Path,
    out_dir: Path,
    target_file: Path | None,
    *,
    json_mod: Any,
    validated_target_files: set[Path] | None = None,
) -> None:
    """Emit one regression test (+ co-located exploit/fixtures/target) for one
    exploit, echoing the per-test ``Wrote …`` lines and next-step guidance.

    Factored out of :func:`generate` so a multi-finding scan dir can emit one
    test per finding into per-pattern subdirs. The single-exploit output is
    unchanged.

    ``validated_target_files``, when supplied, is a cache of target-file paths
    already loaded+validated (by this call or an earlier one in the same
    multi-finding loop) — a multi-finding scan dir re-invokes this once per
    exploit, all typically against the SAME target file, so re-parsing and
    re-validating the identical YAML on every finding is pure overhead
    (DCR-0013/0009 perf). Absent (``None``), every call validates independently
    — the original, always-correct behaviour.
    """
    from mylonite._redaction import redact_target_yaml
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
    colocated_exploit = out_dir / f"exploit_{safe_slug(enriched.pattern_id)}.json"
    colocated_exploit.write_text(
        json_mod.dumps(enriched.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    fixtures_dir = out_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    echo(f"Wrote test:    {test_path}")
    echo(f"Wrote exploit: {colocated_exploit}")
    echo(f"Fixtures dir:  {fixtures_dir}")

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
            echo(f"Using target:  {candidate} (from the scan dir)")
    if target_file is not None:
        resolved_target_file = target_file.resolve()
        if validated_target_files is None or resolved_target_file not in validated_target_files:
            from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

            try:
                build_target_spec(load_target_file(target_file))  # validate before copying
            except Exception as exc:
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
            if validated_target_files is not None:
                validated_target_files.add(resolved_target_file)
        colocated_target = out_dir / "target.yaml"
        # Never copy a target file verbatim into a directory we tell the operator
        # to commit: request.headers and env may carry live credentials (DCR-0010).
        colocated_target.write_text(
            redact_target_yaml(target_file.read_text(encoding="utf-8")), encoding="utf-8"
        )
        echo(f"Wrote target:  {colocated_target}")
        echo_err(
            "note: credential-shaped values in the copied target.yaml were masked. "
            "Restore them from your secret store (or reference them via env) before "
            "running the emitted test."
        )
    elif is_custom:
        echo("")
        echo_err(
            f"warning: {exploit.target_id} is a custom target - the emitted test re-drives "
            "your real app and needs a co-located target.yaml. Re-run with "
            "`--target-file <your-target>.yaml`, or copy your scan's target YAML into "
            f"{out_dir} as target.yaml. Without it the test errors at runtime."
        )

    echo("")
    if is_custom:
        # The custom test is LIVE (gated behind MYLONITE_LIVE_TARGET=1): it needs
        # pytest, a provider key, a runnable MCP server, and the co-located YAML.
        echo("Next - this is a LIVE custom-target test. To run it you need:")
        echo("  - pytest + mylonite installed in the consuming environment")
        echo("  - your provider API key set (e.g. ANTHROPIC_API_KEY)")
        echo("  - your target's MCP server runnable, and target.yaml co-located")
        echo("Then:")
        echo(f"  MYLONITE_LIVE_TARGET=1 pytest {out_dir}")
        # validate auto-resolves the co-located target.yaml — no --target-file needed.
        echo(f"  mylonite validate {out_dir}")
    else:
        echo(f"Next: mylonite validate {out_dir}")


def _tag_control_for_generate(exploit: Any) -> Any:
    """Stamp ``synthetic_control`` so the generator emits an ``assert_control_holds``
    test (``generate --prove-control``), turning the control-efficacy oracle's
    verdict into a committable CI gate.

    Passes the exploit through unchanged (with a notice) for a reference target or
    a weakness with no boundary control — those can't be emitted as a committable
    custom-target control test. Mirrors the tagging ``gate`` does by default.
    """
    from mylonite.gate.mitigation import weakness_class_for
    from mylonite.scan.control_shim import make_control

    if exploit.target_id.startswith("reference:"):
        echo_err(
            f"--prove-control: {exploit.pattern_id} targets a reference twin; emitting "
            "the standard guard test instead."
        )
        return exploit
    cw = weakness_class_for(exploit)
    try:
        make_control(cw)
    except ValueError:
        echo_err(
            f"--prove-control: no boundary control for weakness {cw!r} "
            f"({exploit.pattern_id}); emitting the standard target-resists test instead."
        )
        return exploit
    meta = {**exploit.payload.metadata, "synthetic_control": cw}
    return exploit.model_copy(
        update={"payload": exploit.payload.model_copy(update={"metadata": meta})}
    )


@app.command()
def generate(
    ctx: typer.Context,
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
        typer.Option("--latest", help="Use the newest scan under the resolved scans dir."),
    ] = False,
    scans_dir: Annotated[
        Path | None,
        typer.Option(
            "--scans-dir",
            help=(
                "The directory `scan --output-dir` wrote to, when using --latest "
                "(default: the resolved layout's scans dir, normally .mylonite/scans). "
                "An INPUT — where --latest searches for a scan to read, not where "
                "this command writes; for the emitted test's output dir see --out. "
                "Ignored if you pass SCAN_PATH explicitly instead of --latest."
            ),
        ),
    ] = None,
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
    from mylonite.plugins._reference.reference_pytest_generator import (
        UnsafeExploitRecord,
    )

    # No --config on `generate` (kept minimal): absent an explicit --scans-dir,
    # the resolved Layout is MYLONITE_ROOT / the built-in default, via the root
    # callback (ctx.obj) — the SAME resolution `scan`'s own default --output-dir
    # uses, so a scan written under a root moved by mylonite.yaml/MYLONITE_ROOT is
    # found here too. An explicit --scans-dir (highest priority; an INPUT read by
    # --latest, deliberately NOT named --output-dir like scan's own flag — that
    # name would mislead as "where generate writes", which is --out's job) points
    # --latest at that exact scans root directly, closing the "generate --latest
    # hardcodes .mylonite/scans" bug outright: a scan written to a one-off custom
    # dir via `scan --output-dir X` is found by `generate --latest --scans-dir X`.
    # Silently unused when SCAN_PATH is passed explicitly instead of --latest —
    # consistent with how --latest itself is already ignored in that case (see
    # _resolve_exploit_paths: an explicit scan_path short-circuits before either
    # is consulted).
    layout = _layout_for(ctx)
    scans_root = scans_dir if scans_dir is not None else layout.scans
    exploit_paths = _resolve_exploit_paths(scan_path, latest, scans_root)
    multi = len(exploit_paths) > 1

    if multi:
        echo(f"Found {len(exploit_paths)} findings - emitting one test each.")
        echo("")

    # Validate an explicit --target-file ONCE, up front (fail fast before emitting
    # anything), rather than re-loading + re-validating the identical YAML once per
    # exploit inside the loop below (DCR-0013/0009 perf). The cache also covers the
    # auto-resolved (scan-dir-co-located) target.yaml case across iterations, since a
    # multi-finding scan dir's findings share the same co-located target.
    validated_target_files: set[Path] = set()
    if target_file is not None:
        from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

        try:
            build_target_spec(load_target_file(target_file))
        except Exception as exc:
            echo_exc(f"invalid --target-file {target_file}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        validated_target_files.add(target_file.resolve())

    for index, exploit_path in enumerate(exploit_paths):
        try:
            exploit = testkit.load_exploit(exploit_path)
        except (FileNotFoundError, ValueError) as exc:
            echo_exc(f"could not load exploit at {exploit_path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        if prove_control:
            exploit = _tag_control_for_generate(exploit)

        # With multiple findings, give each its own subdir so tests don't clobber
        # each other; a single finding keeps the exact dir the operator chose.
        if out is not None:
            this_out = out / _slugify_pattern(exploit.pattern_id) if multi else out
        else:
            this_out = layout.generated_for(_slugify_pattern(exploit.pattern_id))

        if multi and index > 0:
            echo("")
        # exploit_*.json is a user-editable artefact (hand-edited or stale from
        # before pattern_id validation existed), so a hostile/unsafe pattern_id
        # must degrade to a clean error here too, not just at the unit-tested
        # ReferencePytestGenerator.emit() boundary.
        try:
            _emit_generated_test(
                exploit,
                exploit_path,
                this_out,
                target_file,
                json_mod=json,
                validated_target_files=validated_target_files,
            )
        except UnsafeExploitRecord as exc:
            echo_exc(f"could not generate a test for {exploit_path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

    raise typer.Exit(code=EXIT_SUCCESS)


def _boundary_control(weakness: str, spec: Any) -> Any:
    """Build a boundary control for ``weakness``, applying the target's ControlConfig
    hints (declared egress / consequential / read tools, URL param, allowlist) when
    present; falls back to the control's name heuristics, then a fail-closed default,
    otherwise."""
    from mylonite.scan.control_shim import make_control

    cfg = getattr(spec, "control_config", None)
    if cfg is None:
        return make_control(weakness)
    return make_control(
        weakness,
        read_tool_names=frozenset(cfg.read_tool_names) or None,
        egress_tools=frozenset(cfg.egress_tools) or None,
        url_param=cfg.egress_url_param,
        fetch_allowlist=tuple(cfg.fetch_allowlist) or None,
        consequential_tools=frozenset(cfg.consequential_tools) or None,
    )


def _guarded_factory(spec: Any, scope: str | None, model: str, weakness: str) -> Any:
    """Build the GUARDED side of a custom-target differential for ``weakness``.

    Parity with ``ablate``'s server-layer mode: when the target declares a
    server-layer toggle for this weakness (``control_env``), the guarded twin is
    the REAL default launch (the server's own guard ON), so the differential
    measures the actual server-layer control. Otherwise it falls back to the
    adapter-boundary shim — a low-fidelity stand-in that cannot see server-side
    guards (the verdict is reframed honestly in that case; see
    ``DifferentialValidator(guarded_is_server_layer=...)``).
    """
    from mylonite.plugins._mcp.factory import build_mcp_adapter

    if weakness in getattr(spec, "control_env", {}):
        # Real server, guard ON (default launch) — no boundary shim, no env toggle.
        return build_mcp_adapter(family=spec.family, scope=scope, model=model)
    return build_mcp_adapter(
        family=spec.family,
        scope=scope,
        model=model,
        controls=[_boundary_control(weakness, spec)],
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
    from mylonite.plugins._mcp.factory import build_mcp_adapter

    if getattr(spec, "vulnerable_launch", None) is None:
        return build_mcp_adapter(family=spec.family, scope=scope, model=model)
    return build_mcp_adapter(
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
    not the model, carries the security — is the core differentiator. It now runs BY DEFAULT for a
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
    randomize_exfil: bool = False,
    fast: bool = False,
    prove_input_control: bool = False,
    authorize: str | None = None,
) -> Any:
    """Validate a custom-target test by re-driving the REAL target (R1/R8).

    DCR-0009: this re-drives a real third-party target — sending live attack
    payloads (including exfil) — so it is gated by the same ``--authorize``
    rule as ``scan``/``gate`` (:func:`_enforce_custom_authorize`), not zero
    checks.
    """
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
    )

    if target_file is None:
        echo_err(
            "validating a custom-target test requires --target-file (the same target "
            "YAML you scanned); the validator re-drives the real target."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        echo_exc(f"invalid --target-file {target_file}", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    _enforce_custom_authorize(
        spec.family, tf.scope, spec.requires_scope, authorize, command="validate"
    )

    # DCR-0008: fail fast on an unreachable provider with a distinct exit 4 —
    # otherwise the full N-iteration live loop against the REAL target would
    # just run to a misleading non-discriminating REJECTED. Always AFTER the
    # authorize check above: authorization gates every live-driving action,
    # and this preflight (a scan against the bundled reference twin, never the
    # operator's real target) must not fire before an unauthorized request is
    # rejected.
    try:
        reachable = _provider_preflight(provider, model)
    except (ModuleNotFoundError, ImportError) as exc:
        _exit_if_missing_kitchen_sink(exc)
        raise
    if not reachable:
        echo_err(
            "no provider reachable — set ANTHROPIC_API_KEY, or pass "
            "--provider/--model for another LiteLLM provider."
        )
        raise typer.Exit(code=EXIT_PROVIDER)

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)

    # M1: the differential leg (re-driving a guarded twin of the SAME real target,
    # model held constant) gates `kept` BY DEFAULT — proving the *safeguard*, not the
    # model, carries the security. `--fast` opts out (it doubles the live runs per
    # finding); a weakness with no inferable control falls back loudly to the
    # stability/effect/consensus gate.
    run_diff, control_weakness, diff_note = _differential_plan(generated.exploit, fast=fast)
    echo_err(f"validate: {diff_note}")
    if not randomize_exfil:
        echo_err(
            "note: --no-randomize-exfil is set, so the result only proves the target blocks the "
            "one demo literal, not exfil to ANY attacker address. Drop it (randomization is the "
            "default for custom targets) to avoid 'teaching to the test'."
        )

    # Does the target declare a SERVER-LAYER toggle for this control (control_env)?
    # If so, the differential measures the REAL server guard at parity with `ablate`:
    # the raw side env-disables THIS control (other guards stay ON), the guarded side
    # is the real default launch. Otherwise both sides use the adapter-boundary shim —
    # a low-fidelity stand-in that cannot see server-side guards, so the verdict is
    # reframed honestly (DifferentialValidator(guarded_is_server_layer=...)).
    server_layer = control_weakness is not None and control_weakness in spec.control_env

    # A black-box HTTP agent (transport: rest) has no adapter-boundary control we can
    # apply — HTTPAgentAdapter has no tool surface for the W1/W2 envelope, so a
    # boundary-guarded twin would be BYTE-IDENTICAL to the raw target and wrongly
    # REJECT a real finding. By default fall back to the non-differential gate
    # (stability + effect + consensus). With --prove-input-control the operator opts
    # into an INPUT data-framing ("spotlighting") differential — raw vs a build that
    # wraps the payload as untrusted data — to measure whether that realistic input
    # defence is load-bearing for their agent. `--fast` (skip the differential leg)
    # takes precedence over --prove-input-control: without this guard the plan
    # printed above ("--fast: skipping the differential leg") would be silently
    # contradicted by re-enabling it here (DCR-0017).
    rest_input_frame = (
        prove_input_control and spec.transport == "rest" and not server_layer and not fast
    )
    if fast and prove_input_control and spec.transport == "rest" and not server_layer:
        # Re-emit the diff note: the printed plan must match what actually runs.
        echo_err(
            "validate: --fast overrides --prove-input-control — the differential leg "
            "(including the input data-framing check) stays skipped."
        )
    if rest_input_frame:
        run_diff = True
        control_weakness = control_weakness or "W2"
        echo_err(
            "validate: rest input-control differential — raw vs input data-framing "
            "(spotlighting). `kept` means input framing IS load-bearing for this attack."
        )
    elif spec.transport == "rest" and not server_layer:
        run_diff = False
        echo_err(
            "validate: rest (HTTP-agent) target — the boundary-control differential does "
            "not apply to a black box, so `kept` is decided by stability + effect + consensus "
            "(not the control-efficacy differential). Declare control_env / vulnerable_launch "
            "for a server-layer differential, or pass --prove-input-control to test input "
            "data-framing."
        )

    if spec.vulnerable_launch is not None or server_layer:
        echo_err(
            f"validate: the raw side runs {spec.family!r} with the "
            f"{control_weakness or 'target'} guard DISABLED (deliberately unguarded) — "
            "ensure you are authorized to run it. Env values are never logged."
        )

    def _factory() -> Any:
        if server_layer:
            if control_weakness is None:
                raise RuntimeError(
                    "internal error: server_layer is True but control_weakness is "
                    "None — server_layer is defined as "
                    "`control_weakness is not None and control_weakness in "
                    "spec.control_env`, so this should be unreachable"
                )
            return build_mcp_adapter(
                family=spec.family,
                scope=tf.scope,
                model=model,
                launch_env=spec.launch_env(disable_controls=(control_weakness,)),
            )
        return _vulnerable_adapter(spec, tf.scope, model)

    guarded_factory: Any = None
    control_context: str | None = None
    if run_diff and rest_input_frame:
        # Guarded build = the SAME HTTP agent driven with input data-framing applied.
        control_context = "Control: input data-framing (spotlighting)"

        def _guarded() -> Any:
            return build_mcp_adapter(
                family=spec.family, scope=tf.scope, model=model, input_frame=True
            )

        guarded_factory = _guarded
    elif run_diff and control_weakness is not None:
        from mylonite.gate.mitigation import _snippet

        cw = control_weakness
        # Name the control in force for the report (control-efficacy oracle).
        control_context = f"Control {cw}: {_snippet(cw)}"

        def _guarded() -> Any:
            return _guarded_factory(spec, tf.scope, model, cw)

        guarded_factory = _guarded

    if server_layer:
        twin_kind = "real server-layer twin"
    elif rest_input_frame:
        twin_kind = "input data-framing guard"
    elif run_diff:
        twin_kind = "synthetic boundary twin"
    else:
        twin_kind = "none (differential not applicable to a black-box target)"
    echo_err(
        f"validate re-drives the REAL target {spec.family!r} live — {iterations} runs "
        f"+ multi-judge consensus + effect probe (guarded side: {twin_kind})."
    )
    if run_diff and not server_layer and not rest_input_frame:
        bar = "=" * 74
        echo_err(
            f"{bar}\n"
            "BOUNDARY-PROXY CAVEAT: the guarded side is a SYNTHETIC control Mylonite\n"
            "applies at the adapter boundary, NOT your server's own guard. A kept\n"
            "finding proves a canonical control WOULD be load-bearing for this model --\n"
            "not that your implementation is. For the strong, server-side claim, declare\n"
            "control_env or vulnerable_launch in your target.yaml (see docs/concepts.md).\n"
            f"{bar}"
        )
    validator = DifferentialValidator(
        iterations=iterations,
        provider=provider,
        model=model,
        target_adapter_factory=_factory,
        guarded_adapter_factory=guarded_factory,
        control_weakness=control_weakness,
        randomize_exfil=randomize_exfil,
        guarded_is_server_layer=server_layer,
        control_context=control_context,
        iteration_timeout_s=iteration_timeout_s,
        progress_cb=lambda msg: echo_err(f"  … {msg}"),
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
        echo_err(
            f"target not found: {target}. Pass the dir (or test file) emitted by "
            "`mylonite generate`."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    exploit_matches = sorted(gen_dir.glob("exploit_*.json"))
    if not exploit_matches:
        echo_err(
            f"no exploit_*.json found in {gen_dir}. Re-run `mylonite generate` to "
            "emit a test + its co-located exploit."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    test_matches = sorted(gen_dir.glob("test_security_*.py"))
    if not test_matches:
        echo_err(f"no test_security_*.py found in {gen_dir}. Re-run `mylonite generate`.")
        raise typer.Exit(code=EXIT_CONFIG)

    return test_matches[0], exploit_matches[0]


def _render_validation_report(report: Any, console: Console | None = None) -> None:
    """Render a per-leg Rich report (F4): one row per ValidationOutcome.

    This is the core differentiator's SHOWCASE surface, so it is made ASCII-safe independently
    of the root callback's UTF-8 forcing: a legacy cp1252 Windows console must
    never crash on the pass/fail marks or the title dash (Issue #9). Shows the
    per-leg result + metric + detail; the gating formula with live per-leg marks,
    the fires/resists reproducibility counts, the per-seed kill matrix and the
    mutation-score headline; the overall kept verdict; plus a remediation line
    per failed gating leg when the test was rejected.
    """
    # ASCII-aware marks/separators so the showcase surface never crashes on a
    # legacy cp1252 console — independent of the root callback's UTF-8 forcing.
    from mylonite._redaction import redact
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
        # outcome.detail is free text from the validation pipeline (e.g. an
        # exception message, or a third-party ValidatorBase plugin's own
        # detail string) — redact it here, before Rich's column-width
        # wrapping has a chance to split a secret-shaped token across a line
        # break, which would defeat a post-render regex redaction. Also
        # escape Rich markup: a detail that quotes target/exception output
        # shaped like a closing tag (e.g. "[/bold]") would otherwise raise
        # rich.errors.MarkupError when the table renders (same class as
        # scan/artefacts.py's render_summary fix, DCR-0004). outcome.stage is
        # a contract Literal (not free text), so it needs neither.
        table.add_row(outcome.stage, mark, metric, rich_escape(redact(outcome.detail)))

    console_print(console, table)

    # --- the differential-oracle EVIDENCE (PR2: make the differential legible) --------
    # The gating formula with live per-leg marks, the fires/resists counts, and
    # the per-seed kill matrix were previously buried in report.notes (rendered
    # nowhere). Surface them so a "KEPT" verdict shows WHY it's trustworthy.
    # Metric legend — what the bare decimals in the table's metric column mean.
    console_print(
        console,
        "metric legend: "
        + sep.join(
            ["differential=agreement", "flakiness=reproducibility", "metamorphic=robustness (0-1)"]
        ),
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
        console_print(console, f"gate: kept = {rendered}  =>  {verdict}")

    # Reproducibility counts (fires/resists) behind differential + flakiness.
    repro = getattr(report, "reproducibility", None)
    if repro is not None:
        if repro.guard_resisted is not None:
            console_print(
                console,
                f"reproducibility: vulnerable fired {repro.vuln_fired}/{repro.iterations}, "
                f"guarded resisted {repro.guard_resisted}/{repro.iterations}",
            )
        else:
            console_print(
                console,
                f"reproducibility: reproduced {repro.vuln_fired}/{repro.iterations} "
                "against the real target (no in-repo guarded twin)",
            )

    if report.mutation_score is not None:
        console_print(console, f"mutation score: {report.mutation_score:.2f}")

    # Per-seed kill matrix — the oracle's discrimination, seed by seed.
    matrix = getattr(report, "mutation_matrix", None) or []
    if matrix:
        killed = sum(1 for s in matrix if s.killed)
        console_print(
            console,
            f"kill matrix ({killed}/{len(matrix)} seeds killed = "
            "fired-on-vulnerable, resisted-on-guarded):",
        )
        for seed in matrix:
            console_print(console, f"  {_mark(seed.killed)} {seed.weakness}:{seed.pattern_id}")

    # Metamorphic robustness gates kept (M2) — say so explicitly so a failing
    # metamorphic row below IS read as a gate failure, not just a footnote.
    if any(o.stage == "metamorphic" for o in report.outcomes):
        console_print(
            console,
            "note: metamorphic robustness gates kept - a failing row below means "
            "the differential did not survive that perturbation.",
        )

    if report.kept:
        console_print(
            console, f"[green]verdict: KEPT {dash} the test discriminates and is stable.[/green]"
        )
    else:
        console_print(console, f"[red]verdict: REJECTED {dash} the test was not kept.[/red]")
        # The differential remediation must not accuse a real (server-layer) control
        # of being theater when the guarded side was only the SYNTHETIC boundary shim.
        # The validator stamps a [guarded-twin=...] marker into notes; key off it.
        notes = getattr(report, "notes", "") or ""
        if "guarded-twin=synthetic-boundary" in notes:
            diff_remediation = (
                "differential fail: the SYNTHETIC boundary twin did not block the attack. "
                "If your real control is server-layer (an approval gate / allowlist enforced "
                "inside the server), declare control_env / vulnerable_launch in the target file "
                "so the differential measures it - the boundary twin cannot see server-side "
                "guards, so this is NOT evidence your control is ineffective."
            )
        elif "guarded-twin=server-layer" in notes:
            diff_remediation = (
                "differential fail: the server-layer control did not discriminate (raw and "
                "guarded behaved alike) - the control as configured did not stop this attack."
            )
        else:
            diff_remediation = "differential fail: no discriminating power between the twins."
        _remediation = {
            "build": "build fail: emitted test didn't collect; re-run `mylonite generate`.",
            "differential": diff_remediation,
            "flakiness": "flakiness fail: exploit too flaky to gate; try a more deterministic seed.",
            "stability": "stability fail: the attack did not reproduce against the real target.",
            "effect": "effect fail: the target's effect probe did not confirm the damage materialised.",
            "consensus": "consensus fail: judges disagreed the effect was real; add an effect_probe.",
        }
        for outcome in report.outcomes:
            if not outcome.passed and outcome.stage in _remediation:
                console_print(console, f"[red]  remediation: {_remediation[outcome.stage]}[/red]")


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


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite validate .mylonite/generated/<slug>` -- re-prove the emitted test (the validation engine).\n\n"
        "`mylonite validate <dir> --fast` -- skip the differential leg (faster, weaker guarantee).\n\n"
        "`mylonite validate <dir> --target-file app.yaml` -- re-drive YOUR real app, not the twin.\n\n"
        "Exit codes: 0 kept | 2 config/usage | 4 provider unreachable | 5 not kept (rejected)."
    )
)
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
        float,
        typer.Option(
            "--iteration-timeout",
            help=(
                "Per-scan wall-clock budget (seconds) for a CUSTOM-target run. A "
                "stuck or slow real target aborts that run cleanly instead of "
                "hanging open-ended; the loop still completes and reports. "
                "Defaults to a sane non-zero bound (DCR-0010) — a CI job must not "
                "be able to hang indefinitely just because this flag was left "
                "unset; pass a larger value for a target known to need more time."
            ),
        ),
    ] = _DEFAULT_ITERATION_TIMEOUT_S,
    prove_input_control: Annotated[
        bool,
        typer.Option(
            "--prove-input-control",
            help=(
                "For a black-box HTTP (rest) target: run an input data-framing "
                "('spotlighting') differential — raw vs a build that wraps the payload as "
                "untrusted data — to measure whether that input defence is load-bearing. "
                "Opt-in; otherwise a rest target is gated by stability + effect + consensus. "
                "--fast takes precedence: it skips the differential leg outright and "
                "makes this a no-op."
            ),
        ),
    ] = False,
    fast: Annotated[
        bool,
        typer.Option(
            "--fast",
            help=(
                "For a CUSTOM target: skip the differential leg (the boundary-guarded "
                "twin). Faster/cheaper (~half the live runs) but a WEAKER guarantee: "
                "kept = build ∧ stability ∧ effect ∧ consensus, without proving the "
                "safeguard carries the security. Also overrides --prove-input-control "
                "(never re-enables the differential it just skipped). For a REFERENCE "
                "target: the twin-vs-twin differential itself isn't optional, so this "
                "instead reduces the metamorphic robustness check to a single "
                "perturbation strategy (still gates kept, just cheaper/less thorough)."
            ),
        ),
    ] = False,
    randomize_exfil: Annotated[
        bool | None,
        typer.Option(
            "--randomize-exfil/--no-randomize-exfil",
            help=(
                "Mint a unique exfil destination per run instead of the demo address, so "
                "the run proves the control/target stops exfil to ANY attacker destination "
                "(generalizes) rather than blocking one literal address (avoids 'teaching "
                "to the test'). Defaults ON for live custom-target runs; the reference/replay "
                "path never randomizes."
            ),
        ),
    ] = None,
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help=(
                "Required for a CUSTOM target (--target-file); assert ownership of the "
                "target. validate live-drives it — including sending real attack payloads. "
                "Not required for reference:* targets (bundled, safe-by-construction)."
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
        echo_exc(f"could not load exploit at {exploit_path}", exc)
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
        _exit_if_missing_kitchen_sink(exc)
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

    # Randomize the exfil destination by DEFAULT on live custom-target runs, so a kept
    # finding proves the control blocks ANY attacker address, not the one demo literal
    # (avoids 'teaching to the test'). The reference/replay path must never randomize —
    # it replays committed fixtures pinned to the demo address. Explicit
    # --randomize-exfil / --no-randomize-exfil always wins.
    if randomize_exfil is None:
        randomize_exfil = is_custom

    # Auto-resolve the target YAML co-located with the test (written by `generate`)
    # so the operator needn't re-pass --target-file. Explicit --target-file wins.
    if target_file is None and is_custom:
        candidate = test_path.parent / "target.yaml"
        if candidate.is_file():
            target_file = candidate
            echo_err(f"Using target: {candidate} (co-located with the test)")

    if is_custom:
        # DCR-0008: the provider-reachability preflight is done INSIDE
        # _validate_custom, AFTER its authorization gate — never before it.
        # Authorization must gate every live-driving action on the operator's
        # real target (Phase 4's "one authorization gate" invariant); the
        # preflight itself only calls the LLM provider (via the bundled
        # reference twin, not the operator's target) so it carries no
        # authorization concern of its own, but ordering it before the
        # authorize check would still mean an unauthorized `validate` burns a
        # live LLM call before being rejected.
        report = _validate_custom(
            generated,
            target_file,
            iterations,
            effective_provider,
            effective_model,
            iteration_timeout_s=iteration_timeout,
            randomize_exfil=randomize_exfil,
            fast=fast,
            prove_input_control=prove_input_control,
            authorize=authorize,
        )
    else:
        echo_err(
            f"validate runs ~{iterations} iterations x 2 twins live (Haiku) — roughly a "
            "minute, a few cents; needs a provider (ANTHROPIC_API_KEY)."
        )
        # Fail fast on an unreachable provider with a distinct exit 4 — otherwise
        # the full loop would just report a misleading non-discriminating result.
        try:
            reachable = _provider_preflight(effective_provider, effective_model)
        except (ModuleNotFoundError, ImportError) as exc:
            _exit_if_missing_kitchen_sink(exc)
            raise
        if not reachable:
            echo_err(
                "no provider reachable — set ANTHROPIC_API_KEY, or pass "
                "--provider/--model for another LiteLLM provider."
            )
            raise typer.Exit(code=EXIT_PROVIDER)

        # DCR-0007: `fast` was previously accepted by this command but silently
        # dropped on the reference branch — a reference-target `--fast` was a
        # complete no-op, contradicting the flag's own "faster/cheaper" promise.
        # The reference path's twin-vs-twin differential itself isn't optional
        # (unlike the custom path, there is no non-differential fallback gate),
        # so `--fast` here instead trims the metamorphic robustness leg — the
        # other genuinely-optional source of extra live calls (7 perturbation
        # strategies x 2 twins each, on top of the `iterations` differential
        # loop) — to a single strategy.
        if fast:
            echo_err(
                "validate: --fast reduces the metamorphic robustness check to a single "
                "perturbation strategy (faster/cheaper; weaker robustness signal)."
            )
        validator = DifferentialValidator(
            iterations=iterations,
            provider=effective_provider,
            model=effective_model,
            metamorphic_strategies=["paraphrase"] if fast else None,
            # Record the canonical guarded fixtures into the gen dir's `fixtures/`
            # and run the on-disk committed test offline as a full-pass build —
            # closing the validate→committed-artefact loop.
            record_fixtures_dir=test_path.parent / "fixtures",
            progress_cb=lambda msg: echo_err(f"  … {msg}"),
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
        echo("")
        echo(
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
        echo_err(
            f"don't know how to report on {target.name}. Pass a scan dir, a "
            "generated/validated dir, or a scan_report.json / validation_report.json."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if target.is_dir():
        vr = target / "validation_report.json"
        if vr.is_file():
            return "validation", vr
        sr = target / "scan_report.json"
        if sr.is_file():
            return "scan", sr
        echo_err(
            f"no validation_report.json or scan_report.json found in {target}. "
            "Run `mylonite scan` or `mylonite validate` first."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    echo_err(f"path not found: {target}. Pass a scan/validated dir or a report JSON.")
    raise typer.Exit(code=EXIT_CONFIG)


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite report .mylonite/scans/<dir>` -- terminal trust panel (offline, no LLM).\n\n"
        "`mylonite report <dir> --sarif out.sarif` -- GitHub code scanning (Security tab + PR checks).\n\n"
        "`mylonite report <dir> --json finding.json` -- machine-readable bundle (dashboards/SIEM/bots)."
    )
)
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

    kind, path = _locate_report_artefact(target)
    console = _Console()

    # Captured for the machine-readable exports below (SARIF / JSON bundle),
    # enriched so NIST is present everywhere.
    vreport: Any = None
    sreport: Any = None
    dashboard_exploit: Any = None
    dashboard_exploits: list[Any] = []
    # A1: the exit code for a `kind == "scan"` artefact. Defaults to success;
    # overwritten below from `ScanOutcome.from_report(sreport)` once loaded --
    # the same single "did this scan actually work" authority `scan`/`gate`
    # already go through (mylonite.scan.coverage). Before this, `report`
    # rendered "aborted: <reason>" in its own output text and then STILL fell
    # through to `raise typer.Exit(code=EXIT_SUCCESS)` unconditionally --
    # exactly the silent fail-open this release exists to close. A validation
    # artefact has no comparable "did this actually run" signal to re-derive
    # (any persisted validation_report.json already reflects a completed run;
    # `kept=False` is a genuine verdict, not an infra abort), so it keeps
    # EXIT_SUCCESS unconditionally.
    exit_code = EXIT_SUCCESS

    if kind == "validation":
        from mylonite import testkit
        from mylonite.contracts import ValidationReport

        try:
            vreport = ValidationReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            echo_exc(f"could not load {path}", exc)
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
                console_print(
                    console, f"compliance: {_compliance_tags_line(dashboard_exploit.compliance)}"
                )
                console_print(
                    console,
                    f"target: {dashboard_exploit.target_id}  "
                    f"pattern: {dashboard_exploit.pattern_id}",
                )
            except (FileNotFoundError, ValueError):
                pass
        console_print(console, f"artefacts: {path.parent}")
    else:
        from mylonite import testkit
        from mylonite.contracts._types import ScanReport
        from mylonite.scan.artefacts import render_summary
        from mylonite.scan.engine import ScanResult

        try:
            sreport = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            echo_exc(f"could not load {path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        from mylonite.scan.coverage import ScanOutcome

        # Code-quality review of the A1 fix (43dc63b): `ScanReport.aborted` has
        # no enum constraint at the pydantic layer, so a legacy-version or
        # hand-edited/corrupted scan_report.json can load fine here yet carry
        # an `aborted` value outside the current AbortReason enum --
        # `ScanOutcome.from_report` raises ValueError for exactly that case.
        # Left uncaught, that surfaces as a bare traceback (exit 1, empty
        # output) -- strictly worse than the silent-exit-0 bug this branch
        # exists to fix. Degrade the same way the sibling try/except a few
        # lines above (unparseable report) already does: a clear message, no
        # traceback, EXIT_CONFIG.
        try:
            exit_code = ScanOutcome.from_report(sreport).exit_code
        except ValueError as exc:
            echo_exc(f"could not classify {path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        result = ScanResult(report=sreport, exploits=[])
        # render_summary already returns a fully-rendered, ASCII-aware string.
        console_print(console, render_summary(result), markup=False)
        # Compliance tags aggregated across the co-located exploit files, enriched
        # on read (derive NIST from the OWASP cross-refs) so the report matches the
        # emitted test's marks even for scan dirs whose persisted exploits predate
        # enrichment.
        tags: set[str] = set()
        target_id = sreport.target_id
        from mylonite.plugins._reference.reference_compliance_mapper import (
            ReferenceComplianceMapper,
        )

        # Built once, reused for every exploit file (DCR-0014 perf) — a scan dir
        # with many findings would otherwise construct + import a fresh mapper
        # per finding in this loop.
        compliance_mapper = ReferenceComplianceMapper()
        for exploit_file in sorted(path.parent.glob("exploit_*.json")):
            try:
                exploit = _map_compliance(testkit.load_exploit(exploit_file), compliance_mapper)
            except (FileNotFoundError, ValueError, OSError):
                continue
            dashboard_exploits.append(exploit)
            c = exploit.compliance
            for ids in (c.owasp_llm, c.owasp_asi, c.mitre_atlas, c.nist_ai_rmf):
                tags.update(ids)
        if tags:
            console_print(console, f"compliance: {', '.join(sorted(tags))}")
        console_print(console, f"target: {target_id}  artefacts: {path.parent}")

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
            echo(f"Wrote SARIF (GitHub code scanning): {sarif}")
        if json_bundle is not None:
            from mylonite.report import to_bundle

            json_bundle.write_text(
                _json.dumps(to_bundle(findings), indent=2) + "\n", encoding="utf-8"
            )
            echo(f"Wrote JSON finding bundle: {json_bundle}")
    raise typer.Exit(code=exit_code)


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


_RESERVED_FAMILIES = frozenset({"filesystem", "fetch", "github", "target", "app"})


def _scaffold_rest_target_file(
    *,
    output: Path,
    rest_url: str,
    rest_body: str | None,
    rest_response_path: str | None,
    force: bool,
) -> None:
    """Implement ``scan --scaffold --rest-url``: write a RUNNABLE HTTP-agent target.

    A plain HTTP agent has nothing to introspect, so (unlike the MCP scaffold) this
    writes a complete, ready-to-scan ``target.yaml`` for the endpoint — no hand-editing
    required. See docs/http-agent.md.
    """
    from mylonite.plugins._mcp.target_file import TargetFile, dump_target_file
    from mylonite.plugins._mcp.target_registry import RequestSpec

    if output.exists() and not force:
        echo_err(f"{output} already exists — pass --force to overwrite.")
        raise typer.Exit(code=EXIT_CONFIG)

    body = rest_body or '{"prompt": "{prompt}"}'
    if "{prompt}" not in body:
        echo_err("--rest-body must contain a {prompt} placeholder.")
        raise typer.Exit(code=EXIT_CONFIG)

    import re

    stem = re.sub(r"[^a-z0-9]+", "-", output.stem.lower()).strip("-") or "http-agent"
    family = "http-agent" if stem in _RESERVED_FAMILIES else stem

    try:
        tf = TargetFile(
            family=family,
            transport="rest",
            weakness_classes=["W2"],
            request=RequestSpec(url=rest_url, body=body, response_path=rest_response_path),
        )
    except Exception as exc:
        echo_exc("invalid rest target", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    header = (
        "# Mylonite HTTP-agent target — generated by `mylonite scan --scaffold ... --rest-url`.\n"
        "# A black-box HTTP agent is tested for prompt-injection / goal-hijack (W2), judged\n"
        "# on the reply. This file is runnable as-is; edit the request block to match your\n"
        "# endpoint (auth goes in request.headers — never logged). See docs/http-agent.md.\n\n"
    )
    output.write_text(header + dump_target_file(tf), encoding="utf-8")
    echo(f"wrote runnable HTTP-agent target -> {output}")
    echo_err(f"next: mylonite scan --target-file {output} --authorize {family}")


def _scaffold_target_file(
    *,
    output: Path,
    command: str | None,
    arg: list[str] | None,
    env: list[str] | None,
    scope: str | None,
    system_prompt: str | None,
    system_prompt_file: Path | None,
    model: str | None,
    force: bool,
) -> None:
    """Implement ``scan --scaffold``: launch the MCP server, list its tools, and
    write a commented ``target.yaml`` starter (NO LLM call, no attack).

    Introspects the live tool surface and writes a starter with SUGGESTED
    ``weakness_classes`` / ``primary_tools`` and a ``seed_arm`` + ``effect_probe``
    template for the operator to fill in. The suggestions are hints grounded in
    the bundled OWASP-LLM/ASI taxonomy — the operator owns the
    consequential-capability + effect-probe declarations, so they review and edit
    before scanning.
    """
    import yaml

    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec

    if not command:
        echo_err("--scaffold needs --command (the MCP server launch command).")
        raise typer.Exit(code=EXIT_CONFIG)

    if output.exists() and not force:
        echo_err(f"{output} already exists — pass --force to overwrite.")
        raise typer.Exit(code=EXIT_CONFIG)

    tf = _target_file_from_flags(
        command=command,
        args=arg,
        env=env,
        scope=scope,
        system_prompt=system_prompt,
        system_prompt_file=system_prompt_file,
        primary_tools=None,
        weakness_classes=None,
    )

    try:
        spec = build_target_spec(tf)
    except Exception as exc:
        echo_exc("invalid target flags", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    adapter = build_mcp_adapter(
        family=spec.family, scope=tf.scope, model=model or "claude-haiku-4-5-20251001"
    )

    echo_err(f"launching {command!r} to introspect its tools (no LLM call)…")
    try:
        descriptor = asyncio.run(adapter.describe())
    except Exception as exc:
        echo_exc("could not launch / introspect the MCP server", exc)
        echo_err("check --command/--arg/--env and that the server speaks MCP over stdio.")
        raise typer.Exit(code=EXIT_CONFIG) from exc

    tools = list(descriptor.tools)
    tool_names = [t.name for t in tools]
    suggested_weaknesses = _suggest_weakness_classes(tools)
    roles = _classify_tools(tools)

    # #18 footgun: warn (do not block) on a relative SQLite DB path.
    for key in _relative_sqlite_env_keys(tf.env):
        echo_err(
            f"warning: env {key} looks like a relative SQLite path. "
            "On Windows a relative/ambiguous sqlite URL can open a DIFFERENT or empty "
            "DB, making a vulnerable agent look clean (#18). Prefer an absolute path. "
            "(value withheld — env values may carry credentials)"
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
        echo_exc("internal error: scaffolded YAML failed validation", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    output.write_text(yaml_text, encoding="utf-8")
    echo(f"wrote {output} — {len(tool_names)} tools discovered.")
    echo_err(
        "  suggested weakness_classes "
        f"{suggested_weaknesses or '[]'} (hints — confirm/edit before scanning)."
    )
    if roles.seed_arm_tool is not None:
        echo_err(
            f"  seed_arm candidate: {roles.seed_arm_tool}(...{roles.seed_arm_param}='{{payload}}') "
            f"+ retrieval via {roles.retrieve_tool!r}."
            if roles.retrieve_tool is not None
            else (
                f"  seed_arm candidate: {roles.seed_arm_tool} — but NO id-free retrieval tool was "
                "found to surface what it stores. The planner never learns a new record's id, so a "
                "store whose only readback needs that id (the save_note/read_note trap) will never "
                "deliver the poison. Confirm a list/recall/search-style tool exists, or expect those "
                "seeds to report NOT TESTED."
            )
        )
    elif "W2" in suggested_weaknesses:
        echo_err(
            "  no obvious content-storing tool found for the seed_arm — fill it in by hand "
            "(the tool that ingests untrusted content), or W2 seeds will report NOT TESTED."
        )
    from mylonite._authz import required_authorization

    echo_err(
        "  next: fill in the seed_arm (how to plant untrusted content) and the "
        "effect_probe (how to confirm damage), then run "
        f"`mylonite scan --target-file {output} "
        f"--authorize {required_authorization(family=spec.family, scope=tf.scope)}`."
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

    from mylonite._redaction import redact_env

    roles = roles or _ToolRoles(None, None, None, None, [])

    def _yaml_list(items: list[str]) -> str:
        return yaml.safe_dump(items, default_flow_style=True).strip()

    args_line = _yaml_list(list(tf.args)) if tf.args else "[]"
    env_block = ""
    if tf.env:
        # Dump as a proper YAML mapping so values with ':' (e.g. sqlite URLs) are
        # quoted/escaped correctly — never hand-roll per-value scalars. A credential-
        # shaped --env value (e.g. a live GITHUB_TOKEN) must not reach the scaffold
        # file on disk in cleartext — same leak class as the scan/generate/gate
        # target.yaml writes, just a fourth, earlier origination path (DCR-0006).
        env_block = yaml.safe_dump({"env": redact_env(dict(tf.env))}, default_flow_style=False)
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
# Mylonite custom-target scaffold — generated by `mylonite scan --scaffold`.
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
#   id_key: id           # the field in the store tool's RESULT holding the new record's
#                        # handle (look for: id, uuid, note_id, key, _id). ONLY needed when
#                        # recall requires that id; a list/search-style recall does not.
#                        # Alternatives: id_pattern (a regex) or id_from: first_int.

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
    repo_root: Path,
    exploit: Any,
    report: Any,
    target_file: Path | None,
    pr_mod: Any,
    *,
    gate_dir: Path,
) -> None:
    """Best-effort GitHub check-run annotation for a finding that maps to a committed
    prompt line (R4). Untestable live glue (needs a real PR + ``checks:write``); the
    payload assembly and localization it calls are unit-tested. Never raises.

    ``gate_dir`` is the resolved ``gate --out`` directory — threaded through to
    :func:`mylonite.gate.annotate.post_check_run` so its scratch file lands
    alongside the rest of this run's gate artefacts rather than always under
    the hardcoded default.
    """
    try:
        from mylonite.gate.annotate import (
            annotations_from_findings,
            check_run_payload,
            post_check_run,
        )

        sp_path: str | None = None
        sp_text: str | None = None
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import (
                load_target_file,
                resolved_system_prompt_path,
            )

            tf = load_target_file(target_file)
            spf = resolved_system_prompt_path(tf)  # raises PathEscapesBase on escape
            if spf is not None:
                sp_text = spf.read_text(encoding="utf-8")
                try:
                    sp_path = str(spf.relative_to(repo_root.resolve()))
                except ValueError:
                    # Contained in the target-file dir but outside the repo — do not
                    # publish content we cannot name relative to the PR.
                    sp_text = None

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
        post_check_run(repo_root, payload, gate_dir=gate_dir, _run=pr_mod._default_run)
    except Exception:  # live glue must never break the gate
        return


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite gate reference:vulnerable` -- the full pipeline on the demo target.\n\n"
        "`mylonite gate --target-file app.yaml --authorize my-app` -- gate YOUR app (writes test + workflows).\n\n"
        "`mylonite gate --target-file app.yaml --authorize my-app --open-pr` -- also open the gating PR via gh."
    )
)
def gate(
    ctx: typer.Context,
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
    purpose: Annotated[
        str | None,
        typer.Option(
            "--purpose",
            help=(
                "One-line description of what the app is for; tailors the probes to the "
                "app's domain. Overrides 'purpose' in the target file."
            ),
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
        Path | None,
        typer.Option(
            "--out",
            help=(
                "Output directory for gate artefacts (default: the resolved layout's "
                "gate dir, normally .mylonite/gate — see mylonite.yaml `root:` / "
                "MYLONITE_ROOT)."
            ),
        ),
    ] = None,
    max_llm_calls: Annotated[
        int | None,
        typer.Option(
            "--max-llm-calls",
            help="Process-wide LLM call cap for the scan phase.",
            show_default=str(_DEFAULT_MAX_LLM_CALLS),
        ),
    ] = None,
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
    prove_input_control: Annotated[
        bool,
        typer.Option(
            "--prove-input-control",
            help=(
                "For a black-box HTTP (rest) target: run the input data-framing "
                "('spotlighting') differential to measure whether that input defence is "
                "load-bearing. Opt-in; otherwise a rest target is gated by "
                "stability + effect + consensus."
            ),
        ),
    ] = False,
    randomize_exfil: Annotated[
        bool | None,
        typer.Option(
            "--randomize-exfil/--no-randomize-exfil",
            help=(
                "Mint a unique exfil destination per run so the finding proves the "
                "control/target stops exfil to ANY attacker destination, not just the "
                "demo address (avoids 'teaching to the test'). Defaults ON for a live "
                "custom target (--target-file); the reference target never randomizes."
            ),
        ),
    ] = None,
    iterations: Annotated[
        int,
        typer.Option(
            "--iterations",
            help=(
                "Differential iterations for the validation leg (default 3). The kept "
                "verdict then reflects reproducibility across runs — the guarded side "
                "must resist every run and the attack must fire in all but one. Pass 1 "
                "for the fastest, weakest gate (fire once)."
            ),
        ),
    ] = 3,
) -> None:
    """Scan -> generate -> validate -> (optionally) open a gating PR. The full pipeline."""
    if randomize_exfil is None:
        # Default ON for any LIVE target (custom --target-file OR a bundled mcp:<family>);
        # only the in-process reference targets replay fixtures and must not randomize.
        randomize_exfil = not (target is not None and target.startswith("reference:"))
    if iterations < 1:
        echo_err("--iterations must be >= 1.")
        raise typer.Exit(code=EXIT_CONFIG)
    from mylonite.gate import ScanOutcomeBundle, run_gate
    from mylonite.gate import pr as pr_mod
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
        UnsafeExploitRecord,
    )
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
            echo_exc(f"invalid config {config_path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        if run_config_path is None:
            echo_err(f"gate: using {config_path} (auto-discovered).")
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        max_llm_calls = _resolve_option(max_llm_calls, rc.max_llm_calls, _DEFAULT_MAX_LLM_CALLS)
        config_root = rc.root
    else:
        max_llm_calls = _resolve_option(max_llm_calls, None, _DEFAULT_MAX_LLM_CALLS)
        config_root = None

    # The resolved artefact Layout, mirroring `scan`: an explicit --out always
    # wins outright; absent that, mylonite.yaml's `root:` / MYLONITE_ROOT / the
    # built-in default decide where gate artefacts (test, exploit, check-run
    # scratch file) land instead of the historical hardcoded `.mylonite/gate`.
    layout = _layout_for(ctx, config_root=config_root)
    out = out if out is not None else layout.gate

    effective_provider = provider or "anthropic"
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    # --- resolve adapter (mirrors scan command routing) ---
    # 'reference:*' + --target-file is never meaningful — the reference targets
    # are bundled in-process twins with no target file of their own. Reject it
    # up front rather than silently letting one win (#24): a prior version
    # computed `is_reference` from the target STRING before this branch could
    # override routing to a custom adapter, so validate_fn below could drive the
    # wrong oracle (reference twins) against a scan that actually ran a custom
    # target, or vice versa.
    if target is not None and target.startswith("reference:") and target_file is not None:
        echo_err(
            "gate: 'reference:*' targets are bundled in-process twins and don't take "
            "--target-file. Pass a custom target via --target-file alone (drop the "
            "'reference:' target argument), or drop --target-file to gate the "
            "reference twin."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    tf = None
    routed_to: str

    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp — enforce --authorize BEFORE loading the file,
        # exactly as scan does.
        if not authorize:
            echo_err("--authorize is required for custom targets. See SECURITY.md.")
            raise typer.Exit(code=EXIT_CONFIG)
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
        else:
            # mcp:custom with inline flags — not supported via gate (no --command etc.)
            echo_err(
                "gate --target-file <yaml> is the custom-target path; "
                "inline mcp:custom flags are not wired in `gate`. "
                "Pass a target YAML via --target-file."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_custom(tf, authorize, effective_model, command="gate")
        routed_to = "custom"
    elif target is None:
        echo_err("no target given. Pass a target (e.g. reference:vulnerable) or --target-file.")
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_model)
        routed_to = "reference"
    elif target.startswith("mcp:"):
        if not authorize:
            echo_err(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter = _build_adapter_for_mcp(target, authorize, effective_model)
        routed_to = "mcp"
    else:
        echo_err(
            f"unknown target shape {target!r}. "
            "Expected 'reference:<variant>', 'mcp:<family>[:<scope>]', or --target-file."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Derived from what actually ran (routed_to), NOT re-parsed from the target
    # string — see the up-front rejection above for why the two could diverge.
    is_reference = routed_to == "reference"

    # --- closures injected into run_gate ---

    def scan_fn() -> ScanOutcomeBundle:
        from mylonite.plugins.registry import discover
        from mylonite.scan.coverage import ScanOutcome
        from mylonite.scan.customiser import PayloadCustomiser
        from mylonite.scan.engine import ScanConfig, ScanEngine
        from mylonite.scan.judge import SuccessJudge

        try:
            all_modules: list[Any] = discover("mylonite.attack_modules")
        except Exception as exc:
            echo_exc("plugin discovery failed", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        attack_modules = [m for m in all_modules if m.attack_metadata().id in _V0_2_ATTACK_FAMILIES]
        if not attack_modules:
            echo_err(
                "no usable attack modules discovered "
                "(looking for 'prompt-injection-family' or 'excessive-agency-family')"
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
            customiser=PayloadCustomiser(
                model=effective_model, purpose=purpose or (tf.purpose if tf else None)
            ),
            judge=SuccessJudge(model=effective_model),
        )
        result = asyncio.run(engine.run())
        # The typed verdict for "did this scan actually run" (A1 fix) — carried
        # alongside the exploits so run_gate can tell a genuine clean scan apart
        # from one that never meaningfully ran (e.g. provider_unreachable).
        outcome = ScanOutcome.from_report(result.report)
        # Enrich compliance (derive NIST) once so both the emitted test and the PR
        # carry it.
        exploits = [_map_compliance(ex) for ex in result.exploits]
        # M1: tag each controllable CUSTOM finding BY DEFAULT so generate_fn emits the
        # control test and validate_fn runs the differential (the safeguard, not the
        # model, carries the security). --fast opts out; reference targets use the
        # in-repo differential and are not tagged here. This tagging is the default
        # behaviour; the old --prove-control opt-in flag was removed in 0.7.7.
        if fast or is_reference:
            return ScanOutcomeBundle(outcome=outcome, exploits=exploits)
        if tf is not None and tf.transport == "rest":
            if prove_input_control:
                # Opt-in: measure whether input data-framing (spotlighting) is
                # load-bearing. Tag with the input-frame sentinel so validate_fn builds
                # the framing-guarded HTTP build for the differential.
                echo_err(
                    "gate: rest input-control differential — raw vs input data-framing "
                    "(spotlighting)."
                )
                return ScanOutcomeBundle(
                    outcome=outcome,
                    exploits=[
                        ex.model_copy(
                            update={
                                "payload": ex.payload.model_copy(
                                    update={
                                        "metadata": {
                                            **ex.payload.metadata,
                                            "synthetic_control": "input-frame",
                                        }
                                    }
                                )
                            }
                        )
                        for ex in exploits
                    ],
                )
            # A black-box HTTP agent has no adapter-boundary control to apply, so a
            # boundary-guarded twin would equal the raw target and wrongly REJECT a
            # real finding. Don't tag; the gate is decided by stability/effect/consensus.
            echo_err(
                "gate: rest (HTTP-agent) target — the control-efficacy differential does not "
                "apply to a black box; the emitted test is gated by stability + effect + "
                "consensus. Declare control_env / vulnerable_launch for a server-layer "
                "differential, or pass --prove-input-control to test input data-framing."
            )
            return ScanOutcomeBundle(outcome=outcome, exploits=exploits)
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
        return ScanOutcomeBundle(outcome=outcome, exploits=tagged)

    def generate_fn(exploit: Any) -> Any:
        # run_gate() is Typer-agnostic by design (its docstring: "Collaborators
        # are injected so the Typer command supplies live ones") -- the CLI-
        # framework-specific degrade-cleanly behaviour belongs in this closure,
        # not in the orchestrator, mirroring scan_fn's own echo_exc + typer.Exit
        # above for plugin-discovery failures.
        try:
            return ReferencePytestGenerator().emit(exploit)
        except UnsafeExploitRecord as exc:
            echo_exc("could not generate a regression test for this finding", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

    def validate_fn(generated: Any) -> Any:
        if is_reference:
            validator = DifferentialValidator(
                iterations=iterations,
                provider=effective_provider,
                model=effective_model,
                record_fixtures_dir=out / "fixtures",
                progress_cb=lambda msg: echo_err(f"  … {msg}"),
            )
            return validator.validate(
                generated,
                ReferenceVulnerableOracle().adapter(),
                ReferenceVulnerableOracle(),
            )
        # Custom target: mirror _validate_custom — re-drive the REAL target.
        if tf is None:
            echo_err("internal: expected a loaded TargetFile for custom validate_fn")
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.factory import build_mcp_adapter
        from mylonite.plugins._mcp.target_file import build_target_spec

        spec = build_target_spec(tf)
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)

        def _factory() -> Any:
            return build_mcp_adapter(family=spec.family, scope=tf.scope, model=effective_model)

        # Control-efficacy leg: a controllable finding (tagged in scan_fn) gets a
        # boundary-guarded twin so the differential leg proves the control is
        # load-bearing (model held constant).
        guarded_factory: Any = None
        control_weakness = generated.exploit.payload.metadata.get("synthetic_control")
        if control_weakness == "input-frame":
            # rest input-control: the guarded build is the SAME HTTP agent driven with
            # input data-framing (spotlighting) applied.
            def _guarded_framed() -> Any:
                return build_mcp_adapter(
                    family=spec.family, scope=tf.scope, model=effective_model, input_frame=True
                )

            guarded_factory = _guarded_framed
        elif control_weakness:
            cw: str = control_weakness

            def _guarded() -> Any:
                return build_mcp_adapter(
                    family=spec.family,
                    scope=tf.scope,
                    model=effective_model,
                    controls=[_boundary_control(cw, spec)],
                )

            guarded_factory = _guarded

        # gate validates across `iterations` re-drives (default 3) so the kept verdict
        # reflects reproducibility: the attack must fire in all but one run
        # (vuln_threshold = iterations - 1) and the guarded side must resist every run.
        # `--iterations 1` restores the fastest, weakest gate (fire once). Deeper nightly
        # discovery still complements this via the committed test's regression assert.
        validator = DifferentialValidator(
            iterations=iterations,
            vuln_threshold=max(1, iterations - 1),
            provider=effective_provider,
            model=effective_model,
            target_adapter_factory=_factory,
            guarded_adapter_factory=guarded_factory,
            control_weakness=control_weakness,
            randomize_exfil=randomize_exfil,
            progress_cb=lambda msg: echo_err(f"  … {msg}"),
        )
        return validator.validate(generated, _factory(), ReferenceVulnerableOracle())

    def open_pr_fn(*, out_dir: Path, exploit: Any, report: Any, body: str, open_pr: bool) -> Any:
        from mylonite._redaction import redact_target_yaml
        from mylonite.gate.workflows import write_workflows

        repo_root = Path.cwd()
        wf_files = (
            write_workflows(repo_root, runs_on=runs_on, gate_dir=out_dir) if workflows else []
        )
        if target_file is not None:
            # A gate PR is pushed to the operator's remote — never carry a live
            # credential from request.headers/env into that history (DCR-0019).
            (out_dir / "target.yaml").write_text(
                redact_target_yaml(target_file.read_text(encoding="utf-8")), encoding="utf-8"
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
            _post_gate_annotations(
                repo_root, exploit, report, target_file, pr_mod, gate_dir=out_dir
            )
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
        # An inconclusive row's raw/guarded fired counts and contribution
        # percentage are computed purely from the FIRED/RESISTED legs and
        # exclude the crashed leg(s) entirely — left alone, they can still
        # read as a genuine load-bearing/theater signal (e.g. "2/0 of 2",
        # "+100%") to anyone skimming the table or copying a row out of
        # context, even though `status` correctly says "inconclusive". Never
        # render a bare percentage or count for this row; always surface the
        # inconclusive count instead.
        if r.status == "inconclusive":
            contribution_cell = "n/a"
            fired_cell = (
                f"{r.raw_fired}/{r.guarded_fired} of {r.total} ({r.inconclusive} inconclusive)"
            )
        else:
            contribution_cell = f"{r.contribution:+.0%}"
            fired_cell = f"{r.raw_fired}/{r.guarded_fired} of {r.total}"
        table.add_row(r.weakness, r.status, contribution_cell, fired_cell)
    console_print(console, table)
    load_bearing = [r.weakness for r in results if r.load_bearing]
    redundant = [r.weakness for r in results if r.status == "redundant"]
    theater = [r.weakness for r in results if r.status == "theater"]
    inconclusive = [r.weakness for r in results if r.status == "inconclusive"]
    if load_bearing:
        console_print(console, f"load-bearing: {', '.join(load_bearing)}")
    if redundant:
        console_print(console, f"redundant (another control covers it): {', '.join(redundant)}")
    if theater:
        console_print(console, f"security theater (no marginal contribution): {', '.join(theater)}")
    if inconclusive:
        console_print(
            console,
            f"inconclusive (scan didn't produce a trustworthy result on at least one "
            f"side -- NOT the same as resisted, re-run before trusting this control): "
            f"{', '.join(inconclusive)}",
        )


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
    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.scan.ablation import (
        REP_SEED_BY_WEAKNESS,
        FireOutcome,
        all_inconclusive,
        run_control_ablation,
        scan_target_fires,
        seeds_for_weaknesses,
        total_failure_exit_code,
    )
    from mylonite.scan.control_shim import make_control
    from mylonite.scan.coverage import ScanOutcome

    if target_file is None:
        echo_err("ablate requires --target-file (the app whose controls you want to score).")
        raise typer.Exit(code=EXIT_CONFIG)
    if not authorize:
        echo_err("--authorize is required to ablate a custom target. See SECURITY.md.")
        raise typer.Exit(code=EXIT_CONFIG)
    if iterations < 1:
        echo_err("--iterations must be >= 1.")
        raise typer.Exit(code=EXIT_CONFIG)

    effective_provider = provider or "anthropic"
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    effective_model = _route_model(provider, base_model)

    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        echo_exc(f"invalid --target-file {target_file}", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # DCR-0009/one-gate: ablate live-drives the real target exactly like scan/gate/
    # validate — same rule, same derivation (scope if declared, else family name).
    _enforce_custom_authorize(
        spec.family, tf.scope, spec.requires_scope, authorize, command="ablate"
    )

    # Server-layer mode: the target bakes its guards into the server (toggled by
    # env / a security profile), so the differential's "raw" side is produced by
    # DISABLING them via control_env — not by emptying the adapter shim, which
    # cannot reach a server-layer guard. This is what lets ablation classify
    # load-bearing/theater on the common real architecture instead of returning
    # no-attack for every control.
    server_layer = bool(spec.control_env)

    if controls:
        # dict.fromkeys dedupes while preserving order — "W2,W3,W2" must not
        # double-count W2's scans/rows in the ablation matrix (DCR-0015).
        chosen = list(dict.fromkeys(c.strip().upper() for c in controls.split(",") if c.strip()))
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
                echo_err(f"skipping {c}: no control_env toggle declared")
                continue
        else:
            try:
                make_control(c)
            except ValueError:
                echo_err(f"skipping {c}: no boundary control implemented")
                continue
        if c not in REP_SEED_BY_WEAKNESS:
            echo_err(f"skipping {c}: no representative seed")
            continue
        usable.append(c)
    if not usable:
        echo_err(
            "no ablatable controls. Pass --controls W2,W3,W4 or declare weakness_classes / "
            "control_config in the target file."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    seeds_by_weakness = seeds_for_weaknesses(usable, max_per_weakness=max_seeds)
    sides = 3 if redundancy else 2
    total_scans = sum(len(seeds_by_weakness.get(c, [])) for c in usable) * iterations * sides

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    mode = "all-minus-c (redundancy)" if redundancy else "on/off"
    layer = "server-layer (env toggles)" if server_layer else "adapter-shim"
    echo_err(
        f"ablate re-drives {spec.family!r} live, toggling {', '.join(usable)} {mode} "
        f"via {layer} ({iterations} run(s) each) — ~{total_scans} scoped scans."
    )

    # Populated by scan_target_fires's on_outcome sink below with the full
    # ScanOutcome (abort reason + exit_code) behind every non-FIRED scoped
    # scan -- discarded by the bare FireOutcome return value otherwise. Used
    # after run_control_ablation returns to pick an honest, non-zero exit
    # code if EVERY control comes back inconclusive (see the
    # all_inconclusive(results) check below). Appended from worker threads
    # (each scoped scan runs via asyncio.to_thread -- see _run_pair/
    # _run_triple); list.append is safe under the GIL and no ordering
    # invariant is needed across entries.
    observed_outcomes: list[ScanOutcome] = []

    def scan_fires(applied: tuple[str, ...], pattern_id: str) -> FireOutcome:
        if server_layer:
            # ``applied`` = controls currently ON. The raw side (applied=()) turns
            # them all OFF; the "only C" side leaves only C on. Translate to the
            # complement and disable those server-layer guards via the launch env.
            disable = tuple(c for c in usable if c not in applied)
            adapter = build_mcp_adapter(
                family=spec.family,
                scope=tf.scope,
                model=effective_model,
                launch_env=spec.launch_env(disable_controls=disable),
            )
        else:
            adapter = build_mcp_adapter(
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
            on_outcome=observed_outcomes.append,
        )

    try:
        results = run_control_ablation(
            controls=usable,
            seeds_by_weakness=seeds_by_weakness,
            scan_fires=scan_fires,
            iterations=iterations,
            progress=lambda msg: echo_err(f"  … {msg}"),
            redundancy=redundancy,
            all_controls=usable,
        )
    finally:
        target_registry.clear_runtime_targets()

    _render_ablation_matrix(results)
    if server_layer and results and all(r.status == "no-attack" for r in results):
        echo_err(
            "hint: every control classified 'no-attack' — the raw side never fired. "
            "Check that control_env actually disables the server's guard for these "
            "weakness classes, and that the representative seeds reach the surface."
        )
    if any(r.status == "inconclusive" for r in results):
        echo_err(
            "hint: one or more controls came back 'inconclusive' — the scan didn't run "
            "to completion on at least one side (provider outage, adapter crash, or "
            "no applicable attempts). This is NOT the same as the control resisting the "
            "attack; it must not be read as load-bearing/theater/redundant. Check "
            "connectivity/credentials and re-run."
        )
    if all_inconclusive(results):
        # Total failure: NOTHING could be determined for ANY control (the
        # confirmed T6 keyless bug -- previously fell through to an implicit
        # exit 0, indistinguishable from a genuine "every control resisted"
        # run). A MIXED result -- some controls determined, some inconclusive
        # -- is deliberately NOT treated the same way: ablate is inherently
        # multi-control, so a partial result is still real, actionable signal
        # for the controls that did resolve (already flagged per-row above,
        # via the table's status column and the "hint" line) rather than a
        # failure of the run itself.
        #
        # Exit-code derivation itself lives in ablation.py's
        # total_failure_exit_code (pure, directly unit-tested there) --
        # matching the gate/ScanOutcomeBundle precedent of keeping that
        # decision out of the Typer command body.
        echo_err(
            "error: every control came back inconclusive — ablate could not determine "
            "ANY control's status (total failure, not a null result). Check provider "
            "credentials/connectivity, then re-run."
        )
        raise typer.Exit(code=total_failure_exit_code(observed_outcomes))


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
    console_print(_console, table)
