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
import functools
import inspect
import logging
import os
import sys
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, TypeVar

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print, echo, echo_err, echo_exc
from mylonite._paths import safe_slug
from mylonite.contracts.exec_context import ExecContext
from mylonite.layout import Layout, resolve_layout
from mylonite.scan.tool_roles import _classify_tools, _ToolRoles
from mylonite.version import __version__

if TYPE_CHECKING:
    from mylonite.scan.model_ref import ModelRef

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

#: DCR-0008: bound on the outbound `gh api` check-run POST in the gate path —
#: no CLI-flag layer exists for this internal call, so a single sane constant
#: (not zero, no existing codebase convention to mirror for a subprocess
#: timeout) stands in for one. A stalled GitHub API call must fail fast
#: instead of hanging the gate job indefinitely.
_GH_API_TIMEOUT_S: Final = 30.0

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


def _load_env_file(path: Path) -> None:
    """Load recognised provider credential/config vars from a dotenv file —
    never blanket.

    Reads ``KEY=VALUE`` lines and sets a var when
    ``providers.looks_like_provider_env_var`` recognises the key name, so a
    stray ``.env`` can't inject arbitrary environment. That recognition is
    PATTERN-based (``*_API_KEY``, ``AZURE_*``) plus a small explicit map for
    the rest (``providers.PROVIDER_ENV_VARS`` — AWS's two-var Bedrock
    credential pair, which matches neither pattern) — not a closed allowlist,
    which used to silently drop any provider's key it didn't already know
    about (Groq/Mistral/DeepSeek/OpenRouter) and Azure's non-key vars
    (``AZURE_API_BASE``/``AZURE_API_VERSION``, only 1 of its 3 required vars).
    Every unrecognised key is reported on stderr — dropped, never silent.

    An explicitly-passed flag OVERRIDES an ambient value (standard CLI
    precedence: explicit > ambient — the exact case the flag exists for is a
    wrong key already in the shell), warning on stderr when it does.
    """
    from mylonite.scan.providers import looks_like_provider_env_var

    if not path.exists():
        echo_err(f"env file {path} not found.")
        raise typer.Exit(code=EXIT_CONFIG)
    loaded: list[str] = []
    dropped: list[str] = []
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
        if not looks_like_provider_env_var(key):
            dropped.append(key)
            continue
        if key in os.environ and os.environ[key] != value:
            echo_err(f"warning: overriding ambient {key} with the value from {path}.")
        os.environ[key] = value
        loaded.append(key)
    if loaded:
        echo_err(f"loaded {', '.join(sorted(loaded))} from {path}.")
    if dropped:
        echo_err(
            f"ignored {', '.join(sorted(dropped))} from {path}: not a recognised "
            "provider credential/config var name (expected e.g. *_API_KEY, "
            "AZURE_*, or an entry in providers.PROVIDER_ENV_VARS)."
        )


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
    # DCR-0011: derive the dotenv-vs-bare-key SHAPE decision from the first
    # non-comment, non-blank line too, not the raw first line — a leading
    # `#`-comment line (e.g. `# my key\nANTHROPIC_API_KEY=sk-ant-abc123`)
    # otherwise misrouted a valid dotenv file into the bare-key branch below
    # (the comment line has no `=`), which then went on to treat the WHOLE
    # `KEY=VALUE` line as a bare key and failed to infer a provider from it.
    # Reuses the same comment-skip logic the bare-key extraction loop below
    # already has, instead of a second, independent implementation.
    first_content_line = ""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            first_content_line = stripped
            break
    if "=" in first_content_line:
        _load_env_file(path)
        return
    # DCR-0009: derive the key from the first non-comment, non-blank line, not
    # `content.split()[0]` over the WHOLE file — a leading `#`-comment line
    # (e.g. `# my key\nsk-ant-abc123`) made that yield the literal `"#"`.
    key = first_content_line.split()[0] if first_content_line else ""
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
                "use; auto-discovered from ./mylonite.yaml when present; an explicit "
                "flag always wins."
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
    from mylonite.scan.providers import env_vars_for

    # Mirror scan/gate/validate/ablate: fill provider/model from mylonite.yaml
    # (auto-discovered from ./mylonite.yaml when --config is omitted, T14) then
    # the flat MYLONITE_* env vars, so `doctor` checks the SAME model those
    # commands will actually use rather than silently falling back to its own
    # default -- doctor is exactly the command that should show an operator
    # what config would actually be used. No --provider CLI flag any more
    # (removed 0.7.10, T13's deprecated alias) -- `provider` can still arrive
    # via mylonite.yaml's `provider:` key or MYLONITE_PROVIDER, both of which
    # remain (separately deprecated, but not removed) sources _resolve_model_ref
    # still warns on.
    _config_path, rc = _discover_run_config(run_config_path, command="doctor")
    env_rc = _env_run_config_or_exit()
    provider: str | None = None
    # DCR-0012: `is not None` throughout, not `or` -- the exact DCR-0004/0012/
    # 0015/0005 precedence pattern `_resolve_option`'s own docstring explains
    # (an explicit-but-falsy value, e.g. `--model ""`, is not the same as
    # "omitted" and must not be silently replaced by a lower-precedence
    # source or the hardcoded default). `provider` has no CLI flag of its own
    # on `doctor` (removed 0.7.10), so only `model`'s chain can actually
    # observe this in practice, but both are written the same way for the
    # same reason `_resolve_option` exists: so this can't silently regress
    # the next time a flag is added here.
    if rc is not None:
        provider = provider if provider is not None else rc.provider
        model = model if model is not None else rc.model
    provider = provider if provider is not None else env_rc.provider
    model = model if model is not None else env_rc.model

    base_model = model if model is not None else "claude-sonnet-4-6"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    routed = ref.raw
    resolved_provider = ref.provider

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

    Backward-compat wrapper only — new code should resolve a model via
    :func:`_resolve_model_ref` (base model) or :func:`_parse_model_ref_or_exit`
    (a second/role model in the same invocation), which additionally derive
    ``.provider`` and raise loudly on an unroutable model instead of silently
    passing it through to fail later, mid-call. The actual prefixing rule
    lives in :func:`mylonite.scan.model_ref.route_model` (the single source
    of truth :class:`~mylonite.scan.model_ref.ModelRef` also uses to build
    ``.raw``); this wrapper stays importable under its original name only for
    existing tests.
    """
    from mylonite.scan.model_ref import route_model

    return route_model(provider, model)


def _warn_deprecated_provider_config() -> None:
    """H1/close-the-loop: a separate ``provider`` value is deprecated in
    favour of a provider-prefixed model string — the convention LiteLLM
    itself uses and that promptfoo/garak adopters already know.

    The ``--provider`` CLI flag itself was REMOVED in 0.7.10 (it no longer
    exists on any command but ``demo``, whose ``--provider`` is a different,
    non-deprecated thing — see that command's help). This warning still
    fires for the two remaining ways to set a bare ``provider``: a
    ``mylonite.yaml`` ``provider:`` key, or a ``MYLONITE_PROVIDER`` env var
    (see :class:`~mylonite.config.RunConfig`). Emits once per command
    invocation: each command reads its own ``provider`` value exactly once,
    so a single call here (guarded on ``provider is not None``) at that
    point naturally fires once, never spammed across a retry loop.
    """
    echo_err(
        "warning: setting a bare provider (mylonite.yaml's `provider:` key, or "
        "MYLONITE_PROVIDER) is deprecated -- prefix the model instead, e.g. "
        "model: anthropic/claude-haiku-4-5 instead of model: claude-haiku-4-5 "
        "plus provider: anthropic."
    )


def _parse_model_ref_or_exit(model: str, provider: str | None) -> ModelRef:
    """``ModelRef.parse`` for a CLI argument, degrading a bad/unroutable model
    to a friendly ``EXIT_CONFIG`` instead of an unhandled traceback.

    No deprecation warning here — a command resolving a SECOND model in the
    same invocation (a role-separated ``--planner-model``/``--customiser-
    model``/``--judge-model`` override in ``scan``) reuses this directly so
    reusing the resolved ``provider`` for that override doesn't re-fire the
    warning :func:`_resolve_model_ref` already fired once for the base
    ``--model``.
    Every model a command resolves goes through this (or ``_resolve_model_ref``
    for the base one) — a role override must reject an unroutable model at
    CLI-argument time exactly like the base model does, since it drives the
    identical LiteLLM call path.
    """
    from mylonite.scan.model_ref import ModelRef

    try:
        return ModelRef.parse(model, provider_hint=provider)
    except ValueError as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _resolve_model_ref(model: str, provider: str | None) -> ModelRef:
    """``ModelRef.parse`` for a command's BASE model — see
    :func:`_parse_model_ref_or_exit` for the shared parse-or-exit behaviour.

    Also warns (once) when ``provider`` is set — see
    :func:`_warn_deprecated_provider_config`. The ``--provider`` CLI flag was
    removed in 0.7.10 (T-close-the-loop), so by construction ``provider``
    here can now only have come from a declarative ``mylonite.yaml``
    ``provider:`` key or a ``MYLONITE_PROVIDER`` env var — every caller folds
    either into its own ``provider`` local before calling here (see
    ``scan``/``gate``/``doctor``/``validate``/``ablate``), so this can't tell
    (and doesn't need to tell) which of the two it was.
    """
    if provider is not None:
        _warn_deprecated_provider_config()
    return _parse_model_ref_or_exit(model, provider)


def _discover_run_config(explicit_path: Path | None, *, command: str) -> tuple[Path | None, Any]:
    """Resolve the ``mylonite.yaml`` run config for ``command``.

    An explicit ``--config`` always wins; otherwise auto-discover
    ``./mylonite.yaml`` when present. Returns ``(path_used_or_None,
    RunConfig_or_None)`` — ``(None, None)`` when no config applies at all.

    T14/H3: this was ``gate``-only (the ``if config_path is None and
    Path("mylonite.yaml").is_file(): ...`` block T11 added) — every other
    command that accepts ``--config`` (``scan``, ``doctor``, and now
    ``validate``/``ablate``) re-implemented (or, for ``scan``/``doctor``,
    simply lacked) the SAME auto-discovery check. Centralising it here means
    a future command gets auto-discovery by construction, not by remembering
    to copy the ``gate``-specific block.
    """
    from mylonite.config import load_run_config

    path = explicit_path
    if path is None and Path("mylonite.yaml").is_file():
        path = Path("mylonite.yaml")
    if path is None:
        return None, None
    try:
        rc = load_run_config(path)
    except Exception as exc:
        echo_exc(f"invalid config {path}", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    if explicit_path is None:
        # DCR-0001: api_base is security-sensitive in a way no other RunConfig
        # field is -- honoring it from a repo-shipped, auto-discovered
        # mylonite.yaml the operator never asked to load would let a
        # malicious repo silently redirect every outbound LiteLLM call (and
        # the operator's real provider API key riding on it) to an attacker
        # host. Auto-discovery still applies to every OTHER field; api_base
        # specifically requires an explicit --config opt-in.
        if rc.api_base is not None:
            echo_err(
                f"{command}: using {path} (auto-discovered) -- its api_base "
                "will NOT be honored automatically (it could redirect your "
                "provider API key to an untrusted host); pass --config "
                f"{path} explicitly to opt in."
            )
            rc = rc.model_copy(update={"api_base": None})
        else:
            echo_err(f"{command}: using {path} (auto-discovered).")
    return path, rc


def _env_run_config_or_exit() -> Any:
    """``env_run_config()``, catching a credentialed ``MYLONITE_API_BASE`` the
    same way :func:`_discover_run_config` catches one from ``mylonite.yaml``
    (``echo_err`` + ``EXIT_CONFIG``) rather than letting
    :class:`~mylonite.scan.llm_policy.CredentialedApiBaseError` propagate as a
    raw traceback. The security property is identical either way (the value
    is refused, never silently used) — this only makes the failure mode
    consistent across all three sources (CLI flag validation, mylonite.yaml,
    env var) instead of the env-var layer alone surfacing as an uncaught
    exception (exit 1) rather than a clean, actionable exit 2.
    """
    from mylonite.config import env_run_config
    from mylonite.scan.llm_policy import CredentialedApiBaseError

    try:
        return env_run_config()
    except CredentialedApiBaseError as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _resolve_llm_policy(rc: Any | None, env_rc: Any) -> Any:
    """Build the :class:`~mylonite.scan.llm_policy.LLMPolicy` for a live run.

    Sources, in precedence order: ``rc`` (the resolved ``mylonite.yaml``, if
    any) then ``env_rc`` (the flat ``MYLONITE_*`` env vars — see
    :func:`~mylonite.config.env_run_config`, called ONCE per command
    invocation and reused for both this and the model/provider/role-model
    resolution alongside it); a field left unset by both keeps
    ``LLMPolicy``'s own documented default. There is deliberately no
    CLI-flag layer for these fields yet (T14 scope: ``--api-base``/
    ``--max-tokens``/etc. would be five more flags apiece across ``scan``/
    ``gate``/``validate``/``ablate`` — left for a follow-up if operators
    actually need a per-invocation override rather than a per-project/
    per-shell one); ``mylonite.yaml``/env cover the "my org runs a LiteLLM
    proxy" and "I want max_tokens=4096 for every run" cases this was written
    for.
    """
    from mylonite.scan.llm_policy import LLMPolicy

    api_base = (rc.api_base if rc is not None else None) or env_rc.api_base
    max_tokens = (rc.max_tokens if rc is not None else None) or env_rc.max_tokens
    temperature = rc.temperature if rc is not None else None
    if temperature is None:
        temperature = env_rc.temperature
    timeout = (rc.timeout if rc is not None else None) or env_rc.timeout
    num_retries = rc.num_retries if rc is not None else None
    if num_retries is None:
        num_retries = env_rc.num_retries
    kwargs: dict[str, Any] = {}
    if api_base is not None:
        kwargs["api_base"] = api_base
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    if temperature is not None:
        kwargs["temperature"] = temperature
    if timeout is not None:
        kwargs["timeout"] = timeout
    if num_retries is not None:
        kwargs["num_retries"] = num_retries
    return LLMPolicy(**kwargs)


def _require_llm_configured_or_exit(*models: str, provider: str | None = None) -> None:
    """Pre-flight :func:`~mylonite.config.require_llm_configured` for every
    resolved model a live run will actually call (planner/customiser/judge
    can each be a different provider — see ``scan``'s ``_resolve_role_model``)
    — ``EXIT_CONFIG`` before any adapter/subprocess/engine work starts,
    naming every way to set a credential, instead of a scan/gate/validate/
    ablate run burning a full attempt (spinning up an MCP subprocess, etc.)
    one attempt at a time before a missing key surfaces buried in a report.

    This is the ONE place the deleted ``MyloniteSettings.require_llm()``'s
    "no default provider, fail loudly" invariant (CLAUDE.md) is actually
    enforced as a pre-flight, not just as a later per-attempt diagnosis.
    """
    from mylonite.config import LLMNotConfiguredError, require_llm_configured

    seen: set[str] = set()
    for m in models:
        if m in seen:
            continue
        seen.add(m)
        try:
            require_llm_configured(model=m, provider=provider)
        except LLMNotConfiguredError as exc:
            echo_err(str(exc))
            raise typer.Exit(code=EXIT_CONFIG) from exc


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
        if scope is None or authorize != scope:
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
    randomize_exfil: Annotated[
        bool | None,
        typer.Option(
            "--randomize-exfil/--no-randomize-exfil",
            help=(
                "Mint a unique exfil destination per run instead of the demo address, so "
                "a finding proves the target leaks to ANY attacker destination "
                "(generalizes) rather than only the one literal address (avoids 'teaching "
                "to the test'). Defaults ON for live custom-target scans; the reference/"
                "replay path never randomizes. Matches generate/validate/gate's own default "
                "(A5)."
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
    # T14: auto-discovered from ./mylonite.yaml when no --config is passed —
    # was gate-only before; see _discover_run_config.
    config_root: Path | None = None
    _config_path, rc = _discover_run_config(run_config_path, command="scan")
    env_rc = _env_run_config_or_exit()
    # No --provider CLI flag any more (removed 0.7.10, T13's deprecated
    # alias). `provider` can still arrive via mylonite.yaml's `provider:` key
    # or MYLONITE_PROVIDER below -- both remain (separately deprecated, but
    # not removed) sources _resolve_model_ref still warns on.
    provider: str | None = None
    if rc is not None:
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        planner_model = planner_model or rc.planner_model
        customiser_model = customiser_model or rc.customiser_model
        judge_model = judge_model or rc.judge_model
        max_llm_calls = _resolve_option(max_llm_calls, rc.max_llm_calls, _DEFAULT_MAX_LLM_CALLS)
        config_root = rc.root
    else:
        max_llm_calls = _resolve_option(max_llm_calls, None, _DEFAULT_MAX_LLM_CALLS)
    # MYLONITE_MODEL / MYLONITE_PROVIDER / role-model env vars are the
    # lowest-precedence source, below mylonite.yaml.
    model = model or env_rc.model
    provider = provider or env_rc.provider
    planner_model = planner_model or env_rc.planner_model
    customiser_model = customiser_model or env_rc.customiser_model
    judge_model = judge_model or env_rc.judge_model
    effective_policy = _resolve_llm_policy(rc, env_rc)

    # The resolved artefact Layout: an explicit --output-dir always wins outright
    # (below); absent that, mylonite.yaml's `root:` / MYLONITE_ROOT / the built-in
    # default decide where scan artefacts land — and, by construction, where
    # `generate --latest` later looks for them (both read mylonite.layout.Layout).
    layout = _layout_for(ctx, config_root=config_root)
    effective_output_dir = output_dir if output_dir is not None else layout.scans

    # Resolve provider + model with sensible defaults so dry-run doesn't require
    # a live LLM provider configured.
    base_model = model or "claude-sonnet-4-6"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    # Role-separated models: each defaults to the base model. Validate +
    # resolve any explicit override through ModelRef exactly like --model —
    # it drives the identical LiteLLM call path, so an unroutable override
    # must reject at CLI-argument time too, not just fail later mid-scan.
    # `.provider` is discarded: a role override doesn't get its own env-var
    # check, only the base model's provider feeds ScanConfig/env lookups.
    def _resolve_role_model(override: str | None) -> str:
        if not override:
            return effective_model
        _validate_model_string(override)
        return _parse_model_ref_or_exit(override, provider).raw

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

    # A named positional target (e.g. 'reference:vulnerable', 'mcp:filesystem')
    # combined with --target-file is never meaningful — --target-file already
    # fully describes a custom target on its own. The custom-target branch below
    # (`target_file is not None or target == "mcp:custom"`) is checked BEFORE
    # every other branch, so passing both would silently ignore the named
    # positional argument entirely and scan --target-file's target instead —
    # surprising for an operator who typed e.g. 'mcp:filesystem' expecting the
    # BUNDLED family (DCR-0010: this used to be checked only for 'reference:*',
    # leaving 'mcp:<family>' + --target-file silently mis-routed the same way).
    # (Unlike `gate`'s #24 fix, `scan` never computed a separate
    # `is_reference`-style variable read downstream — `report_target_id` is
    # always set INSIDE the branch that actually ran, so there is no
    # oracle/routing-divergence bug here, just this silent-argument-ignoring
    # footgun.) Reject the combination up front with a clear message. Only
    # 'mcp:custom' (which itself means "build the custom target from CLI
    # flags", never from --target-file) and no positional target at all are
    # exempt.
    if target is not None and target != "mcp:custom" and target_file is not None:
        echo_err(
            f"scan: --target-file already fully describes a custom target and can't "
            f"be combined with a positional target ({target!r}). Pass a custom "
            "target via --target-file alone (drop the positional target argument), "
            f"or drop --target-file to scan {target!r} instead."
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

    # T14/H3: the "no default provider, fail loudly" invariant, enforced
    # BEFORE any adapter/subprocess/engine work starts (not just later, one
    # attempt at a time, as a buried per-attempt diagnosis) -- but AFTER
    # every other config/usage validation above (authorize, target shape,
    # seed_arm, ...) so a more specific error still wins when both apply.
    # --dry-run makes no live LLM call at all (ScanConfig.dry_run
    # short-circuits before invocation), so it is deliberately exempt.
    if not dry_run:
        _require_llm_configured_or_exit(
            effective_planner_model,
            effective_customiser_model,
            effective_judge_model,
            provider=provider,
        )

    customiser = PayloadCustomiser(model=effective_customiser_model, purpose=effective_purpose)
    judge = SuccessJudge(model=effective_judge_model)

    # A5: randomize the exfil destination by DEFAULT on live custom-target scans, so a
    # finding proves the target leaks to ANY attacker address, not the one demo literal
    # baked into every W2/W3 seed (avoids 'teaching to the test'). The reference/replay
    # path must never randomize — it replays committed fixtures pinned to the demo
    # address. Explicit --randomize-exfil / --no-randomize-exfil always wins. Mirrors
    # generate's/gate's own tri-state resolution.
    if randomize_exfil is None:
        randomize_exfil = not report_target_id.startswith("reference:")

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
        randomize_exfil=randomize_exfil,
    )

    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=attack_modules,
        customiser=customiser,
        judge=judge,
    )

    from mylonite.scan._llm import llm_scope

    try:
        # T14: activates effective_policy (mylonite.yaml/env-resolved
        # LLMPolicy) for every LiteLLM call this run makes — the customiser,
        # judge, and (via LLMPlanner) the planner all read it through
        # scan._llm.active_policy(). asyncio.run() copies the current
        # contextvar context into the coroutine it schedules, so entering
        # this scope BEFORE asyncio.run (rather than inside ScanEngine.run,
        # which separately owns the budget-counter scope) is sufficient.
        with llm_scope(policy=effective_policy):
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

        # write_artefacts() redacts secret-shaped string leaves internally
        # (redact_value(), 0.7.9/DCR-0002) before persisting scan_report.json
        # and each exploit_*.json — never structural, so schema validation and
        # replay both keep working on the redacted copy. The console-rendered
        # summary string below is separately redacted before display.
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


def _backfill_scan_report(
    source_report: Path,
    out_dir: Path,
    *,
    json_mod: Any,
    trimmed_cache: dict[Path, dict[str, str] | None] | None = None,
) -> None:
    """T12 back-fill: co-locate a TRIMMED ``scan_report.json`` next to a
    ``generate``-emitted custom-target test.

    ``scan`` writes ``scan_report.json`` into the SCAN dir (``exploit_path.parent``
    in :func:`_emit_generated_test`), but ``generate`` writes its output into a
    DIFFERENT directory (``layout.generated_for(slug)``, e.g.
    ``.mylonite/generated/<slug>/``). Without this, an exploit with no embedded
    ``mylonite.exec.*`` execution-context metadata (e.g. one scanned before this
    release) has no sibling report for ``testkit._resolve_exec_context`` to
    back-fill from once co-located there — the back-fill safety net is dead in
    practice against the real CLI-produced layout.

    Writes ONLY ``{"model": ..., "provider": ...}`` — never a verbatim copy.
    Unlike ``target.yaml`` (redacted before copying, see the caller), a raw
    ``ScanReport``'s ``attempts`` can carry unredacted target/judge free text,
    and ``out_dir`` is a directory this project tells the operator to commit.
    A no-op (nothing written, no error) when ``source_report`` is absent,
    unparseable, or doesn't carry both fields — this is a best-effort back-fill,
    not a hard requirement (``testkit`` raises its own loud error at test-run
    time if nothing ever supplied a usable model/provider).

    ``trimmed_cache``, when supplied, memoises the trimmed result per resolved
    ``source_report`` path — a multi-finding scan dir invokes this once per
    exploit, all against the SAME scan dir's ``scan_report.json``, so re-reading
    and re-parsing the identical file on every finding is pure overhead
    (mirrors ``validated_target_files`` below). Absent (``None``), every call
    re-reads independently.
    """
    resolved_source = source_report.resolve()
    if trimmed_cache is not None and resolved_source in trimmed_cache:
        trimmed = trimmed_cache[resolved_source]
    else:
        trimmed = None
        if source_report.is_file():
            try:
                report_data = json_mod.loads(source_report.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report_data = None
            if isinstance(report_data, dict):
                candidate = {
                    key: report_data[key]
                    for key in ("model", "provider")
                    if isinstance(report_data.get(key), str)
                }
                # Only useful to testkit's back-fill if BOTH fields are present —
                # a partial trim (e.g. model only) would silently mask that the
                # source report itself was incomplete.
                trimmed = candidate if {"model", "provider"} <= candidate.keys() else None
        if trimmed_cache is not None:
            trimmed_cache[resolved_source] = trimmed

    if trimmed is None:
        return

    colocated_report = out_dir / "scan_report.json"
    colocated_report.write_text(
        json_mod.dumps(trimmed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    echo(f"Wrote report:  {colocated_report} (model/provider back-fill only)")


def _dispatch_emit(generator: Any, exploit: Any, context: ExecContext | None) -> Any:
    """Call ``generator.emit()``, passing ``context=`` only if the generator
    actually accepts it.

    ``TestGenerator.CONTRACT_VERSION`` moved 0.1.0 -> 0.2.0 in 0.7.10 to add
    an optional ``context: ExecContext | None = None`` parameter to ``emit``
    (see ``contracts/test_generator.py``). A third-party plugin still built
    against 0.1.x only defines ``emit(self, exploit)`` — unconditionally
    calling ``generator.emit(exploit, context=context)`` would raise
    ``TypeError: emit() got an unexpected keyword argument 'context'`` for
    such a plugin.

    This is a TEMPORARY compat bridge for pre-0.2.0 third-party
    ``TestGenerator`` plugins: inspect the plugin's ``emit`` signature
    BEFORE calling it (rather than wrapping the call in a broad
    ``except TypeError``, which could just as easily mask a real bug
    *inside* a conforming ``emit()`` implementation and misattribute it to
    this bridge), and only pass ``context=`` when the signature declares it
    (by name or via ``**kwargs``).
    """
    try:
        sig = inspect.signature(generator.emit)
    except (TypeError, ValueError):
        # Signature couldn't be introspected (e.g. a non-Python callable) —
        # be conservative and use the pre-0.2.0 call shape.
        return generator.emit(exploit)
    accepts_context = "context" in sig.parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    if accepts_context:
        return generator.emit(exploit, context=context)
    return generator.emit(exploit)


def _emit_generated_test(
    exploit: Any,
    exploit_path: Path,
    out_dir: Path,
    target_file: Path | None,
    *,
    json_mod: Any,
    validated_target_files: set[Path] | None = None,
    scan_report_cache: dict[Path, dict[str, str] | None] | None = None,
    redacted_target_cache: dict[Path, str] | None = None,
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

    ``scan_report_cache`` is the same style of cache for
    :func:`_backfill_scan_report`'s trimmed ``scan_report.json`` read.

    ``redacted_target_cache`` (DCR-0013) is the same style of cache for the
    target file's REDACTED text written into each finding's ``target.yaml``
    below: ``validated_target_files`` only remembers "already validated"
    (a boolean), so before this the identical file was still re-read from
    disk and re-run through ``redact_target_yaml`` on every finding in a
    multi-finding scan dir sharing one target file. Absent (``None``), every
    call reads+redacts independently — the original, always-correct
    behaviour.
    """
    from mylonite._redaction import redact_target_yaml, redact_value
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
    )

    # Enrich compliance ONCE (derives NIST from the OWASP cross-refs) and use the
    # SAME enriched record for both the emitted test's marks and the co-located
    # exploit JSON. Writing the raw record here left the persisted exploit (what
    # `mylonite report` reads) without the NIST tags the marks carried — the
    # marks-vs-report inconsistency from the v0.7.0 assessment.
    enriched = _map_compliance(exploit)
    # T12/0.7.10: build the exec context from the exploit's stamped
    # mylonite.exec.* metadata and pass it explicitly rather than relying on
    # the generator to re-derive it — see ExecContext.from_metadata's and
    # TestGenerator.emit's docstrings. _dispatch_emit is the compat bridge
    # for any pre-0.2.0 third-party generator that doesn't accept `context`.
    exec_ctx = ExecContext.from_metadata(enriched.payload.metadata)
    generated = _dispatch_emit(ReferencePytestGenerator(), enriched, exec_ctx)
    out_dir.mkdir(parents=True, exist_ok=True)

    test_path = out_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")

    # Co-locate the exploit under the exact name the emitted test loads
    # (`load_exploit(here / "exploit_<pattern_id>.json")`).
    # Never write the exploit's captured response/payload verbatim into a
    # directory we tell the operator to commit — a successful exfiltration
    # attack can carry a live secret in raw_response (DCR-0002 companion).
    # Mirrors the redact_target_yaml() treatment applied to colocated_target
    # a few lines below.
    colocated_exploit = out_dir / f"exploit_{safe_slug(enriched.pattern_id)}.json"
    colocated_exploit.write_text(
        json_mod.dumps(redact_value(enriched.model_dump(mode="json")), indent=2, sort_keys=True)
        + "\n",
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

    # T12 back-fill (see _backfill_scan_report's docstring): only applies to
    # custom targets — a reference-target test replays the bundled twin via
    # assert_guard_holds, which takes no model/provider kwargs and has no use
    # for a co-located scan_report.json at all.
    if is_custom:
        _backfill_scan_report(
            exploit_path.parent / "scan_report.json",
            out_dir,
            json_mod=json_mod,
            trimmed_cache=scan_report_cache,
        )

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
        # DCR-0013: read + redact at most once per unique target file, cached
        # across every finding in a multi-finding loop (see the cache's
        # docstring above) instead of redoing this on every single finding.
        if redacted_target_cache is not None and resolved_target_file in redacted_target_cache:
            redacted_target_text = redacted_target_cache[resolved_target_file]
        else:
            redacted_target_text = redact_target_yaml(target_file.read_text(encoding="utf-8"))
            if redacted_target_cache is not None:
                redacted_target_cache[resolved_target_file] = redacted_target_text
        colocated_target.write_text(redacted_target_text, encoding="utf-8")
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

    # No --config FLAG on `generate` (kept minimal), but DCR-0006: it still
    # auto-discovers ./mylonite.yaml (same helper scan/gate/validate/ablate
    # use) so its `root:` key is honored here too. Before this fix, absent an
    # explicit --scans-dir, the resolved Layout was ONLY MYLONITE_ROOT / the
    # built-in default via the root callback (ctx.obj) -- which per
    # _CliState's own docstring resolves BEFORE mylonite.yaml's `root:` is
    # even readable -- so a scan written under a `root:`-configured directory
    # was invisible to `generate --latest`, reporting "no scans found" even
    # though a scan just ran. An explicit --scans-dir (highest priority; an
    # INPUT read by --latest, deliberately NOT named --output-dir like scan's
    # own flag — that name would mislead as "where generate writes", which is
    # --out's job) points --latest at that exact scans root directly, closing
    # the "generate --latest hardcodes .mylonite/scans" bug outright: a scan
    # written to a one-off custom dir via `scan --output-dir X` is found by
    # `generate --latest --scans-dir X`. Silently unused when SCAN_PATH is
    # passed explicitly instead of --latest — consistent with how --latest
    # itself is already ignored in that case (see _resolve_exploit_paths: an
    # explicit scan_path short-circuits before either is consulted).
    _config_path, rc = _discover_run_config(None, command="generate")
    config_root = rc.root if rc is not None else None
    layout = _layout_for(ctx, config_root=config_root)
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
    # Mirrors validated_target_files: a multi-finding scan dir shares one
    # scan_report.json across every finding's _backfill_scan_report call.
    scan_report_cache: dict[Path, dict[str, str] | None] = {}
    # DCR-0013: same idea again for the target file's REDACTED text — a
    # multi-finding scan dir's findings share one target file, so the
    # read + redact_target_yaml() work below is done at most once per unique
    # path, not once per finding.
    redacted_target_cache: dict[Path, str] = {}
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
                scan_report_cache=scan_report_cache,
                redacted_target_cache=redacted_target_cache,
            )
        except UnsafeExploitRecord as exc:
            echo_exc(f"could not generate a test for {exploit_path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

    raise typer.Exit(code=EXIT_SUCCESS)


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
    planner_model: str | None = None,
    customiser_model: str | None = None,
    judge_model: str | None = None,
    policy: Any | None = None,
) -> Any:
    """Validate a custom-target test by re-driving the REAL target (R1/R8).

    DCR-0009: this re-drives a real third-party target — sending live attack
    payloads (including exfil) — so it is gated by the same ``--authorize``
    rule as ``scan``/``gate`` (:func:`_enforce_custom_authorize`), not zero
    checks.

    ``planner_model``/``customiser_model``/``judge_model`` (T14) each default
    to ``model`` (via ``DifferentialValidator``'s own fallback, mirroring
    ``ScanConfig.resolved_planner_model`` et al.) when ``None``. ``policy``
    (an :class:`~mylonite.scan.llm_policy.LLMPolicy`) is activated for the
    live re-drive via ``scan._llm.llm_scope`` when given.
    """
    from mylonite.gate.mitigation import weakness_class_for
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_adapter_for_spec
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.plugins._mcp.twins import plan_twins
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

    # T14/H3: the "no default provider, fail loudly" invariant -- a cheap,
    # no-network credential-presence check, distinct from (and cheaper than)
    # _provider_preflight's real live call just below. Ordered AFTER the
    # authorize check above for the same DCR-0008 reason that preflight is:
    # authorization gates every live-driving action, even one this static.
    _require_llm_configured_or_exit(
        planner_model or model, customiser_model or model, judge_model or model, provider=provider
    )

    # DCR-0008: fail fast on an unreachable provider with a distinct exit 4 —
    # otherwise the full N-iteration live loop against the REAL target would
    # just run to a misleading non-discriminating REJECTED. Always AFTER the
    # authorize check above: authorization gates every live-driving action,
    # and this preflight (a scan against the bundled reference twin, never the
    # operator's real target) must not fire before an unauthorized request is
    # rejected.
    try:
        reachable = _provider_preflight(
            provider, model, timeout_s=iteration_timeout_s or _DEFAULT_ITERATION_TIMEOUT_S
        )
    except (ModuleNotFoundError, ImportError) as exc:
        _exit_if_missing_kitchen_sink(exc)
        raise
    if not reachable:
        echo_err(
            "no provider reachable — set ANTHROPIC_API_KEY, or pass "
            "--model provider/modelname for another LiteLLM provider (e.g. "
            "--model openai/gpt-4o)."
        )
        raise typer.Exit(code=EXIT_PROVIDER)

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)

    # M1: the differential leg (re-driving a guarded twin of the SAME real target,
    # model held constant) gates `kept` BY DEFAULT — proving the *safeguard*, not the
    # model, carries the security. `--fast` opts out (it doubles the live runs per
    # finding); a weakness with no inferable control falls back loudly to the
    # stability/effect/consensus gate.
    #
    # plan_twins is the ONE place that decides raw-vs-guarded (server-layer
    # control_env / vulnerable_launch / rest input-framing / boundary shim /
    # no differential) — `gate` and `testkit.assert_control_holds` call the exact
    # same function with the exact same inputs, so this decision cannot drift
    # between them (the bug this closes: `gate` used to hold a parallel, drifted
    # copy of this logic that ignored control_env entirely).
    cw = weakness_class_for(generated.exploit)
    plan = plan_twins(spec, weakness=cw, fast=fast, prove_input_control=prove_input_control)
    if plan.banner:
        for line in plan.banner.split("\n"):
            echo_err(f"validate: {line}")
    if not randomize_exfil:
        echo_err(
            "note: --no-randomize-exfil is set, so the result only proves the target blocks the "
            "one demo literal, not exfil to ANY attacker address. Drop it (randomization is the "
            "default for custom targets) to avoid 'teaching to the test'."
        )

    effective_planner_model = planner_model or model

    def _factory() -> Any:
        return build_adapter_for_spec(
            spec, scope=tf.scope, model=effective_planner_model, intent=plan.raw
        )

    guarded_factory: Any = None
    if plan.control_weakness is not None:

        def _guarded() -> Any:
            return build_adapter_for_spec(
                spec, scope=tf.scope, model=effective_planner_model, intent=plan.guarded
            )

        guarded_factory = _guarded

    if plan.guarded_is_server_layer:
        twin_kind = "real server-layer twin"
    elif plan.guarded.input_frame:
        twin_kind = "input data-framing guard"
    elif plan.control_weakness is not None:
        twin_kind = "synthetic boundary twin"
    else:
        twin_kind = "none (differential not applicable to a black-box target)"
    echo_err(
        f"validate re-drives the REAL target {spec.family!r} live — {iterations} runs "
        f"+ multi-judge consensus + effect probe (guarded side: {twin_kind})."
    )
    if (
        plan.control_weakness is not None
        and not plan.guarded_is_server_layer
        and not plan.guarded.input_frame
    ):
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
        planner_model=planner_model,
        customiser_model=customiser_model,
        judge_model=judge_model,
        target_adapter_factory=_factory,
        guarded_adapter_factory=guarded_factory,
        control_weakness=plan.control_weakness,
        randomize_exfil=randomize_exfil,
        guarded_is_server_layer=plan.guarded_is_server_layer,
        control_context=plan.control_context,
        iteration_timeout_s=iteration_timeout_s,
        progress_cb=lambda msg: echo_err(f"  … {msg}"),
    )
    from mylonite.scan._llm import llm_scope

    with llm_scope(policy=policy):
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
        # DCR-0004: a gating_legs entry with no matching outcome must render
        # explicitly as missing, not silently drop out of the AND-chain — an
        # operator reading an incomplete formula with no mark or mention of
        # the missing leg can't tell the VERDICT might depend on it.
        rendered = " AND ".join(
            f"{leg} {_mark(legs_by_stage[leg].passed)}"
            if leg in legs_by_stage
            else f"{leg} (missing)"
            for leg in report.gating_legs
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
            # DCR-0007: a metamorphic-only failure (every other leg passes) is a
            # documented gating leg that can REJECT a report on its own (see the
            # "metamorphic robustness gates kept" note above) -- without this
            # key the remediation loop below silently skipped it, so the
            # operator saw "verdict: REJECTED" with zero guidance for the
            # actual failing leg.
            "metamorphic": (
                "metamorphic fail: the differential did not survive a robustness "
                "perturbation (see the failing row above) - the exploit may be "
                "over-fit to the exact seed wording; try a paraphrase-robust payload."
            ),
        }
        for outcome in report.outcomes:
            if not outcome.passed and outcome.stage in _remediation:
                console_print(console, f"[red]  remediation: {_remediation[outcome.stage]}[/red]")


def _provider_preflight(
    provider: str, model: str, *, timeout_s: float = _DEFAULT_ITERATION_TIMEOUT_S
) -> bool:
    """Cheap reachability probe before the (expensive) live validation loop.

    Runs ONE vulnerable reference scan. If it aborts ``provider_unreachable``,
    the validator's N-iteration loop would too — so we fail fast with a distinct
    exit 4 rather than burning iterations and reporting a misleading non-discrim
    result. Returns True iff the provider is reachable.

    DCR-0008: bounded by ``timeout_s`` (defaults to the same
    ``_DEFAULT_ITERATION_TIMEOUT_S`` the sibling ``DifferentialValidator``
    construction 30 lines below explicitly threads via
    ``iteration_timeout_s``) — this preflight exists specifically to fail
    fast rather than burn iterations, but had no bound of its own: a provider
    that accepts the connection and then stalls mid-response (rather than
    erroring outright) would hang ``asyncio.run(engine.run())`` open-ended,
    defeating the whole "fail fast" purpose and hanging the CLI/CI job with
    no way out. A timeout is treated the same as any other unreachable-
    provider outcome (returns ``False``), not re-raised, so every caller's
    existing ``if not reachable: ... exit(EXIT_PROVIDER)`` handling already
    covers it without a new except clause.
    """
    from mylonite.scan.wiring import build_scan, note_id_counter

    engine = build_scan(
        "vulnerable",
        completion_fn=None,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
    )
    try:
        result = asyncio.run(asyncio.wait_for(engine.run(), timeout=timeout_s))
    except TimeoutError:
        return False
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
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model for the live validation run."),
    ] = None,
    planner_model: Annotated[
        str | None,
        typer.Option(
            "--planner-model",
            help=(
                "Override the model that DRIVES the agent-under-test (the planner). "
                "Defaults to --model. Same three-role split as `scan`/`gate`."
            ),
        ),
    ] = None,
    customiser_model: Annotated[
        str | None,
        typer.Option(
            "--customiser-model",
            help=("Override the model that CRAFTS/REFINES attack payloads. Defaults to --model."),
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help=("Override the model that JUDGES whether an attack landed. Defaults to --model."),
        ),
    ] = None,
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config (provider / model / the role "
                "models). Auto-discovered from ./mylonite.yaml when present; an "
                "explicit flag always wins."
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

    # T14/H3: mylonite.yaml auto-discovery + role-model overrides, mirroring
    # scan/gate — `validate` previously had neither --config nor
    # --planner-model/--customiser-model/--judge-model at all, despite
    # DifferentialValidator already accepting all three.
    _config_path, rc = _discover_run_config(run_config_path, command="validate")
    env_rc = _env_run_config_or_exit()
    # No --provider CLI flag any more (removed 0.7.10, T13's deprecated
    # alias). `provider` can still arrive via mylonite.yaml's `provider:` key
    # or MYLONITE_PROVIDER below -- both remain (separately deprecated, but
    # not removed) sources _resolve_model_ref still warns on.
    provider: str | None = None
    if rc is not None:
        provider = provider or rc.provider
        model = model or rc.model
        planner_model = planner_model or rc.planner_model
        customiser_model = customiser_model or rc.customiser_model
        judge_model = judge_model or rc.judge_model
    provider = provider or env_rc.provider
    model = model or env_rc.model
    planner_model = planner_model or env_rc.planner_model
    customiser_model = customiser_model or env_rc.customiser_model
    judge_model = judge_model or env_rc.judge_model
    effective_policy = _resolve_llm_policy(rc, env_rc)

    # T13: `validate` used to be the ONE model-taking command that skipped
    # BOTH `_validate_model_string` and provider routing/derivation entirely
    # -- a plain `provider or "anthropic"` / `model or "<default>"` with no
    # validation at all. It now goes through the same `ModelRef.parse` path
    # as scan/gate/ablate/doctor, deliberately BEFORE `_locate_generated`
    # below so a bad --model fails fast without first requiring a real
    # generated-test dir on disk.
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    def _resolve_validate_role_model(override: str | None) -> str:
        if not override:
            return effective_model
        _validate_model_string(override)
        return _parse_model_ref_or_exit(override, provider).raw

    effective_planner_model = _resolve_validate_role_model(planner_model)
    effective_customiser_model = _resolve_validate_role_model(customiser_model)
    effective_judge_model = _resolve_validate_role_model(judge_model)

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
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            policy=effective_policy,
        )
    else:
        echo_err(
            f"validate runs ~{iterations} iterations x 2 twins live (Haiku) — roughly a "
            "minute, a few cents; needs a provider (ANTHROPIC_API_KEY)."
        )
        # T14/H3: cheap, no-network credential-presence pre-flight before the
        # real live _provider_preflight call just below (no authorize gate on
        # this branch -- the bundled reference twins are safe-by-construction).
        _require_llm_configured_or_exit(
            effective_planner_model,
            effective_customiser_model,
            effective_judge_model,
            provider=provider,
        )
        # Fail fast on an unreachable provider with a distinct exit 4 — otherwise
        # the full loop would just report a misleading non-discriminating result.
        try:
            reachable = _provider_preflight(
                effective_provider, effective_model, timeout_s=iteration_timeout
            )
        except (ModuleNotFoundError, ImportError) as exc:
            _exit_if_missing_kitchen_sink(exc)
            raise
        if not reachable:
            echo_err(
                "no provider reachable — set ANTHROPIC_API_KEY, or pass "
                "--model provider/modelname for another LiteLLM provider (e.g. "
                "--model openai/gpt-4o)."
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
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            # DCR-0007: thread --iteration-timeout through on the reference-target
            # path too, matching the guard already applied to _validate_custom — a
            # stalled provider call must not be able to hang the CLI/CI job
            # indefinitely just because this branch omitted the kwarg.
            iteration_timeout_s=iteration_timeout,
            metamorphic_strategies=["paraphrase"] if fast else None,
            # Record the canonical guarded fixtures into the gen dir's `fixtures/`
            # and run the on-disk committed test offline as a full-pass build —
            # closing the validate→committed-artefact loop.
            record_fixtures_dir=test_path.parent / "fixtures",
            progress_cb=lambda msg: echo_err(f"  … {msg}"),
        )
        from mylonite.scan._llm import llm_scope

        with llm_scope(policy=effective_policy):
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
    # Redact the per-leg free text first (DCR-0003): outcome.detail can carry a
    # live exception message or third-party ValidatorBase detail string, and
    # `validate` tells the operator to commit this exact directory when the
    # test is kept — the console table already redacts this same field before
    # printing it (_render_validation_report), so persist the same sanitized
    # copy instead of the raw report.
    from mylonite._redaction import redact as _redact_report_text

    sanitized_report = report.model_copy(
        update={
            "outcomes": [
                outcome.model_copy(update={"detail": _redact_report_text(outcome.detail)})
                for outcome in report.outcomes
            ],
            "notes": _redact_report_text(report.notes) if report.notes else report.notes,
        }
    )
    report_path = test_path.parent / "validation_report.json"
    report_path.write_text(sanitized_report.model_dump_json(indent=2) + "\n", encoding="utf-8")

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
            except (FileNotFoundError, ValueError) as exc:
                # DCR-0003: don't silently degrade to an empty --sarif/--json
                # bundle. `dashboard_exploit` stays None below, which zeroes
                # the findings list in `to_sarif`/`to_bundle` -- a
                # REJECTED/vulnerable validation would otherwise show ZERO
                # findings in GitHub code scanning with no diagnostic that
                # compliance data was actually missing. Warn and keep going
                # (degraded but honest), never crash the command over it.
                echo_exc(
                    f"warning: could not load compliance data from {exploit_matches[0]} "
                    "-- --sarif/--json output for this artefact will omit the finding",
                    exc,
                )
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

        # Code-quality review of the A1 fix (43dc63b): a legacy-version or
        # hand-edited/corrupted scan_report.json can carry an `aborted` value
        # outside the current AbortReason enum -- `ScanOutcome.from_report`
        # raises ValueError for exactly that case. Left uncaught, that
        # surfaces as a bare traceback (exit 1, empty output) -- strictly
        # worse than the silent-exit-0 bug this branch exists to fix.
        # Degrade the same way the sibling try/except above (unparseable
        # report) already does: a clear message, no traceback, EXIT_CONFIG.
        #
        # 0.7.10: `ScanReport.aborted` is now `AbortReason | None` (a real
        # Pydantic enum), so an unrecognised value is normally already
        # rejected above, at `ScanReport.model_validate_json()` -- this
        # try/except is now defense-in-depth for a report that reached this
        # point via a path that bypasses Pydantic validation (e.g.
        # `model_construct()`), rather than the primary guard it used to be.
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
        if "://" in val:
            # URL form. DCR-0011: match the SQLite marker against the URL
            # SCHEME, not an unanchored substring test anywhere in the value —
            # `"sqlite" in low` used to misclassify e.g.
            # `postgresql://sqlite-cache.internal:5432/app` (a non-SQLite URL
            # whose HOSTNAME merely contains "sqlite") as a relative SQLite path.
            scheme = low.split("://", 1)[0]
            if scheme not in ("sqlite", "sqlite3"):
                continue
            # The single '/' after the authority separator is NOT part of the
            # path, so `sqlite:///data.db` is RELATIVE `data.db` while
            # `sqlite:////abs/x.db` is absolute `/abs/x.db` — the exact #18 trap.
            after = val.split("://", 1)[1]
            path = after[1:] if after.startswith("/") else after
        else:
            if not ("sqlite" in low or low.endswith((".db", ".sqlite", ".sqlite3"))):
                continue
            path = val
        is_posix_abs = path.startswith("/")
        is_win_abs = len(path) >= 2 and path[1] == ":"  # C:\… or C:/…
        if not (is_posix_abs or is_win_abs):
            flagged.append(key)
    return flagged


_RESERVED_FAMILIES = frozenset({"filesystem", "fetch", "github", "target", "app"})


def _redact_credential_shaped_query_params(url: str) -> str:
    """Mask any query-string parameter VALUE that looks like a live credential.

    ``dump_target_file``/``redact_target_yaml``'s generic sweep already masks a
    value keyed by a RECOGNISED credential name (``api_key=``, ``token=``,
    ``secret=``, ...) or matching a known provider-key prefix (``sk-``,
    ``AKIA``, ...). This closes the residual gap for an opaque,
    key-name-agnostic token under a non-standard param name (e.g. a webhook
    signing secret passed as ``?sig=<opaque>``), mirroring the broader
    :func:`mylonite._redaction.looks_like_api_key` heuristic that ``--env``
    values already get via ``redact_env``/``_is_secret_env`` (DCR-0002).
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    from mylonite._redaction import REDACTION_PLACEHOLDER, looks_like_api_key

    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    masked = [(k, REDACTION_PLACEHOLDER if looks_like_api_key(v) else v) for k, v in pairs]
    new_query = urlencode(masked)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _redact_credential_shaped_json_body(body: str) -> str:
    """Mask any JSON string leaf that looks like a live credential (DCR-0002).

    Best-effort: only touches ``body`` when it parses as JSON (the common
    case — the default/most rest-body templates are simple JSON objects) and
    only rewrites it when something was actually masked, so a non-JSON or
    already-clean body is returned byte-for-byte unchanged (never reformatted
    for no reason). Uses the same :func:`~mylonite._redaction.looks_like_api_key`
    heuristic as :func:`_redact_credential_shaped_query_params` — the
    ``{prompt}`` placeholder itself is far too short to ever match it.
    """
    import json

    from mylonite._redaction import REDACTION_PLACEHOLDER, looks_like_api_key

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return body

    def _walk(value: object) -> object:
        if isinstance(value, str):
            return REDACTION_PLACEHOLDER if looks_like_api_key(value) else value
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    masked = _walk(data)
    if masked == data:
        return body
    return json.dumps(masked)


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

    # This TargetFile is only ever serialised to disk below — no live request is
    # made from this scaffold path — so redacting rest_url/rest_body BEFORE
    # construction is safe and closes the credential-in-URL leak (DCR-0002)
    # at the source, on top of dump_target_file's own generic redaction pass.
    safe_url = _redact_credential_shaped_query_params(rest_url)
    safe_body = _redact_credential_shaped_json_body(body)

    try:
        tf = TargetFile(
            family=family,
            transport="rest",
            weakness_classes=["W2"],
            request=RequestSpec(url=safe_url, body=safe_body, response_path=rest_response_path),
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
        # DCR-0008: no visible timeout on this outbound GitHub API call — a
        # stalled call could hang the gate job indefinitely. Bind a sane
        # explicit timeout onto the runner at this call site rather than
        # changing post_check_run's/Runner's signature.
        _bounded_run = functools.partial(pr_mod._default_run, timeout=_GH_API_TIMEOUT_S)
        post_check_run(repo_root, payload, gate_dir=gate_dir, _run=_bounded_run)
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
                "Defaults to --model. Same three-role split as `scan` — see its "
                "--planner-model help for the rationale."
            ),
        ),
    ] = None,
    customiser_model: Annotated[
        str | None,
        typer.Option(
            "--customiser-model",
            help=(
                "Override the model that CRAFTS/REFINES attack payloads (the red-team / "
                "attacker side). Defaults to --model."
            ),
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help=("Override the model that JUDGES whether an attack landed. Defaults to --model."),
        ),
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

    # Captured BEFORE mylonite.yaml may fill target_file in below, so the
    # DCR-0001 guard further down can name the actual source (explicit flag vs.
    # config) in its error rather than just reporting the resolved path.
    _target_file_flag = target_file

    # Declarative run config (mylonite.yaml): mirror `scan` so `gate` fills any flag
    # the user omitted (target_file / authorize / provider / model / budget) from a
    # project config. Auto-discovered from ./mylonite.yaml when present and no
    # --config is passed; an explicit flag always wins. Closes the parity gap where
    # `gate` required --target-file even though the project's mylonite.yaml set it.
    # T14: delegates to the same _discover_run_config every command shares now.
    config_path, rc = _discover_run_config(run_config_path, command="gate")
    env_rc = _env_run_config_or_exit()
    # No --provider CLI flag any more (removed 0.7.10, T13's deprecated
    # alias). `provider` can still arrive via mylonite.yaml's `provider:` key
    # or MYLONITE_PROVIDER below -- both remain (separately deprecated, but
    # not removed) sources _resolve_model_ref still warns on.
    provider: str | None = None
    if rc is not None:
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        planner_model = planner_model or rc.planner_model
        customiser_model = customiser_model or rc.customiser_model
        judge_model = judge_model or rc.judge_model
        max_llm_calls = _resolve_option(max_llm_calls, rc.max_llm_calls, _DEFAULT_MAX_LLM_CALLS)
        config_root = rc.root
    else:
        max_llm_calls = _resolve_option(max_llm_calls, None, _DEFAULT_MAX_LLM_CALLS)
        config_root = None
    model = model or env_rc.model
    provider = provider or env_rc.provider
    planner_model = planner_model or env_rc.planner_model
    customiser_model = customiser_model or env_rc.customiser_model
    judge_model = judge_model or env_rc.judge_model
    effective_policy = _resolve_llm_policy(rc, env_rc)

    # The resolved artefact Layout, mirroring `scan`: an explicit --out always
    # wins outright; absent that, mylonite.yaml's `root:` / MYLONITE_ROOT / the
    # built-in default decide where gate artefacts (test, exploit, check-run
    # scratch file) land instead of the historical hardcoded `.mylonite/gate`.
    layout = _layout_for(ctx, config_root=config_root)
    out = out if out is not None else layout.gate

    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    # Role-separated models (T14, mirroring `scan`'s _resolve_role_model):
    # each defaults to the base model.
    def _resolve_gate_role_model(override: str | None) -> str:
        if not override:
            return effective_model
        _validate_model_string(override)
        return _parse_model_ref_or_exit(override, provider).raw

    effective_planner_model = _resolve_gate_role_model(planner_model)
    effective_customiser_model = _resolve_gate_role_model(customiser_model)
    effective_judge_model = _resolve_gate_role_model(judge_model)

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

    # DCR-0001: a real 'mcp:<family>[:<scope>]' positional target + a resolved
    # target_file is the same footgun as the 'reference:*' case above, but worse
    # — the branch below (`target_file is not None or target == "mcp:custom"`)
    # tests target_file FIRST, so it would silently gate target_file's target and
    # discard the 'mcp:<family>' argument with NO warning at all. And target_file
    # need not even be an explicit --target-file flag: it may have been pulled
    # from an auto-discovered ./mylonite.yaml (or an explicit --config) above,
    # in which case a command line with zero target-file-shaped flags would still
    # silently override the positional argument. Reject the combination up
    # front, naming both the ignored argument and where target_file came from.
    if (
        target is not None
        and target != "mcp:custom"
        and target.startswith("mcp:")
        and target_file is not None
    ):
        if _target_file_flag is not None:
            target_file_source = "--target-file"
        else:
            target_file_source = f"{config_path} (auto-discovered `target_file:`)"
        echo_err(
            f"gate: a bundled target {target!r} was given on the command line, but "
            f"target_file ({target_file}) is also set via {target_file_source} — "
            "these are mutually exclusive. `gate` would otherwise silently gate the "
            f"target_file's target and discard the {target!r} argument. Drop "
            "--target-file (and any mylonite.yaml `target_file:` entry) to gate "
            f"the bundled {target!r} target, or drop the positional target "
            "argument to gate the custom target."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    tf = None
    # Built once, right after `tf` loads, and reused by BOTH scan_fn (tagging)
    # and validate_fn (twin-building) below — so the two closures share the
    # exact same TargetSpec, not two independently-rebuilt-but-structurally-
    # equal ones. Not strictly required for plan_twins to agree (it's pure), but
    # it removes even the theoretical possibility of the two calls resolving a
    # target file differently.
    custom_spec: Any = None
    # DCR-0014/DCR-0015: the bundled `mcp:<family>[:<scope>]` route sets
    # custom_spec too (below) so scan_fn's tagging step and validate_fn's
    # twin-building can treat it exactly like the custom-target route instead
    # of assuming only `custom`/`reference` routes exist. `mcp_scope` is the
    # scope segment that route's TargetSpec needs (the `custom` route reads it
    # off `tf.scope` instead — there is no TargetFile here to read it from).
    mcp_scope: str | None = None
    routed_to: str
    # DCR-0010: the actual adapter CONSTRUCTION (never anything live/expensive
    # -- no subprocess is spawned until a later invoke()/describe() call, see
    # stdio_adapter.py's own "fresh subprocess per invoke()" docstring) is
    # deferred into this zero-arg factory, invoked only after the
    # LLM-configured pre-flight below succeeds. Every other check in this
    # routing block (target-shape conflicts, `--authorize` presence) still
    # runs eagerly, right here, so a more specific config/usage error still
    # wins over "LLM not configured" when both apply -- unchanged from before.
    adapter_factory: Callable[[], Any]

    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp — enforce --authorize BEFORE loading the file,
        # exactly as scan does.
        if not authorize:
            echo_err("--authorize is required for custom targets. See SECURITY.md.")
            raise typer.Exit(code=EXIT_CONFIG)
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
            custom_spec = build_target_spec(tf)
        else:
            # mcp:custom with inline flags — not supported via gate (no --command etc.)
            echo_err(
                "gate --target-file <yaml> is the custom-target path; "
                "inline mcp:custom flags are not wired in `gate`. "
                "Pass a target YAML via --target-file."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter_factory = functools.partial(
            _build_adapter_for_custom, tf, authorize, effective_planner_model, command="gate"
        )
        routed_to = "custom"
    elif target is None:
        echo_err("no target given. Pass a target (e.g. reference:vulnerable) or --target-file.")
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter_factory = functools.partial(
            _build_adapter_for_reference, target, effective_planner_model
        )
        routed_to = "reference"
    elif target.startswith("mcp:"):
        if not authorize:
            echo_err(
                f"--authorize is required for non-reference targets (got {target!r}). "
                "See SECURITY.md."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        adapter_factory = functools.partial(
            _build_adapter_for_mcp, target, authorize, effective_planner_model
        )
        routed_to = "mcp"
        # Resolve the same TargetSpec `_build_adapter_for_mcp` will validate
        # (family/scope shape only — cheap, no adapter construction) so
        # downstream code can treat this route like the custom-target one —
        # see the custom_spec/mcp_scope comment above.
        from mylonite.plugins._mcp import target_registry

        mcp_family, mcp_scope = _parse_mcp_target(target)
        custom_spec = target_registry.resolve_target(mcp_family, mcp_scope)
    else:
        echo_err(
            f"unknown target shape {target!r}. "
            "Expected 'reference:<variant>', 'mcp:<family>[:<scope>]', or --target-file."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    # Derived from what actually ran (routed_to), NOT re-parsed from the target
    # string — see the up-front rejection above for why the two could diverge.
    is_reference = routed_to == "reference"

    # T14/H3/DCR-0010: the "no default provider, fail loudly" invariant,
    # enforced BEFORE any adapter/subprocess/engine work ACTUALLY starts (the
    # adapter itself is now only constructed by `adapter_factory()` below,
    # after this check passes) -- but AFTER every other config/usage
    # validation above (authorize, target shape, ...), so
    # a more specific error still wins when both apply. `gate` has no
    # --dry-run of its own, so this is unconditional.
    _require_llm_configured_or_exit(
        effective_planner_model,
        effective_customiser_model,
        effective_judge_model,
        provider=provider,
    )

    # DCR-0010: the actual adapter object is constructed here, only after the
    # LLM-configured check above has passed.
    adapter = adapter_factory()

    # --- closures injected into run_gate ---

    def scan_fn() -> ScanOutcomeBundle:
        from mylonite.plugins.registry import discover
        from mylonite.scan._llm import llm_scope
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
            # DCR-0015: the custom route is reachable via TWO equivalent
            # inputs -- an explicit `mcp:custom` positional target, or just
            # `--target-file` with no positional target at all -- and both
            # describe the exact same target. Deriving target_id from the
            # literal `target` string (falling back to `tf.family` only when
            # `target is None`) gave the SAME custom target a DIFFERENT
            # target_id depending on which spelling the operator happened to
            # use: `"mcp:custom"` when typed, `f"mcp:{tf.family}"` when not.
            # Always derive it from `tf.family` on the custom route so it's
            # identical either way; `tf` is always set whenever
            # `routed_to == "custom"` (the only other custom-route branch,
            # inline `mcp:custom` flags, exits before routed_to is assigned)
            # -- branching on `tf is not None` rather than `routed_to ==
            # "custom"` also lets mypy narrow `tf` in this branch.
            target_id=(
                f"mcp:{tf.family}"
                if tf is not None
                else target
                if target is not None
                else "mcp:custom"
            ),
            provider=effective_provider,
            model=effective_model,
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            max_llm_calls=max_llm_calls,
        )
        engine = ScanEngine(
            config=config,
            adapter=adapter,
            attack_modules=attack_modules,
            customiser=PayloadCustomiser(
                model=effective_customiser_model, purpose=purpose or (tf.purpose if tf else None)
            ),
            judge=SuccessJudge(model=effective_judge_model),
        )
        with llm_scope(policy=effective_policy):
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
        if custom_spec is None:
            echo_err("internal: expected a resolved TargetSpec for custom scan_fn tagging")
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.gate.mitigation import weakness_class_for
        from mylonite.plugins._mcp.twins import plan_twins

        # plan_twins is the SAME function validate_fn calls below to build the
        # actual twin — tagging each exploit with plan.control_weakness (rather
        # than independently re-deriving "is this controllable") is what makes it
        # structurally impossible for the tag and the later twin to disagree.
        tagged: list[Any] = []
        announced: set[str] = set()
        for ex in exploits:
            cw = weakness_class_for(ex)
            plan = plan_twins(
                custom_spec, weakness=cw, fast=False, prove_input_control=prove_input_control
            )
            if plan.banner and plan.banner not in announced:
                announced.add(plan.banner)
                for line in plan.banner.split("\n"):
                    echo_err(f"gate: {line}")
            if plan.control_weakness is None:
                tagged.append(ex)
                continue
            meta = {**ex.payload.metadata, "synthetic_control": plan.control_weakness}
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
            exec_ctx = ExecContext.from_metadata(exploit.payload.metadata)
            return _dispatch_emit(ReferencePytestGenerator(), exploit, exec_ctx)
        except UnsafeExploitRecord as exc:
            echo_exc("could not generate a regression test for this finding", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

    def validate_fn(generated: Any) -> Any:
        from mylonite.scan._llm import llm_scope

        if is_reference:
            # DCR-0009: same "all but one" reproducibility rule the custom/mcp
            # branch below explicitly sets (vuln_threshold = iterations - 1) --
            # this branch used to fall back to the constructor default instead,
            # so the reference/demo target's pass/fail reproducibility bar was
            # silently looser than every other target type for no stated reason.
            validator = DifferentialValidator(
                iterations=iterations,
                vuln_threshold=max(1, iterations - 1),
                provider=effective_provider,
                model=effective_model,
                planner_model=effective_planner_model if planner_model else None,
                customiser_model=effective_customiser_model if customiser_model else None,
                judge_model=effective_judge_model if judge_model else None,
                record_fixtures_dir=out / "fixtures",
                progress_cb=lambda msg: echo_err(f"  … {msg}"),
            )
            with llm_scope(policy=effective_policy):
                return validator.validate(
                    generated,
                    ReferenceVulnerableOracle().adapter(),
                    ReferenceVulnerableOracle(),
                )
        # Custom / mcp: both re-drive the REAL target via a TargetSpec-driven
        # twin, mirroring _validate_custom. DCR-0014: the bundled
        # `mcp:<family>[:<scope>]` route never sets `tf` (there is no
        # TargetFile to load for a bundled target) but DOES set custom_spec /
        # mcp_scope at routing time above — branch on routed_to instead of
        # assuming every non-reference route went through the target_file
        # path (which used to make `gate mcp:<family>` exit here on ANY
        # finding).
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.factory import build_adapter_for_spec
        from mylonite.plugins._mcp.twins import plan_twins

        if routed_to == "mcp":
            # custom_spec/mcp_scope are set unconditionally in the mcp routing
            # branch above; BUNDLED_TARGETS is already resolvable as-is, and
            # target_registry.register_target() would raise trying to shadow
            # a bundled family — skip the custom route's registration step.
            if custom_spec is None:
                echo_err("internal: expected a resolved TargetSpec for mcp validate_fn")
                raise typer.Exit(code=EXIT_CONFIG)
            spec = custom_spec
            scope_for_factory = mcp_scope
        else:
            if tf is None:
                echo_err("internal: expected a loaded TargetFile for custom validate_fn")
                raise typer.Exit(code=EXIT_CONFIG)
            from mylonite.plugins._mcp.target_file import build_target_spec

            spec = custom_spec if custom_spec is not None else build_target_spec(tf)
            target_registry.clear_runtime_targets()
            target_registry.register_target(spec)
            scope_for_factory = tf.scope

        # Control-efficacy leg: a controllable finding (tagged in scan_fn, via the
        # SAME plan_twins) gets a guarded twin so the differential leg proves the
        # control is load-bearing (model held constant). Re-deriving the plan from
        # the tagged weakness — rather than re-deciding server_layer/rest/boundary
        # ad hoc here — is what makes it structurally impossible for this twin to
        # disagree with scan_fn's tag or with `validate`'s own plan for the same
        # spec+weakness (the bug this closes: the raw side here used to be a plain
        # adapter that never honoured control_env at all).
        #
        # `fast` (gate()'s own flag) is threaded through explicitly here too —
        # defense-in-depth. Today control_weakness is already None whenever
        # `fast` is set (scan_fn's own early-return under --fast never tags an
        # exploit), so plan_twins would short-circuit on `weakness is None`
        # regardless of what `fast` says — but hardcoding `fast=False` here
        # relied entirely on that separate, implicit cross-closure guarantee
        # holding forever. Passing the real value removes that coupling.
        control_weakness = generated.exploit.payload.metadata.get("synthetic_control") or None
        plan = plan_twins(spec, weakness=control_weakness, fast=fast)

        def _factory() -> Any:
            return build_adapter_for_spec(
                spec, scope=scope_for_factory, model=effective_planner_model, intent=plan.raw
            )

        guarded_factory: Any = None
        if plan.control_weakness is not None:

            def _guarded() -> Any:
                return build_adapter_for_spec(
                    spec,
                    scope=scope_for_factory,
                    model=effective_planner_model,
                    intent=plan.guarded,
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
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            target_adapter_factory=_factory,
            guarded_adapter_factory=guarded_factory,
            control_weakness=plan.control_weakness,
            guarded_is_server_layer=plan.guarded_is_server_layer,
            control_context=plan.control_context,
            randomize_exfil=randomize_exfil,
            progress_cb=lambda msg: echo_err(f"  … {msg}"),
        )
        with llm_scope(policy=effective_policy):
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

    from mylonite.scan._llm import llm_scope

    # Wraps the WHOLE pipeline (scan -> validate -> mitigation enrichment) so
    # the enrichment call (build_pr_body's --llm-enrich path, which run_gate
    # makes AFTER scan_fn/validate_fn's own narrower scopes have already
    # exited) still sees effective_policy — e.g. a configured api_base.
    # A2: thread the target's own system prompt through to build_pr_body so
    # localize() can pin a system-prompt finding to a line number (gate/
    # annotate.py's inline-annotation path was otherwise unreachable — it only
    # fires when a line is resolved). Safe to call unconditionally when tf is
    # set: build_target_spec(tf) above (custom_spec's construction) already
    # calls resolved_system_prompt(tf) once, so a second, pure/deterministic
    # call here cannot newly fail.
    gate_system_prompt: str | None = None
    if tf is not None:
        from mylonite.plugins._mcp.target_file import resolved_system_prompt

        gate_system_prompt = resolved_system_prompt(tf)

    # PR2: build the structural-recommendation engine's TargetContext for any
    # custom target (both the --target-file and mcp:<family> routes set
    # custom_spec — see its construction above). None for a reference target,
    # which keeps build_pr_body's output byte-identical to before PR2 (the
    # differential there is against the in-repo twin, not an operator target
    # to name tools/arguments FROM). Built with no live tool inventory: gate's
    # scan_fn and build_pr_body run in the same synchronous call, and
    # ScanResult.descriptor is only known after scan_fn returns internally to
    # run_gate — threading it through needs run_gate to resolve target_context
    # AFTER scan_fn, not before. W2/W3/W4 recommendations don't need a tool
    # inventory (effect_trace evidence covers them); W1 degrades to
    # medium-confidence, payload-derived evidence instead of high-confidence,
    # real-description evidence until that plumbing lands.
    gate_target_context = None
    if custom_spec is not None:
        from mylonite.plugins._mcp.target_file import target_context_for

        gate_target_context = target_context_for(
            custom_spec,
            target_id=(
                f"mcp:{tf.family}" if tf is not None else target if target is not None else "mcp:custom"
            ),
        )

    with llm_scope(policy=effective_policy):
        result = run_gate(
            out_dir=out,
            scan_fn=scan_fn,
            generate_fn=generate_fn,
            validate_fn=validate_fn,
            open_pr_fn=open_pr_fn,
            open_pr=open_pr,
            llm_enrich=llm_enrich,
            mitigation_model=effective_model,
            system_prompt=gate_system_prompt,
            target_context=gate_target_context,
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
    model: Annotated[str | None, typer.Option("--model")] = None,
    planner_model: Annotated[
        str | None,
        typer.Option(
            "--planner-model",
            help=(
                "Override the model that DRIVES the agent-under-test (the planner) "
                "while scoring controls. Defaults to --model. Same three-role split "
                "as `scan`/`gate`/`validate`."
            ),
        ),
    ] = None,
    customiser_model: Annotated[
        str | None,
        typer.Option(
            "--customiser-model",
            help=("Override the model that CRAFTS/REFINES attack payloads. Defaults to --model."),
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help=("Override the model that JUDGES whether an attack landed. Defaults to --model."),
        ),
    ] = None,
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config (target_file / authorize / "
                "provider / model / the role models). Auto-discovered from "
                "./mylonite.yaml when present; an explicit flag always wins."
            ),
        ),
    ] = None,
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
    from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.plugins._mcp.twins import boundary_control_for
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

    # T14/H3: mylonite.yaml auto-discovery + role-model overrides, mirroring
    # scan/gate/validate.
    _config_path, rc = _discover_run_config(run_config_path, command="ablate")
    env_rc = _env_run_config_or_exit()
    # No --provider CLI flag any more (removed 0.7.10, T13's deprecated
    # alias). `provider` can still arrive via mylonite.yaml's `provider:` key
    # or MYLONITE_PROVIDER below -- both remain (separately deprecated, but
    # not removed) sources _resolve_model_ref still warns on.
    provider: str | None = None
    if rc is not None:
        target_file = target_file or rc.target_file
        authorize = authorize or rc.authorize
        provider = provider or rc.provider
        model = model or rc.model
        planner_model = planner_model or rc.planner_model
        customiser_model = customiser_model or rc.customiser_model
        judge_model = judge_model or rc.judge_model
    provider = provider or env_rc.provider
    model = model or env_rc.model
    planner_model = planner_model or env_rc.planner_model
    customiser_model = customiser_model or env_rc.customiser_model
    judge_model = judge_model or env_rc.judge_model
    effective_policy = _resolve_llm_policy(rc, env_rc)

    if target_file is None:
        echo_err("ablate requires --target-file (the app whose controls you want to score).")
        raise typer.Exit(code=EXIT_CONFIG)
    if not authorize:
        echo_err("--authorize is required to ablate a custom target. See SECURITY.md.")
        raise typer.Exit(code=EXIT_CONFIG)
    if iterations < 1:
        echo_err("--iterations must be >= 1.")
        raise typer.Exit(code=EXIT_CONFIG)

    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    def _resolve_ablate_role_model(override: str | None) -> str:
        if not override:
            return effective_model
        _validate_model_string(override)
        return _parse_model_ref_or_exit(override, provider).raw

    effective_planner_model = _resolve_ablate_role_model(planner_model)
    effective_customiser_model = _resolve_ablate_role_model(customiser_model)
    effective_judge_model = _resolve_ablate_role_model(judge_model)

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

    # T14/H3: the "no default provider, fail loudly" invariant, enforced
    # BEFORE any adapter/subprocess/engine work starts -- AFTER the authorize
    # check above (DCR-0008/one-gate: authorization gates every live-driving
    # action, even one this static).
    _require_llm_configured_or_exit(
        effective_planner_model,
        effective_customiser_model,
        effective_judge_model,
        provider=provider,
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
        # Builds through the same build_adapter_for_spec/LaunchIntent chokepoint
        # plan_twins-routed callers use (T10), and boundary_control_for is the
        # exact ControlConfig-aware factory plan_twins itself uses for the
        # single-weakness case. WHICH controls to disable/apply is deliberately
        # ablate's own decision (see twins.py's module docstring): it toggles the
        # FULL requested control set against each other (N-ary), not a single
        # weakness in isolation — a different question from plan_twins'.
        if server_layer:
            # ``applied`` = controls currently ON. The raw side (applied=()) turns
            # them all OFF; the "only C" side leaves only C on. Translate to the
            # complement and disable those server-layer guards via the launch env.
            disable = tuple(c for c in usable if c not in applied)
            intent = LaunchIntent(disable_controls=disable)
        else:
            intent = LaunchIntent(
                boundary_controls=tuple(boundary_control_for(spec, w) for w in applied)
            )
        adapter = build_adapter_for_spec(
            spec, scope=tf.scope, model=effective_planner_model, intent=intent
        )
        return scan_target_fires(
            adapter,
            pattern_id,
            provider=effective_provider,
            model=effective_planner_model,
            customiser_model=effective_customiser_model,
            judge_model=effective_judge_model,
            on_outcome=observed_outcomes.append,
        )

    from mylonite.scan._llm import llm_scope

    try:
        with llm_scope(policy=effective_policy):
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
