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
* ``mylonite ablate`` — hidden/experimental; needs ``MYLONITE_EXPERIMENTAL=1``.
* ``mylonite version`` — print the installed version.

See the documentation site for guides and the full reference.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, NoReturn, TypeVar

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import (
    _exit_if_missing_target_file,
    console_print,
    echo,
    echo_err,
    echo_exc,
    missing_target_file_message,
)
from mylonite._experimental import hidden_command as _hidden_experimental_command
from mylonite.commands.check import check
from mylonite.commands.llm_ceiling import CeilingGuardGroup, apply_request_ceiling
from mylonite.exit_codes import (
    EXIT_BUDGET,
    EXIT_CONFIG,
    EXIT_NOT_KEPT,
    EXIT_PR_FAILED,
    EXIT_PROVIDER,
    EXIT_SUCCESS,
)
from mylonite.exit_codes import (
    EXIT_FINDINGS as EXIT_FINDINGS,  # re-export (tests import from cli)
)
from mylonite.gate.wiring import (
    _post_gate_annotations as _post_gate_annotations,  # re-export (tests import from cli)
)
from mylonite.gate.wiring import (
    budget_hint,
    generate_fn,
    make_open_pr_fn,
    make_scan_fn,
    make_validate_fn,
    resolve_gate_out_dir_or_exit,
    validation_cost_note,
)
from mylonite.generate.wiring import (
    _dispatch_emit as _dispatch_emit,  # re-export (tests import from cli)
)
from mylonite.generate.wiring import (
    _emit_generated_test,
    _map_compliance,
    _resolve_exploit_paths,
    _slugify_pattern,
    _tag_control_for_generate,
)
from mylonite.layout import Layout, resolve_layout
from mylonite.plugins._mcp.scaffold import (
    _relative_sqlite_env_keys as _relative_sqlite_env_keys,  # re-export (tests import from cli)
)
from mylonite.plugins._mcp.scaffold import (
    _scaffold_rest_target_file,
    _scaffold_target_file,
    _target_file_from_flags,
)
from mylonite.plugins.cli_targets import (
    _build_adapter_for_custom,
    _build_adapter_for_mcp,
    _build_adapter_for_reference,
    _enforce_custom_authorize,
    _parse_mcp_target,
)
from mylonite.report.render import _render_ablation_matrix, _render_validation_report
from mylonite.scan.assembly import (
    build_scan_engine,
    load_attack_modules,
    no_usable_modules_message,
    select_attack_modules,
)
from mylonite.scan.preflight import (
    DEFAULT_ITERATION_TIMEOUT_S as _DEFAULT_ITERATION_TIMEOUT_S,  # validate --iteration-timeout
)
from mylonite.scan.preflight import PreflightFailure as _PreflightFailure
from mylonite.scan.preflight import preflight_failure_message, unreachable_hint
from mylonite.scan.preflight import provider_preflight as _provider_preflight
from mylonite.scan.preflight import provider_preflight_direct as _provider_preflight_direct
from mylonite.scan.providers import LOCAL_MODEL_HINT as _LOCAL_MODEL_HINT
from mylonite.scan.providers import preflight_model_or_exit
from mylonite.scan.providers import (
    require_llm_configured_or_exit as _require_llm_configured_or_exit,
)
from mylonite.scan.tool_roles import _classify_tools as _classify_tools  # re-export (tests)
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
        "`mylonite scan reference:vulnerable` -- run the attack suite against a target.\n\n"
        "`mylonite scan --command python --arg server.py --scaffold app.yaml` -- "
        "scaffold a target.yaml.\n\n"
        "`mylonite gate --target-file app.yaml --authorize custom --open-pr` -- scan to a gating PR.\n\n"
        "Docs: https://abidemialade.github.io/mylonite/ -- "
        "run 'mylonite COMMAND --help' for any command."
    ),
    add_completion=False,
    no_args_is_help=True,
    cls=CeilingGuardGroup,
)

# Exit codes: defined once in mylonite.exit_codes (imported at the top of this
# module and re-exported), so `from mylonite.cli import EXIT_SUCCESS` still works.

#: The built-in --max-llm-calls default. A Typer option default of ``50`` is
#: indistinguishable from an explicit ``--max-llm-calls 50`` — comparing the
#: resolved value against this literal (``if max_llm_calls == 50``) is exactly
#: the DCR-0004/0012/0015 bug. The option default is ``None`` (see scan()/
#: gate()); this constant is the actual fallback, applied via
#: :func:`_resolve_option`, and is also what ``--help`` displays via
#: ``show_default``.
_DEFAULT_MAX_LLM_CALLS = 50

#: #186: floor for the seed_arm auto-wire describe() probe (below). A
#: first-run npx/uvx server download can genuinely take this long, so a
#: timeout here gets its OWN diagnosis instead of falling through to "add a
#: seed_arm".
_AUTOWIRE_DESCRIBE_TIMEOUT_S: Final = 20.0


def _autowire_budget_s(tf_timeout_s: float | None) -> float:
    """The describe() budget for the seed_arm auto-wire probe and the
    uncoverable-class refusal: at least ``_AUTOWIRE_DESCRIBE_TIMEOUT_S`` even
    when a target file's own ``timeout_s`` is smaller (#186) -- a first-run
    npx/uvx download needs that floor regardless of what the operator set for
    the (larger, multi-turn) session timeout generally."""
    return max(_AUTOWIRE_DESCRIBE_TIMEOUT_S, tf_timeout_s or 0)


def _calibrate_custom_target_now(adapter: Any) -> None:
    """Calibrate the effect probe with real writes, once --authorize matched."""
    from mylonite.plugins._mcp.calibration import calibrate_custom_target

    asyncio.run(calibrate_custom_target(adapter, authorized=True))


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

    Rich renders the scan/report tables with non-ASCII glyphs (✓ ✗ ⚠ —). On a
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
    """S4: a clear note on Python 3.15+, which litellm (capped <3.15) rejects."""
    if sys.version_info >= (3, 15):
        echo_err(
            "note: Mylonite supports Python 3.11-3.14. litellm caps Python below "
            "3.15, so live LLM calls may fail to import on this interpreter - use a "
            "3.11-3.14 virtualenv for scan/validate."
        )


def _mylonite_env_var_names() -> frozenset[str]:
    """The ``MYLONITE_*`` env vars this tool actually reads — a closed allowlist.

    Derived from :class:`~mylonite.config._EnvRunConfig`, the typed settings
    object that DEFINES which flat ``MYLONITE_*`` vars mean anything, so the
    env-file loader and the consumer cannot drift apart. ``--env-file`` used to
    reject all of them, including ``MYLONITE_MODEL`` — which ``.env.example``
    itself marks required — so an operator following the project's own example
    file was told their variables were unrecognised.

    Deliberately NOT a ``MYLONITE_*`` prefix match. ``MYLONITE_API_BASE`` was
    the SSRF / key-exfiltration vector in DCR-0002 (0.7.9); a prefix rule would
    admit every future network-reaching variable automatically. Membership here
    only means "this name is loadable" — ``api_base``'s own hard validation
    (``validate_api_base``, which rejects a credentialed value) still applies at
    the point of use.
    """
    from mylonite.config import _EnvRunConfig

    return frozenset(f"MYLONITE_{name.upper()}" for name in _EnvRunConfig.model_fields)


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

    def _recognised(key: str) -> bool:
        return looks_like_provider_env_var(key) or key in _mylonite_env_var_names()

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
        if not _recognised(key):
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
    max_llm_requests: Annotated[
        int | None,
        typer.Option(
            "--max-llm-requests",
            min=1,
            help=(
                "Hard ceiling on LLM requests for this whole run, retries included "
                "(also MYLONITE_MAX_LLM_REQUESTS). Hitting it stops the run: exit 3, "
                "NOT TESTED. Default: no ceiling."
            ),
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
    apply_request_ceiling(max_llm_requests)


@app.command()
def version() -> None:
    """Print the installed Mylonite version."""
    echo(__version__)


@app.command()
def plugins() -> None:
    """List installed extension plugins across all five contract groups.

    Discovers every registered plugin via its PyPI entry point, which also runs
    the contract-version compatibility check (a major mismatch is refused here
    rather than failing silently mid-run). Attack modules are additionally *run*
    by ``scan``/``gate``; for the target-adapter, test-generator, validator and
    compliance-mapper contracts Mylonite uses its bundled reference
    implementation, and selecting a third-party one for those is not yet exposed
    on the CLI (see docs/plugin-authoring.md).
    """
    from mylonite.plugins.registry import describe_all

    # `describe_all`, not `discover_all`: listing what is installed does not
    # require constructing it. Three of the target adapters Mylonite itself
    # ships take a required argument (they are built by the target-file
    # factory for a named server family), so constructing them here reported
    # half the product's own adapters as broken on a clean install. The
    # contract-version compatibility check still runs, and reports per plugin.
    described = describe_all()

    incompatible = False
    for group, infos in described.items():
        echo(f"{group}:")
        if not infos:
            echo("  (none registered)")
            continue
        for info in infos:
            # Reported inline rather than aborting the listing: an incompatible or
            # broken plugin is exactly when the user needs to see the rest.
            incompatible = incompatible or bool(info.incompatible)
            echo(f"  - {info.class_name} (contract {info.contract_version}){info.listing_suffix()}")

    if incompatible:
        echo_err(
            "one or more registered plugins declare a contract version this "
            "Mylonite cannot load; they are listed above and will be skipped at "
            "run time. Upgrade the plugin, or Mylonite, to match."
        )
        raise typer.Exit(code=EXIT_CONFIG)


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
    exists on any command). This warning still fires for the two remaining
    ways to set a bare ``provider``: a
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


def _resolve_role_model(override: str | None, *, effective_model: str, provider: str | None) -> str:
    """Role-separated model resolution shared by ``scan``/``validate``/``gate``/
    ``ablate``: each of a command's ``--planner-model``/``--customiser-model``/
    ``--judge-model`` overrides defaults to the command's own base model.

    Validates + resolves any explicit override through ``ModelRef`` exactly
    like ``--model`` — it drives the identical LiteLLM call path, so an
    unroutable override must reject at CLI-argument time too, not just fail
    later mid-scan. ``.provider`` is discarded: a role override doesn't get
    its own env-var check, only the base model's provider feeds
    ScanConfig/env lookups.

    Was four textually-identical nested closures (one per command, each
    closing over that command's own ``effective_model``/``provider`` locals)
    before this dedup; ``effective_model`` and ``provider`` are now explicit
    keyword parameters instead.
    """
    if not override:
        return effective_model
    _validate_model_string(override)
    return _parse_model_ref_or_exit(override, provider).raw


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


def _exit_if_missing_kitchen_sink(exc: BaseException) -> None:
    """Map a missing reference target to a friendly EXIT_CONFIG, else return.

    The deliberately-vulnerable reference target is a separate package (not a
    base dependency): PyPI users get it with ``pip install mcp-kitchen-sink``;
    an editable checkout needs
    ``pip install -e ./reference_targets/mcp_kitchen_sink``. Without it,
    ``scan reference:*`` / ``validate`` raise ``ModuleNotFoundError`` deep
    in the adapter. Translate that one cause into a clear message everywhere (instead
    of a raw traceback on the scan path); re-raise anything unrelated by returning.
    """
    if (getattr(exc, "name", "") or "").split(".")[0] == "mcp_kitchen_sink":
        echo_err(
            "the reference app target isn't installed (it's opt-in) — run "
            "`pip install mcp-kitchen-sink`, or from a checkout "
            "`pip install -e ./reference_targets/mcp_kitchen_sink`."
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _missing_authorize(
    msg: str, target_file: Path | None, *, inline_scope: str | None = None, inline_hint: str = ""
) -> NoReturn:
    """Report a missing ``--authorize`` for a custom target, naming the value it needs.

    Three cases:

    - ``target_file`` does not exist: there is nothing to derive a value from,
      so the fix is ``--scaffold`` (0.10.2), not a guessed value.
    - ``target_file`` exists and loads: the hint names the exact required
      value, via :func:`mylonite._authz.authorize_hint`.
    - no ``target_file`` at all (``mcp:custom`` given inline): derive the
      value the same way :func:`_target_file_from_flags` builds the spec that
      will later be checked — ``inline_scope`` (the ``--scope`` flag) if
      given, else the literal family name ``"custom"``. ``gate`` refuses this
      route outright, so it passes ``inline_hint`` (its refusal) instead.

    A target file that exists but fails to load (bad YAML, wrong shape) gets no
    hint: it is not missing (so not ``--scaffold``) and yields no value.
    """
    from mylonite._authz import authorize_fix, authorize_hint

    if target_file is not None:
        if not target_file.exists():
            echo_err(f"{msg} {missing_target_file_message(target_file)}")
            raise typer.Exit(code=EXIT_CONFIG)
        hint = authorize_hint(target_file)
    else:
        value = inline_scope.strip() if inline_scope and inline_scope.strip() else "custom"
        hint = inline_hint or authorize_fix(value)
    echo_err(f"{msg} {hint}" if hint else msg)
    raise typer.Exit(code=EXIT_CONFIG)


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite scan reference:vulnerable` -- attack the bundled vulnerable twin.\n\n"
        "`mylonite scan --command python --arg server.py --scaffold app.yaml --scope my-app`\n"
        "-- introspect a server and write a starter target.yaml (no LLM call, no attack).\n\n"
        "`mylonite scan --target-file app.yaml --authorize my-app` -- attack YOUR MCP app\n"
        "(--authorize equals the scope the scaffold wrote).\n\n"
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
            help=(
                "A weakness class to scope the scan to, e.g. W2/W4 (repeatable). A "
                "custom target (--target-file, or inline mcp:custom flags) ADDS it "
                "to weakness_classes; every other target (reference:*, a bundled "
                "mcp:<family>) FILTERS which seeds run."
            ),
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
            help="LLM call budget for this scan. Not a hard ceiling: each seed keeps "
            "a small floor, so the worst case is higher (see docs/ci-gating.md).",
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
            help=(
                "Must equal the target's scope, or its family when it declares no scope. "
                "Asserts you own the target; see SECURITY.md."
            ),
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
    if weakness_class:
        from mylonite.scan.weakness import validate_weakness_class_flag_or_exit

        validate_weakness_class_flag_or_exit(weakness_class)
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
    #
    # Haiku, matching `validate`/`gate`/`ablate`/`check` and the documented
    # default. `scan` was the sole outlier on Sonnet, which is roughly 3x the
    # token cost and -- because the default model is also the PLANNER, the agent
    # under test -- resists injection harder, so the same target yielded fewer
    # findings under `scan` than the published scorecard measured. A user
    # budgeting from the quickstart under-budgeted, and a weakness the
    # scorecard reports could go unreported on the very command meant to find it.
    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    # Role-separated models: each defaults to the base model. See
    # _resolve_role_model's docstring for what "resolve" means here.
    effective_planner_model = _resolve_role_model(
        planner_model, effective_model=effective_model, provider=provider
    )
    effective_customiser_model = _resolve_role_model(
        customiser_model, effective_model=effective_model, provider=provider
    )
    # Effective app purpose: the --purpose flag, else the target file's declared
    # purpose (resolved in the custom-target branch below). None for a reference
    # target unless the flag is set.
    effective_purpose = purpose
    effective_judge_model = _resolve_role_model(
        judge_model, effective_model=effective_model, provider=provider
    )

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

    from mylonite.scan.engine import ScanConfig

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
    refusal_tf: Any = None
    flag_added_classes: list[str] = []
    synth_covers_indirect = False
    if target_file is not None or target == "mcp:custom":
        # Custom-target on-ramp (both YAML and inline flags converge here).
        if not authorize:
            _missing_authorize(
                "--authorize is required for custom targets. See SECURITY.md.",
                target_file,
                inline_scope=scope,
            )
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:  # YAML / validation errors → exit 2
                _exit_if_missing_target_file(exc, target_file)
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
            # --weakness-class used to be a silent no-op alongside
            # --target-file (only the YAML's weakness_classes were honoured).
            # Merge the flag's classes into the file's, order-stable and deduped,
            # so a documented, accepted flag actually does something.
            if weakness_class:
                flag_added_classes = [w for w in weakness_class if w not in tf.weakness_classes]
                merged = list(tf.weakness_classes)
                for w in weakness_class:
                    if w not in merged:
                        merged.append(w)
                if merged != list(tf.weakness_classes):
                    tf = tf.model_copy(update={"weakness_classes": merged})
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
            flag_added_classes = list(weakness_class or [])
        from mylonite.plugins._mcp.target_file import (
            dump_target_file,
            effect_probe_warnings,
            needs_seed_arm_autowire,
            validate_for_scan,
        )
        from mylonite.plugins.cli_targets import autowire_seed_arm

        # The persisted target.yaml must describe the target that ACTUALLY ran.
        # Copying the source verbatim after the seed_arm auto-wire (or --purpose
        # overrides the target's declared purpose) would produce a scan dir whose
        # target.yaml is missing the seed_arm the findings depended on, contradicting
        # the adjacent "reproducible from the scan dir alone" guarantee
        # (DCR-0005/0016/0006).
        tf_mutated = False

        # seed_arm auto-wire: infer a seed_arm from the LIVE tool surface when a
        # W2 target omits one, so a real app needs near-zero config instead of
        # the hard block below. Skipped on --dry-run/--allow-no-seed-arm, and
        # for a rest (HTTP-agent) target (no tool surface to introspect or
        # plant into -- W2 rides in as direct prompt injection instead). See
        # cli_targets.autowire_seed_arm for the probe + inference logic itself.
        synth_covers_indirect = False
        if (
            tf.transport != "rest"
            and needs_seed_arm_autowire(tf)
            and not dry_run
            and not allow_no_seed_arm
        ):
            # #207: validate the model BEFORE this probe can launch the real
            # server -- a bad --model must not spawn a subprocess first.
            preflight_model_or_exit(effective_planner_model, api_base=effective_policy.api_base)
            tf, tf_mutated, synth_covers_indirect = autowire_seed_arm(
                tf,
                authorize,
                effective_planner_model,
                budget_s=_autowire_budget_s(tf.timeout_s),
            )

        # Blocking pre-flight (PR3): a target declaring an indirect-injection-only
        # weakness class with no seed_arm would silently skip those seeds and read
        # as clean. Block a REAL scan with a fix hint unless --allow-no-seed-arm is
        # set (or the auto-wire above found one). A --dry-run only enumerates seeds (no
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
        # ACTUALLY ran — a --purpose override, a seed_arm auto-wire, or an
        # inline mcp:custom target must all be reflected here (DCR-0005/0016/0006).
        custom_target_yaml = (
            target_file.read_text(encoding="utf-8")
            if target_file is not None and not tf_mutated
            else dump_target_file(tf)
        )
        adapter = _build_adapter_for_custom(tf, authorize, effective_planner_model)
        # #181b: the uncoverable-class refusal launches the server, so it runs
        # below, after the LLM key/model pre-flight (a bad model or missing key
        # must never spawn the target).
        refusal_tf = tf
        report_target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
    elif target is None:
        echo_err("no target given. Pass a target (e.g. reference:vulnerable) or --target-file.")
        raise typer.Exit(code=EXIT_CONFIG)
    elif target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, effective_planner_model)
        report_target_id = target
    elif target.startswith("mcp:"):
        if not authorize:
            from mylonite._authz import bundled_authorize_fix

            echo_err(
                f"--authorize is required for non-reference targets (got {target!r}). "
                f"See SECURITY.md. {bundled_authorize_fix(target)}"
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
        all_modules, module_load_failures = load_attack_modules()
    except Exception as exc:
        echo_exc("plugin discovery failed", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # Shipped families plus MYLONITE_ATTACK_MODULES opt-ins; the reference_example
    # stub (for plugin authors) stays out unless named. Load failures go to the engine.
    attack_modules = select_attack_modules(all_modules)
    if not attack_modules:
        echo_err(no_usable_modules_message(module_load_failures))
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
            dry_run_flag=True,
            api_base=effective_policy.api_base,
        )

    # #181b: a declared class this surface can never cover — refuse before any
    # LLM spend, and only after the pre-flight above so a bad model or a
    # missing key never launches the server. A no-op for non-custom targets.
    if refusal_tf is not None:
        from mylonite.plugins.cli_targets import refuse_uncoverable_weakness_classes

        refuse_uncoverable_weakness_classes(
            refusal_tf,
            adapter,
            allow_no_seed_arm=allow_no_seed_arm or synth_covers_indirect,
            dry_run=dry_run,
            added_by_flag=flag_added_classes,
            timeout_s=_autowire_budget_s(refusal_tf.timeout_s),
        )

    if refusal_tf is not None and not dry_run and refusal_tf.transport != "rest":
        _calibrate_custom_target_now(adapter)  # never under --dry-run
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

    engine = build_scan_engine(
        config,
        adapter,
        customiser_model=effective_customiser_model,
        judge_model=effective_judge_model,
        purpose=effective_purpose,
        attack_modules=attack_modules,
        module_load_failures=module_load_failures,
    )

    from mylonite.scan._llm import llm_scope
    from mylonite.scan.seeds import weakness_class_scope

    try:
        # T14: activates effective_policy (mylonite.yaml/env-resolved
        # LLMPolicy) for every LiteLLM call this run makes — the customiser,
        # judge, and (via LLMPlanner) the planner all read it through
        # scan._llm.active_policy(). asyncio.run() copies the current
        # contextvar context into the coroutine it schedules, so entering
        # this scope BEFORE asyncio.run (rather than inside ScanEngine.run,
        # which separately owns the budget-counter scope) is sufficient.
        # #205: weakness_class_scope is a no-op for a custom target (its own
        # declared weakness_classes branch is unaffected) -- only filters the
        # reference:*/bundled mcp:<family> fallback selection.
        with weakness_class_scope(weakness_class), llm_scope(policy=effective_policy):
            result = asyncio.run(engine.run())
    except (ModuleNotFoundError, ImportError) as exc:
        # `scan reference:*` lazily imports the bundled reference target inside the
        # adapter; on an editable checkout without it this surfaces here. Fail with
        # a friendly message, not a raw traceback.
        _exit_if_missing_kitchen_sink(exc)
        raise

    from mylonite._redaction import redact
    from mylonite._target_env import write_redacted_target

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
            write_redacted_target(scan_dir / "target.yaml", custom_target_yaml)
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

    outcome = ScanOutcome.from_report(result.report, abort_detail=result.abort_detail)
    if outcome.operator_message:
        echo_err(outcome.operator_message)
    raise typer.Exit(code=outcome.exit_code)


@app.command()
def demo(
    live: Annotated[
        bool,
        typer.Option("--live", help="Make real LLM calls instead of replaying recorded fixtures."),
    ] = False,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="LiteLLM provider. --live only; replay is pinned."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model. --live only; replay is pinned to the recorded one."),
    ] = None,
) -> None:
    """Run the zero-config reference-app playground: vulnerable vs guarded differential.

    Default is offline replay of recorded fixtures - no network, no API key,
    deterministic. `--live` makes real calls against the in-process reference
    agent (two variants, ~2 min). The recorded model is self-hosted, so a live
    run costs nothing but needs that model served locally; `--provider`/`--model`
    point it at a hosted one instead.

    Body lives in `mylonite.demo.cli_entry`, which documents the replay
    invariant that keeps this command independent of the environment.
    """
    from mylonite.demo.cli_entry import run_demo_command

    run_demo_command(live=live, provider=provider, model=model)


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
                "For a CUSTOM target: the target YAML you scanned. Usually not needed — "
                "generate auto-resolves target.yaml from the scan directory SCAN_PATH "
                "points at. Pass it explicitly when that file isn't there (a different "
                "--scans-dir, or an exploit copied elsewhere). Co-located next to the "
                "emitted test as target.yaml so the live test can re-drive your real app."
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
    CUSTOM target, the live test needs the target YAML co-located as
    ``target.yaml``: this auto-resolves from the scan directory when it's there,
    so ``--target-file`` is only needed to point at one that isn't. With
    ``--prove-control`` the emitted test asserts the control is load-bearing
    (``assert_control_holds``) rather than just that the target resists. Prints
    what to run next.
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
            _exit_if_missing_target_file(exc, target_file)
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
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file_and_warn
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
        tf = load_target_file_and_warn(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        _exit_if_missing_target_file(exc, target_file)
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
        planner_model or model,
        customiser_model or model,
        judge_model or model,
        provider=provider,
        api_base=policy.api_base if policy is not None else None,
    )

    # DCR-0008: fail fast on an unreachable provider with a distinct exit 4 —
    # otherwise the full N-iteration live loop against the REAL target would
    # just run to a misleading non-discriminating REJECTED. Always AFTER the
    # authorize check above: authorization gates every live-driving action.
    # The CUSTOM path uses a DIRECT LLM ping, not a reference scan, so it
    # does not require the deliberately-vulnerable mcp_kitchen_sink demo package
    # to be installed just to check "is my provider reachable".
    timeout_s, why = iteration_timeout_s or _DEFAULT_ITERATION_TIMEOUT_S, _PreflightFailure()
    reachable = _provider_preflight_direct(provider, model, timeout_s=timeout_s, failure=why)
    _exit_if_provider_unreachable(reachable, why, provider=provider, model=model)

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)

    # Calibrate the effect probe before it's trusted (--authorize matched above).
    if spec.transport != "rest":
        _calibrate_custom_target_now(build_adapter_for_spec(spec, scope=tf.scope, model=model))
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
            "control_env in your target.yaml (see docs/concepts.md).\n"
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


def _render_recommendation_panel(rec: Any, console: Console | None = None) -> None:
    """Render a structural recommendation (PR7) as a Rich table.

    Every attacker-influenced cell — a tool NAME, an argument VALUE, and a
    prescription HEADLINE (which interpolates evidence values directly, e.g.
    W3's "reached an off-allowlist destination (`<the attacker's URL>`)") —
    is redact()-ed AND rich_escape()'d before add_row. This is NOT redundant
    with console_print's own markup=False: that only helps a bare STRING
    renderable printed directly; a Table's cells parse Rich markup at
    construction time regardless of how the table is later printed (see
    console_print's own docstring, and _render_validation_report's identical
    handling of outcome.detail above) — so a value shaped like `[/bold]`
    would otherwise raise rich.errors.MarkupError, and a value containing a
    style tag could otherwise inject formatting into a terminal a developer
    is about to screenshot.
    """
    from mylonite._redaction import redact

    if console is None:
        console = Console()

    def _safe(text: str) -> str:
        return rich_escape(redact(text))

    header = Table.grid(padding=(0, 1))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("recommendation for:", _safe(rec.weakness_class))
    header.add_row("confidence:", _safe(f"{rec.confidence} ({rec.confidence_reason})"))
    header.add_row("proven:", _safe(f"{rec.proven} (layer: {rec.proven_layer})"))
    if rec.degraded:
        header.add_row("degraded:", _safe("; ".join(rec.degraded)))
    console_print(console, header)

    if rec.evidence:
        ev_table = Table(title="evidence", title_justify="left", show_lines=False)
        ev_table.add_column("tool", no_wrap=True)
        ev_table.add_column("argument", no_wrap=True)
        ev_table.add_column("value")
        ev_table.add_column("executed", no_wrap=True)
        for ev in rec.evidence:
            ev_table.add_row(
                _safe(ev.tool),
                _safe(ev.argument or "-"),
                _safe(ev.value or "-"),
                "yes" if ev.executed else "no",
            )
        console_print(console, ev_table)

    ctl_table = Table(title="recommended controls", title_justify="left", show_lines=True)
    ctl_table.add_column("tier", no_wrap=True)
    ctl_table.add_column("control")
    for p in rec.prescriptions:
        ctl_table.add_row(p.tier, _safe(p.headline))
    console_print(console, ctl_table)


def _exit_if_provider_unreachable(
    reachable: bool, failure: _PreflightFailure | None = None, *, provider: str, model: str
) -> None:
    """Shared by both `validate` branches so this message can't drift (#191 for rate limits)."""
    if reachable:
        return
    if (specific := preflight_failure_message(failure, provider=provider, model=model)) is not None:
        echo_err(specific)
        raise typer.Exit(code=EXIT_PROVIDER)
    echo_err(unreachable_hint(provider, model) + "\n" + _LOCAL_MODEL_HINT)
    raise typer.Exit(code=EXIT_PROVIDER)


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
                "(Haiku): ~5 iterations x 2 twins plus metamorphic re-drives; the "
                "LLM calls and tokens used are printed when it finishes. Needs a "
                "provider (ANTHROPIC_API_KEY)."
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
                "For a CUSTOM target: the same target YAML you scanned. Usually not "
                "needed — this auto-resolves target.yaml co-located with the test "
                "(written by `generate`); pass it explicitly only when that file "
                "isn't there. The validator re-drives the REAL target (N runs + "
                "multi-judge consensus + effect probe) instead of the bundled "
                "twin, so the test fails when YOUR app regresses."
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
                "Must equal the target's scope, or its family when it declares no scope. "
                "Asserts you own the target; see SECURITY.md. Not needed for a "
                "reference:* target."
            ),
        ),
    ] = None,
) -> None:
    """Run a generated test through the differential-oracle validator (LIVE).

    Runs LIVE by default: ~``iterations`` iterations x 2 twins against a real LLM
    (Haiku), plus the metamorphic re-drives, and needs a provider
    (ANTHROPIC_API_KEY). The LLM calls and tokens it used are printed when it
    finishes. Validates the ACTUAL committed test on disk (no
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

    effective_planner_model = _resolve_role_model(
        planner_model, effective_model=effective_model, provider=provider
    )
    effective_customiser_model = _resolve_role_model(
        customiser_model, effective_model=effective_model, provider=provider
    )
    effective_judge_model = _resolve_role_model(
        judge_model, effective_model=effective_model, provider=provider
    )

    test_path, exploit_path = _locate_generated(target)

    try:
        exploit = testkit.load_exploit(exploit_path)
    except (FileNotFoundError, ValueError) as exc:
        echo_exc(f"could not load exploit at {exploit_path}", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # The validator transitively imports mcp_kitchen_sink (via the reference
    # adapter / wiring). Map its absence to a friendly exit-2.
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

    from mylonite.scan._llm import usage_tally
    from mylonite.scan.artefacts import spend_summary

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
        spend_started = time.monotonic()
        with usage_tally() as spend_tally:
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
        from mylonite.plugins._reference.reference_validator import workload_message

        echo_err(workload_message(iterations, fast=fast))
        # T14/H3: cheap, no-network credential-presence pre-flight before the
        # real live _provider_preflight call just below (no authorize gate on
        # this branch -- the bundled reference twins are safe-by-construction).
        _require_llm_configured_or_exit(
            effective_planner_model,
            effective_customiser_model,
            effective_judge_model,
            provider=provider,
            api_base=effective_policy.api_base,
        )
        # Fail fast on an unreachable provider with a distinct exit 4 — otherwise
        # the full loop would just report a misleading non-discriminating result.
        why = _PreflightFailure()
        try:
            reachable = _provider_preflight(
                effective_provider, effective_model, timeout_s=iteration_timeout, failure=why
            )
        except (ModuleNotFoundError, ImportError) as exc:
            _exit_if_missing_kitchen_sink(exc)
            raise
        _exit_if_provider_unreachable(
            reachable, why, provider=effective_provider, model=effective_model
        )

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

        spend_started = time.monotonic()
        with llm_scope(policy=effective_policy), usage_tally() as spend_tally:
            report = validator.validate(
                generated,
                ReferenceVulnerableOracle().adapter(),
                ReferenceVulnerableOracle(),
            )

    # T2: stamp the model the differential was proven against, so the committed
    # regression is honest about which model version it gates (a fix can silently
    # re-emerge on a model upgrade — re-run `validate` with the new
    # `--planner-model` to check; see docs/model-upgrade.md).
    from mylonite.plugins._reference.reference_validator import validated_model_stamp

    _stamp = validated_model_stamp(
        effective_planner_model, effective_customiser_model, effective_judge_model
    )
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
    echo(spend_summary(spend_tally.spend(), time.monotonic() - spend_started))

    if report.kept:
        from mylonite._verdict import next_step_after_keep

        echo("")
        echo(next_step_after_keep(report))
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


def _target_context_for_artefact_dir(artefact_dir: Path) -> Any | None:
    """PR7: reconstruct a TargetContext from an already-completed run's saved
    directory, for `mylonite report` — the offline counterpart to gate's own
    live target_context wiring (PR2).

    Reads the co-located, REDACTED `target.yaml` (written by `scan`/`gate` for
    a custom target) purely as DATA — `build_target_spec` constructs a
    TargetSpec without launching anything, so redacted credential fields
    (env/headers replaced with `${VAR}` refs) are harmless: none of them
    factor into a TargetContext. Enriches with the `tool_surface.json`
    sidecar (PR7) when present. Returns `None` (never raises) for a reference
    target, a directory with no co-located target.yaml, or any load failure —
    every caller must degrade to the class-level fix, not crash `report`.
    """
    target_yaml = artefact_dir / "target.yaml"
    if not target_yaml.is_file():
        return None
    try:
        from mylonite.plugins._mcp.target_file import (
            build_target_spec,
            load_target_file,
            target_context_for,
        )
        from mylonite.scan.artefacts import read_tool_surface

        tf = load_target_file(target_yaml)
        spec = build_target_spec(tf)
        tools = read_tool_surface(artefact_dir) or ()
        target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
        return target_context_for(spec, target_id=target_id, tools=tools, framework=tf.framework)
    except Exception as exc:
        echo_exc(f"warning: could not reconstruct target context from {target_yaml}", exc)
        return None


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

    # PR7: reconstruct a TargetContext from this artefact dir's co-located
    # target.yaml + tool_surface.json sidecar (both optional — a reference
    # target, or a directory from before PR7, simply gets None here and every
    # consumer below degrades to the class-level fix, exactly as build_pr_body
    # already does for target=None).
    target_context = _target_context_for_artefact_dir(path.parent)

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
                if target_context is not None:
                    from mylonite.gate.recommend import recommend as _recommend

                    _render_recommendation_panel(
                        _recommend(dashboard_exploit, vreport, target=target_context),
                        console=console,
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
        from mylonite.contracts import ScanReport
        from mylonite.scan.artefacts import read_verdicts_calibration, render_summary
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

        result = ScanResult(sreport, [], calibration=read_verdicts_calibration(path.parent))
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
        if target_context is not None and dashboard_exploits:
            from mylonite.gate.recommend import recommend as _recommend

            for exploit in dashboard_exploits:
                _render_recommendation_panel(
                    _recommend(exploit, None, target=target_context), console=console
                )

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

            sarif.write_text(
                _json.dumps(to_sarif(findings, target=target_context), indent=2) + "\n",
                encoding="utf-8",
            )
            echo(f"Wrote SARIF (GitHub code scanning): {sarif}")
        if json_bundle is not None:
            from mylonite.report import to_bundle

            json_bundle.write_text(
                _json.dumps(to_bundle(findings, target=target_context), indent=2) + "\n",
                encoding="utf-8",
            )
            echo(f"Wrote JSON finding bundle: {json_bundle}")
    raise typer.Exit(code=exit_code)


@app.command(
    epilog=(
        "Examples:\n\n"
        "`mylonite gate reference:vulnerable` -- the full pipeline on the reference target.\n\n"
        "`mylonite scan --command python --arg server.py --scaffold app.yaml --scope my-app`\n"
        "-- write the target file first; its scope is the --authorize value below.\n\n"
        "`mylonite gate --target-file app.yaml --authorize my-app` -- gate YOUR app (writes the test).\n\n"
        "`mylonite gate --target-file app.yaml --authorize my-app --open-pr` -- also open the gating PR via gh."
    )
)
def gate(
    ctx: typer.Context,
    target: Annotated[
        str | None,
        typer.Argument(
            help=(
                "Target ID: 'reference:vulnerable' / 'reference:guarded' or a "
                "bundled 'mcp:<family>[:<scope>]'. For a custom target, omit this "
                "and pass --target-file. Non-reference targets require --authorize."
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
            help=(
                "Must equal the target's scope, or its family when it declares no scope. "
                "Asserts you own the target; see SECURITY.md."
            ),
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
            help="LLM call budget for the scan phase. Not a hard ceiling: each seed "
            "keeps a small floor, so the worst case is higher (see docs/ci-gating.md).",
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
            help=(
                "Scaffold .github/workflows/ gate + discovery templates into the "
                "repository. Off by default — this writes files you did not ask for."
            ),
        ),
    ] = False,
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
    from mylonite.gate import pr as pr_mod
    from mylonite.gate import run_gate

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

    # #203: anchor a relative --out at the repo root (scan_fn/open_pr_fn close over it).
    out = resolve_gate_out_dir_or_exit(out, open_pr=open_pr, workflows=workflows, pr_mod=pr_mod)

    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    # Role-separated models (T14, mirroring `scan`'s _resolve_role_model):
    # each defaults to the base model.
    effective_planner_model = _resolve_role_model(
        planner_model, effective_model=effective_model, provider=provider
    )
    effective_customiser_model = _resolve_role_model(
        customiser_model, effective_model=effective_model, provider=provider
    )
    effective_judge_model = _resolve_role_model(
        judge_model, effective_model=effective_model, provider=provider
    )

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
        # Custom-target on-ramp: a missing --authorize refuses the run first, as scan
        # does; the file is read only to print the required value in that refusal.
        gate_inline = (
            "gate --target-file <yaml> is the custom-target path; inline mcp:custom "
            "flags are not wired in `gate`. Pass a target YAML via --target-file."
        )
        if not authorize:
            _missing_authorize(
                "--authorize is required for custom targets. See SECURITY.md.",
                target_file,
                inline_hint=gate_inline,
            )
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

            try:
                tf = load_target_file(target_file)
            except Exception as exc:
                _exit_if_missing_target_file(exc, target_file)
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
            custom_spec = build_target_spec(tf)
        else:
            # mcp:custom with inline flags — not supported via gate (no --command etc.)
            echo_err(gate_inline)
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
            from mylonite._authz import bundled_authorize_fix

            echo_err(
                f"--authorize is required for non-reference targets (got {target!r}). "
                f"See SECURITY.md. {bundled_authorize_fix(target)}"
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
        api_base=effective_policy.api_base,
    )

    # DCR-0010: the actual adapter object is constructed here, only after the
    # LLM-configured check above has passed.
    adapter = adapter_factory()
    # #181b: same pre-flight refusal as `scan` — a no-op when `tf` is None.
    from mylonite.plugins.cli_targets import refuse_uncoverable_weakness_classes

    refuse_uncoverable_weakness_classes(
        tf,
        adapter,
        command="gate",
        timeout_s=_autowire_budget_s(tf.timeout_s) if tf is not None else None,
    )

    # --- collaborators injected into run_gate, built by the gate/wiring.py
    # factories (moved out of this command body in #91's thin-shell refactor;
    # each factory takes the values its closure used to capture as explicit
    # keyword parameters and returns the callable run_gate expects). ---

    scan_fn = make_scan_fn(
        target=target,
        tf=tf,
        custom_spec=custom_spec,
        effective_provider=effective_provider,
        effective_model=effective_model,
        effective_planner_model=effective_planner_model,
        planner_model=planner_model,
        effective_customiser_model=effective_customiser_model,
        customiser_model=customiser_model,
        effective_judge_model=effective_judge_model,
        judge_model=judge_model,
        max_llm_calls=max_llm_calls,
        adapter=adapter,
        purpose=purpose,
        fast=fast,
        is_reference=is_reference,
        prove_input_control=prove_input_control,
        effective_policy=effective_policy,
    )
    validate_fn = make_validate_fn(
        is_reference=is_reference,
        iterations=iterations,
        effective_provider=effective_provider,
        effective_model=effective_model,
        effective_planner_model=effective_planner_model,
        planner_model=planner_model,
        effective_customiser_model=effective_customiser_model,
        customiser_model=customiser_model,
        effective_judge_model=effective_judge_model,
        judge_model=judge_model,
        out=out,
        effective_policy=effective_policy,
        routed_to=routed_to,
        custom_spec=custom_spec,
        mcp_scope=mcp_scope,
        tf=tf,
        fast=fast,
        randomize_exfil=randomize_exfil,
    )
    open_pr_fn = make_open_pr_fn(
        runs_on=runs_on,
        workflows=workflows,
        target_file=target_file,
        pr_mod=pr_mod,
    )

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
                f"mcp:{tf.family}"
                if tf is not None
                else target
                if target is not None
                else "mcp:custom"
            ),
            framework=tf.framework if tf is not None else None,
        )

    from mylonite.scan._llm import BudgetExceededError, usage_tally
    from mylonite.scan.artefacts import spend_summary

    spend_started = time.monotonic()
    try:
        with llm_scope(policy=effective_policy), usage_tally() as spend_tally:
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
                budget_hint_text=budget_hint(routed_to, target_file),
                validation_cost_hint=validation_cost_note(
                    is_reference=is_reference, iterations=iterations
                ),
            )
    except BudgetExceededError as exc:
        # One decision, one exit code. Raised inside the validator this used to
        # escape uncaught and exit 1, while the same exhaustion seen first by
        # the engine exits EXIT_BUDGET. Both now report the same way.
        echo_err(f"\nerror: LLM call budget exhausted: {exc}")
        echo_err(budget_hint(routed_to, target_file))
        raise typer.Exit(code=EXIT_BUDGET) from exc
    except pr_mod.GatePrError as exc:
        # The git/gh step is the LAST thing gate does, so by the time it fails
        # the scan, generation and validation have all been paid for and their
        # artefacts are already on disk under --out. Report it as a named error
        # with its own exit code instead of a raw traceback, and point the
        # operator at the evidence they still have.
        echo_err(f"\nerror: the gate's git/gh step failed: {exc}")
        echo_err(
            f"The findings, the generated test and the validation report are "
            f"still in '{out}'. Nothing was lost; only the PR step failed."
        )
        raise typer.Exit(code=EXIT_PR_FAILED) from exc
    echo(f"gate {spend_summary(spend_tally.spend(), time.monotonic() - spend_started)}")
    raise typer.Exit(code=result.exit_code)


@_hidden_experimental_command(app, "ablate")
def ablate(
    target_file: Annotated[
        Path | None,
        typer.Option("--target-file", help="Custom-target YAML (required): the app to ablate."),
    ] = None,
    authorize: Annotated[
        str | None,
        typer.Option(
            "--authorize",
            help=(
                "Must equal the target's scope, or its family when it declares no scope. "
                "Asserts you own the target; see SECURITY.md."
            ),
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

    Without `control_env` declared on the target, this grades Mylonite's own
    boundary stand-in, not your safeguard -- declare `control_env` to grade yours.
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
        _missing_authorize(
            "--authorize is required to ablate a custom target. See SECURITY.md.", target_file
        )
    if iterations < 1:
        echo_err("--iterations must be >= 1.")
        raise typer.Exit(code=EXIT_CONFIG)

    base_model = model or "claude-haiku-4-5-20251001"
    _validate_model_string(base_model)
    ref = _resolve_model_ref(base_model, provider)
    effective_provider = ref.provider or "unknown"
    effective_model = ref.raw

    effective_planner_model = _resolve_role_model(
        planner_model, effective_model=effective_model, provider=provider
    )
    effective_customiser_model = _resolve_role_model(
        customiser_model, effective_model=effective_model, provider=provider
    )
    effective_judge_model = _resolve_role_model(
        judge_model, effective_model=effective_model, provider=provider
    )

    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception as exc:
        _exit_if_missing_target_file(exc, target_file)
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
        api_base=effective_policy.api_base,
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

    # Calibrate the effect probe before it's trusted (--authorize matched above).
    if spec.transport != "rest":
        _calibrate_custom_target_now(
            build_adapter_for_spec(spec, scope=tf.scope, model=effective_planner_model)
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
                # Attribution fix (0.10.4): a probed target's raw/guarded legs
                # share persistent state, so they must not race each other.
                sequential=spec.effect_probe is not None,
            )
    finally:
        target_registry.clear_runtime_targets()

    from mylonite._twin_fidelity import guarded_twin_layer

    # The matrix states whose control played the guarded side, and the claim a
    # load-bearing row earns, through the same single source as validate/SARIF.
    _render_ablation_matrix(results, guarded_layer=guarded_twin_layer(None, server_layer))
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


# `check`'s command body lives in `mylonite.commands.check` (#91/#197 follow-up,
# extracted to keep this composition root thin -- see tests/test_cli_size.py).
# Registered via a function call, not a decorator, because `commands/check.py`
# needs `mylonite.cli._discover_run_config`, imported lazily in the function body.
_hidden_experimental_command(app, "check")(check)
