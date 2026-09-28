"""CLI target routing: turn a ``mylonite`` CLI target string/flags into a
constructed adapter, degrading unroutable input to a friendly
``typer.Exit(EXIT_CONFIG)`` instead of a raw traceback.

Sits next to ``mylonite.plugins.registry`` (the entry-point plugin registry)
as the CLI-facing layer on top of it: this module is where a target STRING
(``reference:vulnerable``, ``mcp:fetch:label``, ``mcp:custom`` + a loaded
``TargetFile``) becomes an actual adapter instance, via the reference
adapters, the bundled MCP registry, or the custom-target factory.

Moved out of ``cli.py`` (#91 thin-shell refactor) verbatim — ``mylonite.cli``
imports these back and calls them from ``scan``/``validate``/``gate``/
``ablate``/``check``, so a single implementation backs every command's
target routing.
"""

from __future__ import annotations

from typing import Any

import typer

from mylonite._cli_io import echo_err
from mylonite.exit_codes import EXIT_CONFIG


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
