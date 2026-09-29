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

from collections.abc import Collection
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
        spec = target_registry.resolve_target(family, scope)
    except (target_registry.InvalidTargetScope, target_registry.UnknownTargetFamily) as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc

    # #184: a bundled spec (currently only `github`) may declare an extra_env
    # entry as a ${VAR} reference into the parent shell -- resolve it now,
    # before any subprocess is spawned, so a missing credential fails once
    # with a named message instead of a deep async describe()/spawn failure.
    from mylonite.plugins._mcp.target_file import expand_env_block

    try:
        expand_env_block(dict(spec.extra_env), subject=f"the bundled mcp:{family} target")
    except ValueError as exc:
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


def refuse_uncoverable_weakness_classes(
    target_file: Any,
    adapter: Any,
    *,
    allow_no_seed_arm: bool = False,
    dry_run: bool = False,
    timeout_s: float | None = None,
    added_by_flag: Collection[str] = (),
    command: str = "scan",
) -> None:
    """Pre-flight refusal (#181b): before any LLM call, refuse a scan/gate
    of a custom target whose declared ``weakness_classes`` include one this
    target's introspected tool surface cannot cover AT ALL — i.e. would
    produce ZERO attempts, never any (honest NOT TESTED) attempt at all.

    ``allow_no_seed_arm=True`` (the operator passed ``--allow-no-seed-arm``,
    accepting ``target_file.validate_for_scan``'s offer to run anyway) exempts
    the indirect-injection-only classes (W2) from THIS refusal too: the
    operator already explicitly opted into running those seeds uncovered
    rather than being blocked, and this must not silently re-impose the exact
    block they opted out of. Any OTHER uncoverable class (e.g. W3/W4 for an
    unrelated reason) still refuses.

    ``dry_run=True`` downgrades the refusal to a warning, exactly like
    ``validate_for_scan``'s own dry-run downgrade: a dry run only enumerates
    seeds (no clean/finding verdict to mislead), so it stays informative
    rather than blocking.

    Fails closed: when ``describe()`` raises or runs past ``timeout_s``, the
    coverability of the declared classes is unknown, so a real run is refused
    with a named message rather than started on the hope that every class can
    run. ``timeout_s`` defaults to 20 seconds, or the target's own
    ``timeout_s`` when that is larger. ``added_by_flag`` names classes that came from ``--weakness-class``
    rather than the file, so the fix points at the flag. ``command="gate"``
    adds the pointer to ``scan``'s seed_arm auto-wire, which gate lacks.

    A no-op when the target declares no ``weakness_classes`` at all (the
    legacy family-mapping targets are unaffected).
    """
    if not getattr(target_file, "weakness_classes", None):
        return
    import asyncio

    from mylonite.scan.seeds import seed_coverage

    if timeout_s is None:
        timeout_s = max(20.0, getattr(target_file, "timeout_s", None) or 0)
    level = "warning" if dry_run else "error"
    try:
        descriptor = asyncio.run(asyncio.wait_for(adapter.describe(), timeout=timeout_s))
    except Exception as exc:
        if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
            what = f"within {timeout_s:g}s"
            fix = (
                "Re-run (a first npx/uvx download is cached after that), or raise "
                "timeout_s in the target file."
            )
        else:
            what = f"({type(exc).__name__})"
            fix = (
                "Check that the target file's command and args start the server and "
                "that it lists its tools, then re-run."
            )
        echo_err(
            f"{level}: could not describe the server {what} to check which declared "
            f"weakness classes can run. {fix}"
        )
        if not dry_run:
            raise typer.Exit(code=EXIT_CONFIG) from exc
        return
    uncoverable = seed_coverage(descriptor).uncoverable
    if allow_no_seed_arm:
        from mylonite.plugins._mcp.target_file import _INDIRECT_ONLY_WEAKNESS_CLASSES

        uncoverable = {
            w: reason
            for w, reason in uncoverable.items()
            if w not in _INDIRECT_ONLY_WEAKNESS_CLASSES
        }
    if not uncoverable:
        return
    echo_err(
        f"{level}: this target declares weakness class(es) its tool surface cannot cover "
        "at all (every attempt for them would never run):"
    )
    for weakness, reason in sorted(uncoverable.items()):
        if weakness in added_by_flag:
            reason = reason.replace(
                f"remove {weakness} from weakness_classes",
                f"{weakness} was added by --weakness-class; drop it from the flag",
            )
        echo_err(f"  {weakness}: {reason}")
    if (
        command == "gate"
        and "W2" in uncoverable
        and getattr(target_file, "seed_arm", None) is None
        and getattr(target_file, "transport", None) != "rest"
    ):
        echo_err(
            "  gate does not auto-wire a seed_arm; scan does. Run `mylonite scan "
            "--target-file <this file> --authorize <family>` first. When it finds a "
            "store->recall pair it writes the wired target to "
            ".mylonite/scans/<timestamp>/target.yaml; pass that file to gate's --target-file."
        )
    if not dry_run:
        raise typer.Exit(code=EXIT_CONFIG)
