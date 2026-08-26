"""Transport-aware target adapter factory.

A single chokepoint that resolves a target's ``transport`` and returns the right
adapter — ``MCPStdioAdapter`` (subprocess), ``MCPRemoteAdapter`` (SSE/HTTP-MCP),
or ``HTTPAgentAdapter`` (a plain HTTP agent, ``transport: rest``). The MCP
adapters share :class:`MCPSessionAdapterBase`'s constructor; the HTTP adapter
takes the same ``family``/``scope`` and ignores MCP-only kwargs — so every caller
passes the same kwargs regardless of transport. All three satisfy
:class:`AsyncTargetAdapterBase`.

Imports of the concrete adapters are deferred to call time so that tests which
``monkeypatch.setattr(stdio_adapter, "MCPStdioAdapter", ...)`` still take effect.

Two entry points, two layers
-----------------------------
:func:`build_mcp_adapter` is the original, low-level entry point: it takes a
bare ``family`` string plus raw constructor kwargs (``controls``, ``launch_env``,
``launch_command``, ``launch_args``, ...) and passes them straight through. A
caller wanting a target's deliberately-unguarded twin must remember to compute
and pass the launch triple itself (e.g. ``launch_env=spec.launch_env(vulnerable=
True)``) — nothing stops a caller from forgetting, which is exactly what let
``testkit``'s adapter construction drift from the real scan path (it never
threaded the launch triple at all).

:func:`build_adapter_for_spec` is the safer entry point layered on top: it takes
an already-resolved :class:`~mylonite.plugins._mcp.target_registry.TargetSpec`
plus a :class:`LaunchIntent` describing *what kind* of twin is wanted
(vulnerable / server-layer-disabled / boundary-guarded / input-framed), and
ALWAYS recomputes the launch triple from ``spec`` + ``intent`` itself — a caller
cannot pass a raw ``launch_env`` and cannot skip it. New callers (and anything
that needs the honesty guarantee that the launch triple was actually applied)
should prefer this one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mylonite.contracts.target_adapter import AsyncTargetAdapterBase
from mylonite.plugins._mcp import target_registry
from mylonite.scan.control_shim import BoundaryControl
from mylonite.scan.llm_types import CompletionFn


def build_mcp_adapter(*, family: str, scope: str | None, **kwargs: Any) -> AsyncTargetAdapterBase:
    """Return the adapter matching ``family``'s declared transport.

    The target must already be registered (bundled or via ``register_target``) —
    the same precondition the adapter constructors have, since they resolve the
    spec too.

    Low-level: ``kwargs`` is passed straight through to the concrete adapter's
    constructor, so the caller is responsible for computing anything
    transport/launch-specific itself (e.g. ``launch_env=spec.launch_env(...)``).
    Prefer :func:`build_adapter_for_spec` for a call shape that cannot skip the
    launch triple.
    """
    spec = target_registry.resolve_target(family, scope)
    transport = getattr(spec, "transport", "stdio")
    if transport == "rest":
        from mylonite.plugins._http.http_adapter import HTTPAgentAdapter

        return HTTPAgentAdapter(family=family, scope=scope, **kwargs)
    if transport in ("sse", "http"):
        from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter

        return MCPRemoteAdapter(family=family, scope=scope, **kwargs)
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter

    return MCPStdioAdapter(family=family, scope=scope, **kwargs)


@dataclass(frozen=True)
class LaunchIntent:
    """What kind of twin :func:`build_adapter_for_spec` should build.

    Every field defaults to "the plain, real target" — constructing with no
    arguments (``LaunchIntent()``) is byte-for-byte today's default launch.

    ``vulnerable``:
        Launch the target's declared ``vulnerable_launch`` override (its
        deliberately-unguarded variant) instead of the default launch. N/A for
        a target with no ``vulnerable_launch`` declared (falls back to the
        default launch, unchanged).
    ``disable_controls``:
        Weakness classes whose SERVER-LAYER guard should be toggled off via
        ``TargetSpec.control_env`` (e.g. ablation's "only control C is on" leg
        disables every OTHER declared control). Independent of ``vulnerable``
        — both may be combined.
    ``boundary_controls``:
        ADAPTER-BOUNDARY controls (see ``mylonite.scan.control_shim``) that
        synthesize a guarded view for a target with no server-layer twin.
        Ignored by the HTTP (``rest``) adapter, which has no tool-call
        boundary to shim.
    ``input_frame``:
        For a ``rest``-transport (plain HTTP agent) target only: wrap each
        payload in the input data-framing ("spotlighting") guard so the
        control-efficacy leg can measure whether that black-box defence is
        load-bearing. Ignored by the MCP adapters.
    """

    vulnerable: bool = False
    disable_controls: tuple[str, ...] = ()
    boundary_controls: tuple[BoundaryControl, ...] = ()
    input_frame: bool = False


def build_adapter_for_spec(
    spec: target_registry.TargetSpec,
    *,
    scope: str | None,
    model: str,
    intent: LaunchIntent | None = None,
    completion_fn: CompletionFn | None = None,
) -> AsyncTargetAdapterBase:
    """Build the transport-matched adapter for an already-resolved ``spec``.

    Dispatches on ``spec.transport`` exactly like :func:`build_mcp_adapter`, but
    — because it takes a :class:`~mylonite.plugins._mcp.target_registry.TargetSpec`
    plus a :class:`LaunchIntent` rather than raw constructor kwargs — it is
    structurally impossible for a caller to skip the launch triple
    (``launch_command``/``launch_args``/``launch_env``): for every non-``rest``
    transport this function ALWAYS recomputes it from ``spec`` + ``intent``, it
    is never accepted from the caller. This is what closes the bug class that
    let ``testkit``'s adapter construction drift from this real scan path (it
    constructed an ``MCPStdioAdapter`` directly and never threaded the launch
    triple at all — so a target's ``vulnerable_launch``/``control_env`` could
    never actually take effect there).
    """
    resolved_intent = intent if intent is not None else LaunchIntent()
    boundary_controls = list(resolved_intent.boundary_controls) or None
    transport = spec.transport

    if transport == "rest":
        from mylonite.plugins._http.http_adapter import HTTPAgentAdapter

        return HTTPAgentAdapter(
            family=spec.family,
            scope=scope,
            input_frame=resolved_intent.input_frame,
            model=model,
            completion_fn=completion_fn,
            controls=boundary_controls,
        )

    # Every non-rest transport shares MCPSessionAdapterBase's constructor. The
    # launch triple is recomputed HERE, from spec + intent — never taken from
    # the caller — so a caller cannot construct an adapter that silently skips
    # vulnerable_launch / control_env (see the docstring above).
    launch_env = spec.launch_env(
        vulnerable=resolved_intent.vulnerable,
        disable_controls=resolved_intent.disable_controls,
    )
    launch_command = spec.launch_command(vulnerable=resolved_intent.vulnerable)
    launch_args = spec.launch_args(scope, vulnerable=resolved_intent.vulnerable)

    if transport in ("sse", "http"):
        from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter

        return MCPRemoteAdapter(
            family=spec.family,
            scope=scope,
            model=model,
            completion_fn=completion_fn,
            controls=boundary_controls,
            launch_env=launch_env,
            launch_command=launch_command,
            launch_args=launch_args,
        )

    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter

    return MCPStdioAdapter(
        family=spec.family,
        scope=scope,
        model=model,
        completion_fn=completion_fn,
        controls=boundary_controls,
        launch_env=launch_env,
        launch_command=launch_command,
        launch_args=launch_args,
    )
