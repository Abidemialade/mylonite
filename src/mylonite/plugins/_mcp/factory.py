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
"""

from __future__ import annotations

from typing import Any

from mylonite.contracts.target_adapter import AsyncTargetAdapterBase
from mylonite.plugins._mcp import target_registry


def build_mcp_adapter(*, family: str, scope: str | None, **kwargs: Any) -> AsyncTargetAdapterBase:
    """Return the adapter matching ``family``'s declared transport.

    The target must already be registered (bundled or via ``register_target``) —
    the same precondition the adapter constructors have, since they resolve the
    spec too.
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
