"""Transport-aware MCP adapter factory.

A single chokepoint that resolves a target's ``transport`` and returns the right
adapter — ``MCPStdioAdapter`` (subprocess) or ``MCPRemoteAdapter`` (SSE/HTTP).
Both share :class:`MCPSessionAdapterBase`'s constructor, so callers pass the same
kwargs regardless of transport (the remote adapter ignores stdio-only knobs such
as ``launch_env``/``launch_command``/``launch_args``).

Imports of the concrete adapters are deferred to call time so that tests which
``monkeypatch.setattr(stdio_adapter, "MCPStdioAdapter", ...)`` still take effect.
"""

from __future__ import annotations

from typing import Any

from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp._session_adapter import MCPSessionAdapterBase


def build_mcp_adapter(*, family: str, scope: str | None, **kwargs: Any) -> MCPSessionAdapterBase:
    """Return the adapter matching ``family``'s declared transport.

    The target must already be registered (bundled or via ``register_target``) —
    the same precondition the adapter constructors have, since they resolve the
    spec too.
    """
    spec = target_registry.resolve_target(family, scope)
    if getattr(spec, "transport", "stdio") in ("sse", "http"):
        from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter

        return MCPRemoteAdapter(family=family, scope=scope, **kwargs)
    from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter

    return MCPStdioAdapter(family=family, scope=scope, **kwargs)
