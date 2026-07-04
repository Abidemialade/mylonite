"""MCP stdio transport ``TargetAdapter``.

Thin transport subclass of :class:`MCPSessionAdapterBase`: it supplies the stdio
session opener (``_open_mcp_session`` — spawns the MCP server as a subprocess and
drives it via ``stdio_client`` + ``ClientSession``) and the stdio-flavoured
descriptor strings. All of the load-bearing attack body (plant → drive planner →
confirm effect, the recording/attack shims, delivery detection) lives in
``_session_adapter`` and is shared with the remote (SSE/HTTP) adapter.

The 0-arg subclasses (``FilesystemMCPAdapter`` / ``FetchMCPAdapter`` /
``GitHubMCPAdapter``) accompany the per-target seeds and are instantiated by the
entry-point plugin loader.

Lifecycle: fresh subprocess per ``invoke()`` call. The SDK's ``stdio_client``
context manager guarantees subprocess cleanup.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Import the package init so per-target predicates register.
import mylonite.plugins._mcp  # noqa: F401
from mylonite.plugins._mcp import target_registry

# Re-exported from the transport-agnostic base so existing import paths
# (`from mylonite.plugins._mcp.stdio_adapter import ...`) keep working and so
# tests that `patch.object(stdio_adapter, ...)` find the symbols here.
from mylonite.plugins._mcp._session_adapter import (  # noqa: F401
    _URL_OR_EMAIL,
    DEFAULT_MODEL,
    DEFAULT_PLANNER_TIMEOUT_S,
    MCPSessionAdapterBase,
    _delivery_haystack,
    _distinctive_tokens,
    _extract_first_number,
    _json_string_leaves,
    _MCPAttackSession,
    _planted_payload_retrieved,
    _RecordingServerShim,
    _render_seed_args,
    _serialise_tools,
    _truncate_result,
    _user_message_for_drive,
)


@asynccontextmanager
async def _open_mcp_session(
    spec: target_registry.TargetSpec,
    scope: str | None,
    *,
    extra_env: dict[str, str] | None = None,
    command: str | None = None,
    args: list[str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Spawn the MCP server and yield an initialised ``ClientSession``.

    Both ``stdio_client`` and ``ClientSession`` are async context managers;
    composing them here keeps the call sites flat. Subprocess cleanup is
    guaranteed by the SDK on exit.

    ``command``/``args`` default to the spec's launch; a caller can override them
    to start a target's deliberately-unguarded (``vulnerable_launch``) variant.
    """
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    params = StdioServerParameters(
        command=command or spec.command,
        args=args if args is not None else spec.render_args(scope),
        env=env,
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


class MCPStdioAdapter(MCPSessionAdapterBase):
    """Generic MCP stdio adapter.

    Subclasses wire family + scope to a 0-arg construction shape matching the
    in-process reference adapter's ``InProcessVulnerableReferenceAdapter``
    pattern, so the plugin registry's entry-point loader can instantiate them
    with no args.
    """

    def _session(
        self,
        *,
        extra_env: dict[str, str] | None,
        command: str | None,
        args: list[str] | None,
    ) -> AbstractAsyncContextManager[ClientSession]:
        # Reference the module-global ``_open_mcp_session`` (not a captured
        # alias) so tests that ``patch.object(stdio_adapter, "_open_mcp_session")``
        # take effect.
        return _open_mcp_session(
            self._spec,
            self._scope,
            extra_env=extra_env,
            command=command,
            args=args,
        )

    def _describe_data_sources(self) -> list[str]:
        return [f"MCP stdio: {self._spec.command} {' '.join(self._spec.render_args(self._scope))}"]

    def _describe_notes(self) -> str:
        return (
            f"MCP stdio target — family={self._family!r}, "
            f"scope={self._scope!r}. Fresh subprocess per invocation."
        )


# --- v0.2.2 bundled 0-arg subclasses -----------------------------------------
# Match the InProcessVulnerableReferenceAdapter pattern: a 0-arg subclass per
# bundled target, registered as an entry point, so the plugin registry can
# instantiate them without knowing per-family constructor shapes.


class FilesystemMCPAdapter(MCPStdioAdapter):
    """Bundled filesystem MCP target.

    Constructed by the CLI with the user-supplied ``scope`` (an absolute path
    to the sandbox the filesystem server is allowed to read/write).
    """

    def __init__(
        self,
        *,
        scope: str = "",
        model: str = DEFAULT_MODEL,
        completion_fn: Callable[..., Any] | None = None,
        planner_timeout_s: float = DEFAULT_PLANNER_TIMEOUT_S,
    ) -> None:
        super().__init__(
            family="filesystem",
            scope=scope or None,
            model=model,
            completion_fn=completion_fn,
            planner_timeout_s=planner_timeout_s,
        )


class FetchMCPAdapter(MCPStdioAdapter):
    """Bundled fetch MCP target. Stateless — scope is an optional label."""

    def __init__(
        self,
        *,
        scope: str | None = None,
        model: str = DEFAULT_MODEL,
        completion_fn: Callable[..., Any] | None = None,
        planner_timeout_s: float = DEFAULT_PLANNER_TIMEOUT_S,
    ) -> None:
        super().__init__(
            family="fetch",
            scope=scope,
            model=model,
            completion_fn=completion_fn,
            planner_timeout_s=planner_timeout_s,
        )


class GitHubMCPAdapter(MCPStdioAdapter):
    """Bundled github MCP target.

    Scope is ``owner/repo``. The CLI passes the user-supplied GITHUB_TOKEN
    via ``extra_env`` in the live e2e tests; the unit tests sidestep that
    via the ``_fake_open`` patch.
    """

    def __init__(
        self,
        *,
        scope: str = "",
        model: str = DEFAULT_MODEL,
        completion_fn: Callable[..., Any] | None = None,
        planner_timeout_s: float = DEFAULT_PLANNER_TIMEOUT_S,
    ) -> None:
        super().__init__(
            family="github",
            scope=scope or None,
            model=model,
            completion_fn=completion_fn,
            planner_timeout_s=planner_timeout_s,
        )
