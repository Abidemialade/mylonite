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
    DEFAULT_MCP_READ_TIMEOUT,
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

#: Parent-environment variables a spawned MCP server may inherit. Everything
#: else — provider API keys, GITHUB_TOKEN, cloud credentials — is withheld: we
#: routinely spawn deliberately-vulnerable and third-party servers, and
#: ``dict(os.environ)`` handed every one of them Mylonite's own secrets
#: (DCR-0012), with ``launch_env`` leaving the merge policy to an unseen caller
#: (DCR-0018). A target that needs some OTHER parent-env variable must declare
#: it explicitly via the target file's ``env:`` block (``TargetSpec.extra_env``
#: / ``launch_env()``'s overlay) — that is the correct, auditable way to widen
#: a spawned server's environment, not a broader allowlist here.
#:
#: The set below is deliberately platform-neutral (both POSIX and Windows
#: entries): a bundled npx/uvx-launched target must keep working on either
#: platform. ``SYSTEMROOT``/``COMSPEC``/``APPDATA``/``LOCALAPPDATA`` are
#: Windows-specific (npx/node and many native subprocess launchers on Windows
#: fail to resolve the shell/DLL search path without them); ``HOME``/``LANG``/
#: ``LC_ALL`` are the POSIX equivalents. Verified empirically on Windows: a
#: real ``npx``-launched filesystem server and ``uvx``-launched fetch server
#: both spawn and respond to ``tools/list`` with only this allowlist.
_INHERITED_ENV_KEYS: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "PATHEXT",
        "COMSPEC",
        "APPDATA",
        "LOCALAPPDATA",
    }
)


def _compose_child_env(extra_env: dict[str, str] | None) -> dict[str, str]:
    """Build the spawned server's environment: the allowlisted parent
    variables, then the target's declared overlay on top — normalized so
    there is never more than one entry for the same effective variable name.

    Two case-sensitivity hazards, both around ``os.environ``'s ACTUAL stored
    key casing being a platform/session quirk (Windows has been observed
    storing e.g. ``"Path"`` instead of ``"PATH"``):

    1. The allowlist CHECK must be case-insensitive (``k.upper() in
       _INHERITED_ENV_KEYS``) or a variable stored under an unexpected casing
       is silently dropped — the safer failure mode for an allowlist is "too
       narrow", not a platform-dependent flake.
    2. Every allowlisted entry is then stored under a SINGLE CANONICAL
       (uppercase) key, and ``extra_env`` overlay keys are merged by first
       removing any existing entry that matches case-insensitively. Without
       this, an inherited ``"Path"`` plus a target-declared override
       ``env: {PATH: ...}`` would both land in the dict as separate keys —
       the override would not cleanly REPLACE the inherited value, it would
       silently ADD a same-effective-name key under different casing, with
       implementation-defined behaviour for which one the OS actually
       resolves. That would defeat ``TargetSpec.launch_env``'s documented
       "single precedence point" guarantee.
    """
    env: dict[str, str] = {}
    # Track, per UPPERCASE name, which exact key currently occupies `env` —
    # lets the extra_env merge below find and remove a case-differing
    # duplicate before inserting the overlay's own key.
    canonical_key_for: dict[str, str] = {}
    for k, v in os.environ.items():
        upper = k.upper()
        if upper in _INHERITED_ENV_KEYS:
            env[upper] = v  # canonical uppercase key — collapses any pre-existing
            canonical_key_for[upper] = upper  # case ambiguity in os.environ itself
    if extra_env:
        for k, v in extra_env.items():
            upper = k.upper()
            existing_key = canonical_key_for.get(upper)
            if existing_key is not None and existing_key != k:
                del env[existing_key]
            env[k] = v
            canonical_key_for[upper] = k
    return env


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

    Environment (DCR-0012/DCR-0018): the child does NOT inherit the full
    parent environment. It gets a narrow, named allowlist
    (``_INHERITED_ENV_KEYS`` — PATH and the handful of OS-plumbing variables a
    subprocess launcher needs) merged with ``extra_env`` (the target's
    declared overlay — see ``TargetSpec.launch_env``'s docstring), composed by
    :func:`_compose_child_env` so a casing mismatch can't produce a duplicate
    entry. This is a deliberate, real behaviour change: a custom MCP server
    that previously relied on inheriting some OTHER parent-env variable must
    now declare it explicitly in the target file's ``env:`` block.
    """
    env = _compose_child_env(extra_env)
    params = StdioServerParameters(
        command=command or spec.command,
        args=args if args is not None else spec.render_args(scope),
        env=env,
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(
            read_stream, write_stream, read_timeout_seconds=DEFAULT_MCP_READ_TIMEOUT
        ) as session,
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
