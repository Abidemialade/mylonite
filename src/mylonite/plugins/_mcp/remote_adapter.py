"""Remote MCP transport adapter (SSE / streamable-HTTP).

A thin transport subclass of :class:`MCPSessionAdapterBase`: it supplies a
``_session`` that connects to a remote MCP server over SSE or streamable-HTTP
(rather than spawning a subprocess), plus remote-flavoured descriptor strings.
The entire attack body — plant, drive planner, confirm effect, the recording and
stateful-attack shims — is inherited unchanged from the base and is transport-
blind.

Remote MCP is the dominant real-world MCP deployment, so this is what lets
Mylonite scan apps it didn't write (e.g. the Layer 1 verification targets, which
run on ports rather than over stdio).

Lifecycle: a fresh connection per ``invoke()`` (clean isolation per attempt),
mirroring the stdio adapter. ``command``/``args``/``extra_env`` and the server-
layer ``vulnerable_launch``/``control_env`` overrides are N/A for a remote
endpoint and are ignored.

SECURITY: ``headers`` may carry bearer tokens. They are passed to the transport
but never logged and never surfaced in the descriptor (only the URL host is).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import timedelta
from urllib.parse import urlsplit

from mcp import ClientSession

from mylonite.plugins._mcp._session_adapter import MCPSessionAdapterBase

#: Bound on how long a single ``ClientSession`` read (including
#: ``session.initialize()``) may block waiting on the remote server before
#: raising, so a non-responding remote endpoint cannot hang a scan forever
#: (RB-DCR-0002).
_READ_TIMEOUT = timedelta(seconds=60.0)


def _host_only(url: str | None) -> str:
    """The host (+ port, if non-default) of ``url`` — never userinfo/credentials.

    ``urlsplit(url).netloc`` includes any embedded userinfo (e.g.
    ``https://sk-live-abc@host/sse`` -> netloc ``sk-live-abc@host``), which
    would surface a URL-embedded credential in a descriptor string
    (RB-DCR-0001). ``.hostname`` never includes userinfo.
    """
    parts = urlsplit(url or "")
    host = parts.hostname or "(unknown)"
    if parts.port:
        return f"{host}:{parts.port}"
    return host


@asynccontextmanager
async def _open_remote_session(
    transport: str,
    url: str,
    headers: dict[str, str] | None,
) -> AsyncIterator[ClientSession]:
    """Connect to a remote MCP server and yield an initialised ``ClientSession``.

    ``sse_client`` yields ``(read, write)``; ``streamablehttp_client`` yields
    ``(read, write, get_session_id)`` — indexing ``[0]``/``[1]`` handles both.
    """
    if transport == "sse":
        from mcp.client.sse import sse_client

        client_cm = sse_client(url, headers=headers or None)
    elif transport == "http":
        try:
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:  # pragma: no cover - depends on SDK version
            raise RuntimeError(
                "transport 'http' needs a newer mcp SDK (mcp.client.streamable_http); "
                "use transport 'sse' or upgrade mcp."
            ) from exc
        client_cm = streamablehttp_client(url, headers=headers or None)
    else:  # pragma: no cover - guarded by TargetFile/registry validation
        raise ValueError(f"unsupported remote transport {transport!r}")

    async with client_cm as streams:
        read_stream, write_stream = streams[0], streams[1]
        async with ClientSession(
            read_stream, write_stream, read_timeout_seconds=_READ_TIMEOUT
        ) as session:
            await session.initialize()
            yield session


class MCPRemoteAdapter(MCPSessionAdapterBase):
    """Generic MCP adapter over a remote SSE / streamable-HTTP endpoint."""

    def _session(
        self,
        *,
        extra_env: dict[str, str] | None,
        command: str | None,
        args: list[str] | None,
    ) -> AbstractAsyncContextManager[ClientSession]:
        # Remote transports ignore the stdio launch knobs.
        if not self._spec.url:
            raise ValueError(
                f"remote target {self._family!r} has no url; transport={self._spec.transport!r}"
            )
        return _open_remote_session(self._spec.transport, self._spec.url, self._spec.headers)

    def _describe_data_sources(self) -> list[str]:
        # Host only — never the full URL with query/credentials/userinfo, never headers.
        host = _host_only(self._spec.url)
        return [f"MCP {self._spec.transport}: {host}"]

    def _describe_notes(self) -> str:
        host = _host_only(self._spec.url)
        return (
            f"MCP {self._spec.transport} target — family={self._family!r}, host={host}. "
            "Fresh connection per invocation."
        )

    @staticmethod
    def _classify_failure(exc: BaseException) -> str:
        name = type(exc).__name__
        if name in {"ConnectError", "ConnectTimeout", "ReadTimeout", "PoolTimeout"}:
            return "init_failure"
        if name in {"HTTPStatusError", "RemoteProtocolError"}:
            return "mcp_protocol_error"
        return MCPSessionAdapterBase._classify_failure(exc)
