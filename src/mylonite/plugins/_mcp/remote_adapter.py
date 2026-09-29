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

import httpx
from mcp import ClientSession

from mylonite.contracts import TargetDescriptor
from mylonite.plugins._mcp._session_adapter import (
    DEFAULT_MCP_READ_TIMEOUT,
    MCPSessionAdapterBase,
)
from mylonite.scan._types import AdapterDescribeFailed

#: Time budget for the standalone preflight request (see
#: ``MCPRemoteAdapter._preflight_auth_check``) — short, because this is a
#: single best-effort request that must never become the slow part of a scan.
_PREFLIGHT_TIMEOUT_S = 5.0

#: Status codes this task treats as "rejected credentials", per the brief.
_AUTH_REJECTED_STATUSES = frozenset({401, 403})


def _find_auth_status(exc: BaseException) -> int | None:
    """Walk ``ExceptionGroup``s and ``__cause__``/``__context__`` chains for
    an ``httpx.HTTPStatusError`` whose status is 401 or 403, and return it.

    The mcp SDK's ``sse_client``/``streamablehttp_client`` run their read
    loop inside an anyio task group, so a rejected connection surfaces
    wrapped in an ``ExceptionGroup`` around the real ``httpx.HTTPStatusError``
    rather than as that exception directly — a name-only check on the
    top-level exception (what ``_classify_failure`` did before this) never
    recognises that shape.
    """
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            status = int(current.response.status_code)
            if status in _AUTH_REJECTED_STATUSES:
                return status
        stack.extend(getattr(current, "exceptions", None) or ())
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return None


def _auth_rejected_message(host: str, status: int) -> str:
    """The operator-facing fix text for a remote target that rejected
    credentials — identical wording for a first-contact ``describe()``
    failure and an in-flight attempt (required behaviour #2)."""
    return (
        f"the server at {host} rejected the request ({status}). Set the token in "
        "`headers:` in the target file, e.g. `Authorization: Bearer ${MY_TOKEN}`, "
        "and export MY_TOKEN before you scan. See docs/target-file.md."
    )


def _describe_failure_message(host: str) -> str:
    """The generic (non-auth) remote describe() failure — about the url and
    headers, never the stdio-flavoured "command" wording (required
    behaviour #1)."""
    return (
        f"could not describe the remote target at {host} (adapter.describe() "
        "failed); nothing was scanned. Check the url and headers in the target "
        "file, and connectivity to the server."
    )


def _host_only(url: str | None) -> str:
    """The host (+ port, when present in the URL) of ``url`` — never
    userinfo/credentials.

    ``urlsplit(url).netloc`` includes any embedded userinfo (e.g.
    ``https://sk-live-abc@host/sse`` -> netloc ``sk-live-abc@host``), which
    would surface a URL-embedded credential in a descriptor string
    (RB-DCR-0001). ``.hostname`` never includes userinfo.

    Two edge cases the naive ``f"{hostname}:{port}"`` composition gets wrong:

    * ``.port`` is LAZILY VALIDATED — accessing it raises ``ValueError`` for
      an out-of-range (e.g. ``:99999``) or non-numeric port. A remote
      target's ``url`` is operator-supplied (a target file) with no
      port-range validation ahead of time, so a malformed configured URL
      must not crash ``describe()`` — the port is simply omitted, same as
      the existing ``hostname is None`` -> ``"(unknown)"`` degradation.
    * An IPv6 ``.hostname`` (e.g. ``::1``) already contains ``:``, so
      appending ``:{port}`` unbracketed produces an ambiguous, unparseable
      string (``::1:8080`` — address vs. port boundary is lost). Reconstruct
      as ``[::1]:8080`` when a port is present; a bare IPv6 host with no
      port is unambiguous as-is.
    """
    parts = urlsplit(url or "")
    host = parts.hostname or "(unknown)"
    try:
        port = parts.port
    except ValueError:
        # Malformed/out-of-range port — degrade gracefully rather than raise.
        port = None
    if port:
        if ":" in host:  # IPv6 — bracket so the port boundary stays unambiguous.
            return f"[{host}]:{port}"
        return f"{host}:{port}"
    return host


@asynccontextmanager
async def _open_remote_session(
    transport: str,
    url: str,
    headers: dict[str, str] | None,
    read_timeout: timedelta = DEFAULT_MCP_READ_TIMEOUT,
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
            read_stream, write_stream, read_timeout_seconds=read_timeout
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
        return _open_remote_session(
            self._spec.transport,
            self._spec.url,
            self._spec.headers,
            read_timeout=self._mcp_read_timeout,
        )

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

    async def describe(self) -> TargetDescriptor:
        # The preflight below (required behaviour #4) runs ONLY on this
        # failure path, and only when the real handshake's own error didn't
        # already carry a recoverable status — never unconditionally before
        # every describe(). A successful describe() (the common case: `scan`,
        # `check`, auto-wire, `--scaffold`) sends zero extra requests. Running
        # it up front, on every call, would have made an unrelated bare GET
        # part of every remote target's first contact — a POST-only /
        # streamable-HTTP-only server that answers 403 to a plain GET (an
        # API-Gateway-style policy) would then falsely abort a scan the real
        # handshake would have completed just fine.
        try:
            return await super().describe()
        except ImportError:
            # A missing dependency is a configuration error; the engine
            # re-raises it on purpose, so it must not become
            # AdapterDescribeFailed here.
            raise
        except AdapterDescribeFailed:
            # #186 fix round 1: the base class already produced an
            # operator-ready message (currently: a timeout naming timeout_s
            # and its effective value) -- the except-Exception branch below
            # would otherwise catch it too and REPLACE that message with the
            # generic host/status-shaped remote one, losing timeout_s
            # entirely. Same treatment as ImportError above.
            raise
        except Exception as exc:
            host = _host_only(self._spec.url)
            # Real local servers (both sse and http/streamable-HTTP) DO
            # surface the status this way — the mcp SDK's read loop runs in
            # an anyio task group, so it arrives wrapped in an ExceptionGroup,
            # not as the bare httpx.HTTPStatusError, which is why this needs
            # the walk in _find_auth_status rather than a name check.
            status = _find_auth_status(exc)
            if status is None:
                # Only reached when the real error truly didn't carry a
                # status at all (a streamable-HTTP peer can close the
                # connection without ever telling the SDK why) — the one case
                # the preflight exists for.
                status = await self._preflight_auth_status()
            message = (
                _auth_rejected_message(host, status)
                if status is not None
                else _describe_failure_message(host)
            )
            raise AdapterDescribeFailed(message) from exc

    async def _preflight_auth_status(self) -> int | None:
        """One request to the URL with the configured headers, run ONLY from
        ``describe()``'s failure path (see the comment there) — never
        unconditionally, so a successful describe() sends no extra request.

        Returns the status when it's 401/403, else ``None`` — a non-auth
        response (2xx, 404, 405 — this endpoint may not accept a bare GET at
        all), a network error, or a timeout is not this check's business and
        is silently swallowed; the caller falls back to the generic message.

        Reads only the RESPONSE HEADERS (``client.stream()``, never
        ``client.get()``) and never the body. A real SSE endpoint answers 200
        with a body that streams indefinitely; ``.get()`` waits for that body
        to finish (or, worse, never technically times out — each keep-alive
        chunk resets httpx's per-read timeout) before returning, which would
        turn this into an open-ended hang on a healthy server. Exiting the
        ``async with`` block below closes the stream as soon as the status is
        read, before any body arrives.
        """
        if not self._spec.url:
            return None
        try:
            async with (
                httpx.AsyncClient(timeout=_PREFLIGHT_TIMEOUT_S) as client,
                client.stream(
                    "GET", self._spec.url, headers=self._spec.headers or None
                ) as response,
            ):
                status = response.status_code
        except Exception:
            return None
        return status if status in _AUTH_REJECTED_STATUSES else None

    @staticmethod
    def _classify_failure(exc: BaseException) -> str:
        # A rejected connection reuses the existing "launch_failure" reason —
        # the closest non-planner classification that already exists (no new
        # outcome enum value; required behaviour #2) — rather than the
        # default "planner_exception", which told the operator their planner
        # had broken when the real cause was a rejected remote credential.
        if _find_auth_status(exc) is not None:
            return "launch_failure"
        name = type(exc).__name__
        if name in {"ConnectError", "ConnectTimeout", "ReadTimeout", "PoolTimeout"}:
            return "init_failure"
        if name in {"HTTPStatusError", "RemoteProtocolError"}:
            return "mcp_protocol_error"
        return MCPSessionAdapterBase._classify_failure(exc)

    def _skip_exception_detail(self, exc: BaseException) -> str:
        status = _find_auth_status(exc)
        if status is not None:
            return _auth_rejected_message(_host_only(self._spec.url), status)
        return super()._skip_exception_detail(exc)
