"""The ``control_config.never_call`` guard: tools Mylonite must never call.

Every MCP call Mylonite makes on a target, whatever the transport (stdio, sse,
http) and whoever issues it (the planner, a seed_arm plant, an effect probe, a
calibration write), goes through the ``ClientSession`` that
:meth:`MCPSessionAdapterBase._guarded_session` yields. That session is wrapped
here, so a call to a listed tool is answered locally with an error result and
never sent to the server.

A blocked call proves nothing about the target: the agent was steered toward
the action and Mylonite stopped it, not the app. The adapter stamps the blocked
names into the attempt's metadata (``never_call_blocked``) and the judge turns
the attempt into a no-verdict result (``MYL-INC-013``), never a finding and
never a resisted attempt.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any, Final

from mcp.types import CallToolResult, TextContent

#: The ``blocked_by`` value a never_call block carries in the planner trace.
NEVER_CALL_BLOCK: Final = "never_call"

#: Adapter metadata key: a JSON list of the never_call tools this attempt tried.
NEVER_CALL_METADATA_KEY: Final = "never_call_blocked"


class NeverCallBlocked(CallToolResult):  # type: ignore[misc,unused-ignore]
    """The local answer to a blocked call.

    A subclass, so the shim can tell a block from a server reply by type: a
    server cannot forge it over the wire.
    """


def blocked_message(name: str) -> str:
    """The error text the agent sees in place of the tool's reply."""
    return (
        f"blocked by Mylonite: {name!r} is listed under control_config.never_call, "
        "so the call was not sent to the server."
    )


class NeverCallSession:
    """A ``ClientSession`` stand-in that refuses calls to the listed tools.

    Every other attribute is the wrapped session's own, so listing tools,
    initialisation and the rest behave as before.
    """

    def __init__(self, inner: Any, never_call: Collection[str]) -> None:
        self._inner = inner
        self._never_call = frozenset(never_call)
        #: Tool names this session refused, in call order.
        self.blocked: list[str] = []

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._inner, attr)

    async def call_tool(self, name: str, arguments: Any = None, *args: Any, **kwargs: Any) -> Any:
        if name in self._never_call:
            self.blocked.append(name)
            return NeverCallBlocked(
                content=[TextContent(type="text", text=blocked_message(name))],
                isError=True,
            )
        return await self._inner.call_tool(name, arguments, *args, **kwargs)


def never_call_names(control_config: Any) -> tuple[str, ...]:
    """The target's never_call list; empty when none is declared."""
    if control_config is None:
        return ()
    return tuple(getattr(control_config, "never_call", ()) or ())


def blocked_tools(planner_calls: Sequence[Mapping[str, Any]], session: Any = None) -> list[str]:
    """Sorted names of the never_call tools this attempt tried to call.

    Read from the trace (the planner's calls) and from the guarded session's
    own record, which also covers calls the planner did not make.
    """
    names = {
        str(call["tool"])
        for call in planner_calls
        if call.get("blocked_by") == NEVER_CALL_BLOCK and isinstance(call.get("tool"), str)
    }
    names.update(getattr(session, "blocked", ()) or ())
    return sorted(names)
