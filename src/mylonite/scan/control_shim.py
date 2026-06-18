"""Boundary control shim: synthesize a guarded twin of a REAL MCP target.

Mylonite's differential oracle measures whether a SAFEGUARD (not the model)
carries the security, by holding the model constant and toggling the guard. For
the bundled reference target that toggle is the vulnerable/guarded server pair.
A real custom MCP target has no in-repo guarded twin, so this module synthesizes
one at the adapter boundary: it applies a canonical control to the data the
planner sees (tool descriptions and tool results) WITHOUT modifying the
customer's server.

Composition (see ``MCPStdioAdapter.invoke``)::

    session -> MCPSessionAsServerLike -> ControlServerShim(controls)
            -> _RecordingServerShim -> LLMPlanner

The control shim sits UNDER the recording shim so the recorded trace /
effect-trace reflect the GUARDED view the planner actually acted on (a W3/W4
refusal surfaces as ``isError`` in the trace, which the judge already treats as
a defended action).

INVARIANT (load-bearing for honesty): only the PLANNER's view is shimmed. The
attacker's plant (``_run_setup``) and the ground-truth verification
(``_run_effect_probe``) talk to the raw ``session`` directly and bypass this
shim. So poison is planted un-sanitized and damage is confirmed against the real
server state; the control only changes what the model is shown on read. If a
future change routes the plant or the probe through this shim, the measurement
is no longer honest.

Slice 1 ships W2 (untrusted-data envelope). W1/W3/W4 land in Slice 2.
"""

from __future__ import annotations

from typing import Any, ClassVar, Protocol, runtime_checkable

from mylonite.scan._control_primitives import (
    host_allowed,
    quarantine,
    sanitize_tool_description,
)
from mylonite.scan.llm_types import ToolDescription, ToolResult

#: Default egress allowlist mirroring the guarded reference twin (W3).
DEFAULT_FETCH_ALLOWLIST: tuple[str, ...] = ("localhost", "127.0.0.1", "example.com")


@runtime_checkable
class _ServerLike(Protocol):
    """The structural surface ``LLMPlanner`` consumes (async list/call)."""

    async def list_tools(self) -> list[ToolDescription]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult: ...


class BoundaryControl:
    """One canonical safeguard applied at the adapter boundary.

    Subclasses override only the hooks they use; the defaults are identity, so a
    result-only control (W2) need not touch descriptions or intercept calls.
    """

    weakness: ClassVar[str] = ""

    def transform_description(self, tool: ToolDescription) -> ToolDescription:
        """Rewrite a tool description before the planner sees it (W1)."""
        return tool

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        """Refuse/short-circuit a call before it reaches the inner tool (W3/W4).

        Return a synthesized ``ToolResult`` to block, or ``None`` to pass through.
        """
        return None

    def transform_result(self, name: str, result: ToolResult) -> ToolResult:
        """Rewrite a tool result before the planner sees it (W2)."""
        return result


# Tool-name hints for "retrieval/read" tools whose results carry untrusted
# content back to the planner (the W2 indirect-injection surface). Substring,
# case-insensitive. Slice 2 replaces this heuristic with tool_roles classification.
_READ_HINTS: tuple[str, ...] = (
    "read",
    "get",
    "fetch",
    "recall",
    "list",
    "search",
    "retrieve",
    "view",
    "load",
    "lookup",
)


class UntrustedEnvelopeControl(BoundaryControl):
    """W2 — wrap retrieval-tool results in an untrusted-data envelope.

    The canonical indirect-injection mitigation (data marking / spotlighting):
    content the planner reads back from storage/fetch is marked as data, not
    instruction. Mirrors ``server_guarded._quarantine`` applied to read results.
    Whether the envelope actually stops the attack depends on the target's model
    and system prompt respecting it — which is exactly what the differential
    measures.
    """

    weakness = "W2"

    def __init__(self, read_tool_names: frozenset[str] | None = None) -> None:
        # Optional explicit allowlist of tool names to wrap; when None, fall back
        # to the name-hint heuristic so a zero-config custom target still works.
        self._read_tool_names = read_tool_names

    def _is_read_tool(self, name: str) -> bool:
        if self._read_tool_names is not None:
            return name in self._read_tool_names
        lowered = name.lower()
        return any(hint in lowered for hint in _READ_HINTS)

    def transform_result(self, name: str, result: ToolResult) -> ToolResult:
        # Never wrap a guarded refusal (isError) — that would mangle the
        # structural signal the judge relies on. Only wrap content the planner
        # reads back as data.
        if result.isError or not self._is_read_tool(name):
            return result
        return ToolResult(
            name=result.name,
            content=quarantine(result.content),
            isError=result.isError,
        )


# Heuristic name hints (substring, case-insensitive). Explicit tool lists from a
# ControlConfig override these; the hints are the zero-config fallback.
_EGRESS_HINTS: tuple[str, ...] = ("fetch", "http", "download", "curl", "request", "egress", "web")
_URL_PARAM_HINTS: tuple[str, ...] = ("url", "uri", "href", "endpoint", "link", "address")
_CONSEQUENTIAL_HINTS: tuple[str, ...] = (
    "send",
    "email",
    "transfer",
    "pay",
    "delete",
    "remove",
    "create",
    "post",
    "write",
    "execute",
    "issue",
    "dispatch",
)


class ToolDescriptionSanitizer(BoundaryControl):
    """W1 — sanitize tool descriptions before the planner sees them.

    Strips hidden ``<IMPORTANT>`` blocks, parenthetical instruction asides, and
    non-ASCII smuggling (unicode tag chars / confusables). The canonical
    tool-poisoning mitigation, applied to EVERY tool's description.
    """

    weakness = "W1"

    def transform_description(self, tool: ToolDescription) -> ToolDescription:
        cleaned = sanitize_tool_description(tool.description)
        if cleaned == tool.description:
            return tool
        return ToolDescription(name=tool.name, description=cleaned, input_schema=tool.input_schema)


def _looks_like_url(value: object) -> bool:
    return isinstance(value, str) and "://" in value


class EgressAllowlistControl(BoundaryControl):
    """W3 — refuse egress-tool calls to hosts outside an allowlist.

    Intercepts calls to egress-shaped tools and, when a URL argument points off
    the allowlist, returns an ``isError`` refusal WITHOUT calling the inner tool
    (mirrors the guarded reference twin's web_fetch allowlist). Egress tools and
    the URL arg come from the ControlConfig when declared, else a name heuristic.
    """

    weakness = "W3"

    def __init__(
        self,
        *,
        egress_tools: frozenset[str] | None = None,
        url_param: str | None = None,
        allowlist: tuple[str, ...] = DEFAULT_FETCH_ALLOWLIST,
    ) -> None:
        self._egress_tools = egress_tools
        self._url_param = url_param
        self._allowlist = allowlist

    def _is_egress(self, name: str) -> bool:
        if self._egress_tools is not None:
            return name in self._egress_tools
        lowered = name.lower()
        return any(hint in lowered for hint in _EGRESS_HINTS)

    def _url_in(self, arguments: dict[str, Any]) -> str | None:
        if self._url_param is not None:
            val = arguments.get(self._url_param)
            return val if isinstance(val, str) else None
        for key, val in arguments.items():
            if any(hint in key.lower() for hint in _URL_PARAM_HINTS) and isinstance(val, str):
                return val
        for val in arguments.values():
            if _looks_like_url(val):
                return str(val)
        return None

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        if not self._is_egress(name):
            return None
        url = self._url_in(arguments)
        if url is None or host_allowed(url, self._allowlist):
            return None
        return ToolResult(
            name=name,
            content=f"refused: host for {url!r} not in egress allowlist",
            isError=True,
        )


class ConfirmGateControl(BoundaryControl):
    """W4 — block unconfirmed consequential actions at the boundary.

    Intercepts calls to consequential-shaped tools and returns a deferred
    ``isError`` "requires confirmation" result instead of executing them, so an
    unconfirmed consequential action never takes effect (the guarded twin's
    two-step send/confirm, modelled as a confirm-gate).

    Fidelity note: this BLOCKS the action rather than allowing it after a real
    confirmation step. For the differential — "did the unconfirmed action take
    effect?" — blocking is the correct signal; it is a low-fidelity stand-in for
    a true human-in-the-loop confirm flow (surfaced in the report/PR).
    """

    weakness = "W4"

    def __init__(self, *, consequential_tools: frozenset[str] | None = None) -> None:
        self._consequential_tools = consequential_tools

    def _is_consequential(self, name: str) -> bool:
        if self._consequential_tools is not None:
            return name in self._consequential_tools
        lowered = name.lower()
        return any(hint in lowered for hint in _CONSEQUENTIAL_HINTS)

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        if not self._is_consequential(name):
            return None
        return ToolResult(
            name=name,
            content=(
                f"deferred: {name!r} requires explicit confirmation "
                "(blocked by boundary confirm-gate)"
            ),
            isError=True,
        )


class ControlServerShim:
    """Wrap a ``_ServerLike`` so the planner sees a control-guarded view.

    ``list_tools`` runs each control's description transform; ``call_tool`` gives
    controls a chance to refuse (``intercept_call``) before the inner tool runs,
    then runs each control's result transform on what the inner returned.
    """

    def __init__(self, inner: _ServerLike, controls: list[BoundaryControl]) -> None:
        self._inner = inner
        self._controls = controls

    async def list_tools(self) -> list[ToolDescription]:
        tools = await self._inner.list_tools()
        out: list[ToolDescription] = []
        for tool in tools:
            transformed = tool
            for control in self._controls:
                transformed = control.transform_description(transformed)
            out.append(transformed)
        return out

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        for control in self._controls:
            refused = control.intercept_call(name, arguments)
            if refused is not None:
                return refused
        result = await self._inner.call_tool(name, arguments)
        for control in self._controls:
            result = control.transform_result(name, result)
        return result


# Registry keyed by weakness class, mirroring gate/mitigations/{W*}.md. A factory
# so each invoke gets a fresh control instance (controls may hold per-run state in
# later slices). Slice 1 implements W2 only.
def make_control(
    weakness: str,
    *,
    read_tool_names: frozenset[str] | None = None,
    egress_tools: frozenset[str] | None = None,
    url_param: str | None = None,
    fetch_allowlist: tuple[str, ...] = DEFAULT_FETCH_ALLOWLIST,
    consequential_tools: frozenset[str] | None = None,
) -> BoundaryControl:
    """Build the canonical boundary control for a weakness class (W1-W4).

    Raises for an unknown class so a caller can never silently get a no-op
    control (which would make a guard look load-bearing when nothing ran).
    """
    if weakness == "W1":
        return ToolDescriptionSanitizer()
    if weakness == "W2":
        return UntrustedEnvelopeControl(read_tool_names=read_tool_names)
    if weakness == "W3":
        return EgressAllowlistControl(
            egress_tools=egress_tools, url_param=url_param, allowlist=fetch_allowlist
        )
    if weakness == "W4":
        return ConfirmGateControl(consequential_tools=consequential_tools)
    raise ValueError(f"no boundary control implemented for weakness {weakness!r}")
