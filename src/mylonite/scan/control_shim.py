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

Implements the W1-W4 boundary controls (e.g. the W2 untrusted-data envelope).
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar, Protocol, runtime_checkable

from mylonite.scan._control_primitives import (
    host_allowed,
    quarantine,
    sanitize_tool_description,
)
from mylonite.scan.llm_types import ToolDescription, ToolResult
from mylonite.scan.tool_classifier import classify, looks_like_destination, url_values

logger = logging.getLogger(__name__)

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

    def _warn_fail_closed_once(self, name: str, reason: str, snippet: str) -> None:
        """Log, once per (control instance, tool name), that ``name`` was
        GUARDED (refused, deferred, or wrapped) by fail-closed classification
        rather than a declared ``control_config`` entry (the escape hatch for
        DCR-0034/0035).

        Never fires for ``reason == "declared"`` — the operator already told us
        about that tool, so there is nothing to surface. State is per-instance
        (``make_control`` builds a fresh control per invoke, per its module
        docstring), so a warning that was suppressed in one scan run re-fires in
        the next; it is not process-global.
        """
        if reason == "declared":
            return
        warned: set[str] | None = getattr(self, "_fail_closed_warned", None)
        if warned is None:
            warned = set()
            self._fail_closed_warned = warned
        if name in warned:
            return
        warned.add(name)
        # "fail-closed default" IS the basis, so stating it once is enough; any
        # other reason (e.g. "a destination-shaped argument", "name hint") is
        # additional information worth keeping alongside it.
        basis = reason if reason == "fail-closed default" else f"fail-closed default: {reason}"
        logger.warning(
            "%s: %r was guarded by %s, not a declared control_config entry. To "
            "classify it precisely, add this to your target file:\n%s",
            self.weakness,
            name,
            basis,
            snippet,
        )


# Tool-name hints for "retrieval/read" tools whose results carry untrusted
# content back to the planner (the W2 indirect-injection surface). Substring,
# case-insensitive; tool_roles classification refines this heuristic.
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
        # Optional explicit allowlist of tool names to wrap; when None, EVERY
        # tool's non-error result is wrapped by fail-closed default (see
        # `_classify` / DCR-0035) — a zero-config custom target still works,
        # and an unhinted retrieval tool is no longer silently unwrapped.
        # Declare `read_tool_names` (or `control_config.read_tool_names` in a
        # target file) to narrow this to just the actual retrieval surface.
        self._read_tool_names = read_tool_names

    def _classify(self, name: str) -> tuple[bool, str]:
        # Declared list -> name hint -> fail-closed default (DCR-0035). There is
        # no structural-evidence tier here (unlike W3's URL check): whether a
        # RESULT is untrusted data isn't decidable from the CALL arguments, only
        # from the tool's role, so name classification is all there is short of
        # an explicit declaration.
        return classify(name, declared=self._read_tool_names, hints=_READ_HINTS)

    def _config_snippet(self, name: str) -> str:
        return f"control_config:\n  read_tool_names: [{name}]"

    def transform_result(self, name: str, result: ToolResult) -> ToolResult:
        # Never wrap a guarded refusal (isError) — that would mangle the
        # structural signal the judge relies on. Only wrap content the planner
        # reads back as data.
        if result.isError:
            return result
        applies, reason = self._classify(name)
        if not applies:
            return result
        # DCR-0035's escape hatch: an operator whose custom target now has
        # EVERY non-error result wrapped (no `read_tool_names` declared) gets a
        # once-per-tool warning with the exact snippet to narrow it. No-ops
        # when `reason == "declared"` — nothing to surface if the operator
        # already told us this is a read tool.
        self._warn_fail_closed_once(name, reason, self._config_snippet(name))
        return ToolResult(
            name=result.name,
            content=quarantine(result.content),
            isError=result.isError,
        )


# Heuristic name hints (substring, case-insensitive). Explicit tool lists from a
# ControlConfig are authoritative over these; an unhinted name still falls
# through to the fail-closed default (see `tool_classifier.classify`) rather
# than passing through unguarded.
_EGRESS_HINTS: tuple[str, ...] = ("fetch", "http", "download", "curl", "request", "egress", "web")
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


class EgressAllowlistControl(BoundaryControl):
    """W3 — refuse egress-tool calls to hosts outside an allowlist.

    Intercepts calls to egress-shaped tools and, when a destination argument
    points off the allowlist, returns an ``isError`` refusal WITHOUT calling the
    inner tool (mirrors the guarded reference twin's web_fetch allowlist).

    Classification is declared list -> structural evidence (a destination-shaped
    argument, regardless of name) -> name hint -> fail-closed default (DCR-0032/
    0033): an egress-classified call with NO identifiable destination is now
    REFUSED, not passed through — the old behaviour meant the allowlist never
    ran on the real destination.
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

    def _destinations_in(self, arguments: dict[str, Any]) -> list[str]:
        """Destination-shaped argument values, scheme-less included (DCR-0032).

        When ``url_param`` is declared, only that argument is checked — the
        operator's precise answer to "which argument is the destination?".
        Otherwise every argument is walked, including nested lists/dicts
        (:func:`mylonite.scan.tool_classifier.url_values`).
        """
        if self._url_param is not None:
            val = arguments.get(self._url_param)
            return [val] if isinstance(val, str) and looks_like_destination(val) else []
        return url_values(arguments)

    def _classify(self, name: str, arguments: dict[str, Any]) -> tuple[bool, str, list[str]]:
        # Computed once here (not again in `intercept_call`): `_classify` is the
        # single source of both the applies/reason decision and the destination
        # list `intercept_call` needs next, since the structural-evidence tier
        # already has to compute it to decide.
        destinations = self._destinations_in(arguments)
        if self._egress_tools is not None:
            return name in self._egress_tools, "declared", destinations
        if destinations:
            return True, "a destination-shaped argument", destinations
        applies, reason = classify(name, declared=None, hints=_EGRESS_HINTS)
        return applies, reason, destinations

    def _config_snippet(self, name: str) -> str:
        return (
            "control_config:\n"
            f"  egress_tools: [{name}]\n"
            "  egress_url_param: <the-argument-name-holding-the-destination>"
        )

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        applies, reason, destinations = self._classify(name, arguments)
        if not applies:
            return None
        if not destinations:
            # An egress-classified tool whose destination we cannot identify is
            # REFUSED, not passed through. Failing open here meant the
            # allowlist never evaluated the real destination (DCR-0032).
            self._warn_fail_closed_once(name, reason, self._config_snippet(name))
            return ToolResult(
                name=name,
                content=(
                    f"refused: {name!r} is treated as an egress tool but no destination "
                    "argument could be identified. Declare control_config.egress_url_param "
                    "in your target file to make this precise."
                ),
                isError=True,
            )
        blocked = [d for d in destinations if not host_allowed(d, self._allowlist)]
        if not blocked:
            return None
        self._warn_fail_closed_once(name, reason, self._config_snippet(name))
        return ToolResult(
            name=name,
            content=f"refused: host(s) for {blocked!r} not in egress allowlist",
            isError=True,
        )


class ConfirmGateControl(BoundaryControl):
    """W4 — block unconfirmed consequential actions at the boundary.

    Intercepts calls to consequential-shaped tools and returns a deferred
    ``isError`` "requires confirmation" result instead of executing them, so an
    unconfirmed consequential action never takes effect (the guarded twin's
    two-step send/confirm, modelled as a confirm-gate).

    Classification is declared list -> name hint -> fail-closed default
    (DCR-0034); there is no structural-evidence tier here — unlike W3's URL
    check, "is this action consequential?" has no shape in the call arguments,
    only in what the tool DOES, so name classification is all there is short of
    an explicit declaration.

    Fidelity note: this BLOCKS the action rather than allowing it after a real
    confirmation step. For the differential — "did the unconfirmed action take
    effect?" — blocking is the correct signal; it is a low-fidelity stand-in for
    a true human-in-the-loop confirm flow (surfaced in the report/PR).
    """

    weakness = "W4"

    def __init__(self, *, consequential_tools: frozenset[str] | None = None) -> None:
        self._consequential_tools = consequential_tools

    def _classify(self, name: str) -> tuple[bool, str]:
        return classify(name, declared=self._consequential_tools, hints=_CONSEQUENTIAL_HINTS)

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        applies, reason = self._classify(name)
        if not applies:
            return None
        self._warn_fail_closed_once(
            name,
            reason,
            f"control_config:\n  consequential_tools: [{name}]",
        )
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
# the boundary control set).
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
