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

import hashlib
import hmac
import json
import logging
import secrets
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


def config_snippet_for(
    weakness: str,
    tool: str,
    *,
    url_param: str | None = None,
    allowlist: tuple[str, ...] = (),
) -> str:
    """The paste-ready ``control_config:`` YAML snippet for a weakness/tool pair.

    The single source of truth for every control's ``_config_snippet`` method
    (W2/W3/W4 below all delegate here with no extra args, reproducing their
    prior byte-identical output) AND for the structural recommendation engine
    (``gate/recommend.py``), which additionally passes ``url_param``/
    ``allowlist`` when the trace identified them — the fail-closed warning
    path never has those, so it always gets exactly today's generic template.
    """
    if weakness == "W2":
        return f"control_config:\n  read_tool_names: [{tool}]"
    if weakness == "W3":
        lines = ["control_config:", f"  egress_tools: [{tool}]"]
        lines.append(f"  egress_url_param: {url_param or '<the-argument-name-holding-the-destination>'}")
        if allowlist:
            lines.append(f"  fetch_allowlist: [{', '.join(allowlist)}]")
        return "\n".join(lines)
    if weakness == "W4":
        return f"control_config:\n  consequential_tools: [{tool}]"
    raise ValueError(f"no config snippet available for weakness {weakness!r}")


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

    def reset(self) -> None:
        """Clear any session-scoped state before a NEW planner session starts.

        Called once by :class:`ControlServerShim`'s constructor. Most controls
        are stateless across calls (default no-op); ``InformationFlowControl``
        (W2, PR4) is the first exception — its taint flag must not leak
        between two different exploit attempts that happen to share the same
        long-lived control instance (``TargetAdapter.__init__`` builds the
        control list once; ``ControlServerShim`` is rebuilt fresh per
        ``invoke()``/session, but the controls it wraps are not).
        """

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
        return config_snippet_for("W2", name)

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


class InformationFlowControl(BoundaryControl):
    """W2 — deterministic information-flow control (PR4, primary W2 control).

    ``UntrustedEnvelopeControl`` (above) wraps untrusted text in a marker and
    hopes the model respects it — a PROBABILISTIC control; its own docstring
    says so ("depends on the target's model and system prompt respecting
    it"). This control instead LABELS the session as tainted the moment a
    read/content tool returns a non-error result, and REFUSES a sink call
    (a consequential or egress-classified tool) while the session is tainted
    — the model may still read and reason over the untrusted content, it
    simply cannot drive a sink from within the same session while it does.
    That is a control that gates the CALL, in code, not the text: the same
    shape as ``EgressAllowlistControl``/``ConfirmGateControl``, and the
    pattern Microsoft ships as FIDES (``agent_framework.security``,
    ``accepts_untrusted``/``max_allowed_confidentiality`` sink annotations).

    Session-scoped: taint is an instance attribute, cleared by
    :meth:`reset`, which :class:`ControlServerShim` calls once per session
    (see its constructor and ``BoundaryControl.reset``'s docstring for why a
    stateful control needs this and the other three don't).

    ``UntrustedEnvelopeControl`` is NOT retired — it is still the correct
    defence-in-depth layer underneath this one and remains directly usable
    (``make_control`` still exposes it as a class); this control is only the
    new PRIMARY answer to "what does `make_control('W2', ...)` return".
    """

    weakness = "W2"

    def __init__(
        self,
        *,
        read_tool_names: frozenset[str] | None = None,
        consequential_tools: frozenset[str] | None = None,
        egress_tools: frozenset[str] | None = None,
        accepts_untrusted: frozenset[str] | None = None,
    ) -> None:
        self._read_tool_names = read_tool_names
        self._consequential_tools = consequential_tools
        self._egress_tools = egress_tools
        self._accepts_untrusted = accepts_untrusted or frozenset()
        self._tainted = False

    def reset(self) -> None:
        self._tainted = False

    def _is_read_tool(self, name: str) -> tuple[bool, str]:
        return classify(name, declared=self._read_tool_names, hints=_READ_HINTS)

    def _is_sink_tool(self, name: str) -> tuple[bool, str]:
        """A sink is anything consequential OR egress-classified — the same
        two hint vocabularies ``ConfirmGateControl``/``EgressAllowlistControl``
        already use, so "what counts as a sink" stays one definition even
        though three different controls each act on it."""
        if self._consequential_tools is not None and name in self._consequential_tools:
            return True, "declared"
        if self._egress_tools is not None and name in self._egress_tools:
            return True, "declared"
        applies, reason = classify(name, declared=None, hints=_CONSEQUENTIAL_HINTS)
        if applies:
            return True, reason
        return classify(name, declared=None, hints=_EGRESS_HINTS)

    def _config_snippet(self, name: str) -> str:
        return config_snippet_for("W2", name)

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        if name in self._accepts_untrusted:
            return None
        if not self._tainted:
            return None
        applies, reason = self._is_sink_tool(name)
        if not applies:
            return None
        self._warn_fail_closed_once(name, reason, self._config_snippet(name))
        return ToolResult(
            name=name,
            content=(
                f"refused: {name!r} is a sink and untrusted content is in scope "
                "this session (W2 information-flow control)"
            ),
            isError=True,
        )

    def transform_result(self, name: str, result: ToolResult) -> ToolResult:
        if result.isError:
            return result
        applies, _reason = self._is_read_tool(name)
        if applies:
            self._tainted = True
        return result


class DescriptionIntegrityControl(BoundaryControl):
    """W1 — pin approved tool descriptions; refuse a call to a tool whose LIVE
    description no longer matches its pinned hash (PR5, primary W1 control).

    ``ToolDescriptionSanitizer`` (below) strips known smuggle FORMS from
    every description — a denylist filter, and its own docstring already
    names the gap: "Plain-prose cross-tool steering... is a known gap".
    Pinning is a strictly different, deterministic property: it doesn't try
    to recognise WHAT changed, only THAT it changed from what was approved —
    catching the sanitizer's exact blind spot (a rug-pull rewritten as
    ordinary prose has nothing for a denylist to match, but it still fails a
    hash comparison). Digests are computed over the RAW description, so a
    rug-pull is caught even where sanitizing would have cleaned the new text
    up and left nothing suspicious-looking behind.

    Architectural note: ``make_control``/``plan_twins`` build exactly ONE
    boundary control per weakness class per differential run, so this
    control does not ALSO run the sanitizer's stripping — it is the new
    single default for "what does ``make_control('W1', ...)`` return",
    exactly as ``InformationFlowControl`` (PR4) became W2's default while
    ``UntrustedEnvelopeControl`` stayed available, unchanged, underneath it.

    Refuses at ``intercept_call`` (a call), not by editing ``list_tools``'s
    output: there is no "drop this tool from the list" contract on
    ``transform_description`` (it must return SOME ``ToolDescription`` for
    the name it was given), so a mismatched tool is still LISTED — with its
    live (unpinned-safe) description — but every attempt to actually CALL it
    is refused, in code, before the inner tool runs.
    """

    weakness = "W1"

    def __init__(self, *, description_pins: dict[str, str] | None = None) -> None:
        self._pins = description_pins or {}
        self._violations: set[str] = set()

    def reset(self) -> None:
        self._violations = set()

    @staticmethod
    def digest(description: str) -> str:
        return hashlib.sha256(description.encode("utf-8")).hexdigest()

    def transform_description(self, tool: ToolDescription) -> ToolDescription:
        expected = self._pins.get(tool.name)
        if expected is not None and self.digest(tool.description) != expected:
            self._violations.add(tool.name)
        return tool

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        if name not in self._violations:
            return None
        return ToolResult(
            name=name,
            content=(
                f"refused: {name!r}'s live description does not match its pinned hash "
                "— possible rug-pull (the description changed after it was approved)"
            ),
            isError=True,
        )


class ToolDescriptionSanitizer(BoundaryControl):
    """W1 — sanitize tool descriptions before the planner sees them.

    Strips hidden ``<IMPORTANT>`` blocks, parenthetical instruction asides, and
    non-ASCII smuggling (unicode tag chars / confusables). The canonical
    tool-poisoning mitigation, applied to EVERY tool's description.

    PR5: demoted from ``make_control``'s W1 default in favour of
    ``DescriptionIntegrityControl`` (above) — this remains directly
    constructible as the probabilistic defence-in-depth layer underneath it.
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
        return config_snippet_for("W3", name)

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
    """W4 — require a server-minted, model-unforgeable token before a
    consequential action executes (PR5: stage/confirm, not a permanent block).

    Intercepts a call to a consequential-shaped tool. Without a valid
    ``confirm_token`` argument, the call is REFUSED and the refusal MINTS a
    token (an HMAC over the tool name + its other arguments, keyed by a
    secret generated fresh per control instance — the model cannot derive or
    guess it, only receive it from a real staged call). A retry of the SAME
    call carrying that exact token is allowed through, with the synthetic
    ``confirm_token`` key stripped before the inner tool ever sees it. This
    models the guarded twin's real two-step send/confirm shape, rather than
    the permanent block the previous version used as a stand-in for it — the
    token cannot be authored by a description, a prompt, or the model itself,
    only replayed back after the control already issued it.

    Classification is declared list -> name hint -> fail-closed default
    (DCR-0034); there is no structural-evidence tier here — unlike W3's URL
    check, "is this action consequential?" has no shape in the call arguments,
    only in what the tool DOES, so name classification is all there is short
    of an explicit declaration.

    Fidelity note, still real: the minted token rides through to the REAL
    inner tool's call as an ordinary argument (stripped only on the
    CONFIRMED path, per the ``arguments.pop`` below) — a third-party tool
    with an ``additionalProperties: false`` JSON-Schema could reject the
    intermediate confirm_token if that path were ever reached, though it
    never is, since the key is removed before the pass-through call. Session-
    scoped: a pending confirmation does not survive :meth:`reset`, so it
    cannot be replayed across two different exploit attempts sharing this
    control instance.
    """

    weakness = "W4"
    _TOKEN_ARG = "confirm_token"  # noqa: S105 -- an argument KEY name, not a credential

    def __init__(self, *, consequential_tools: frozenset[str] | None = None) -> None:
        self._consequential_tools = consequential_tools
        self._secret = secrets.token_bytes(32)
        #: tool name -> the one token currently valid for confirming it.
        self._pending: dict[str, str] = {}

    def reset(self) -> None:
        self._pending = {}

    def _classify(self, name: str) -> tuple[bool, str]:
        return classify(name, declared=self._consequential_tools, hints=_CONSEQUENTIAL_HINTS)

    def _config_snippet(self, name: str) -> str:
        return config_snippet_for("W4", name)

    def _sign(self, name: str, arguments: dict[str, Any]) -> str:
        payload = {k: v for k, v in arguments.items() if k != self._TOKEN_ARG}
        signable = f"{name}:{json.dumps(payload, sort_keys=True, default=str)}"
        return hmac.new(self._secret, signable.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def intercept_call(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        applies, reason = self._classify(name)
        if not applies:
            return None
        expected = self._sign(name, arguments)
        supplied = arguments.get(self._TOKEN_ARG)
        if supplied is not None and supplied == expected and self._pending.get(name) == expected:
            # Confirmed: strip the synthetic key (arguments is the same dict
            # object ControlServerShim.call_tool passes to the inner tool —
            # mutating it here is how a control can alter the pass-through
            # call, since intercept_call's contract is refuse-or-pass-through
            # unchanged, not refuse-or-rewrite) and let the real call happen.
            arguments.pop(self._TOKEN_ARG, None)
            del self._pending[name]
            return None
        self._warn_fail_closed_once(name, reason, self._config_snippet(name))
        self._pending[name] = expected
        return ToolResult(
            name=name,
            content=(
                f"confirmation_required: retry {name!r} with "
                f"{self._TOKEN_ARG}={expected!r} to confirm this consequential action "
                "(server-minted, single-use for this exact call)"
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
        for control in controls:
            control.reset()

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
    fetch_allowlist: tuple[str, ...] | None = None,
    consequential_tools: frozenset[str] | None = None,
    accepts_untrusted: frozenset[str] | None = None,
    description_pins: dict[str, str] | None = None,
) -> BoundaryControl:
    """Build the canonical boundary control for a weakness class (W1-W4).

    Raises for an unknown class so a caller can never silently get a no-op
    control (which would make a guard look load-bearing when nothing ran).

    ``fetch_allowlist=None`` (the default) falls back to
    ``DEFAULT_FETCH_ALLOWLIST`` — mirroring ``read_tool_names``/``egress_tools``,
    an explicitly-empty tuple from a caller (e.g. an unset ``control_config`` hint)
    must not silently replace the sensible default with an allow-nothing
    allowlist (DCR-0009).

    W1 (PR5): returns ``DescriptionIntegrityControl`` — a change-detection
    pin, not ``ToolDescriptionSanitizer``'s denylist filter. W2 (PR4): returns
    ``InformationFlowControl``, the primary/deterministic control — NOT
    ``UntrustedEnvelopeControl`` any more. Both demoted controls are still
    exported and directly constructible for a caller that wants the
    probabilistic defence-in-depth layer explicitly.
    """
    if weakness == "W1":
        return DescriptionIntegrityControl(description_pins=description_pins)
    if weakness == "W2":
        return InformationFlowControl(
            read_tool_names=read_tool_names,
            consequential_tools=consequential_tools,
            egress_tools=egress_tools,
            accepts_untrusted=accepts_untrusted,
        )
    if weakness == "W3":
        return EgressAllowlistControl(
            egress_tools=egress_tools,
            url_param=url_param,
            allowlist=fetch_allowlist if fetch_allowlist is not None else DEFAULT_FETCH_ALLOWLIST,
        )
    if weakness == "W4":
        return ConfirmGateControl(consequential_tools=consequential_tools)
    raise ValueError(f"no boundary control implemented for weakness {weakness!r}")
