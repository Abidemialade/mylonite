"""Fail-closed tool classification shared by every boundary control.

All four controls in ``control_shim`` previously asked "is this tool egress /
consequential / a read?" of a hardcoded substring list, and answered "no — pass
it through" for anything unmatched. That is a control that fails OPEN on
ambiguity (DCR-0032/0033/0034/0035), in the module that implements the very
mitigations the differential oracle uses to prove a fix works.

Classification order, most-authoritative first:

1. An explicit list from the target's ``ControlConfig`` — the operator said so.
2. Structural evidence from the tool's own arguments (a URL-shaped value makes a
   call egress regardless of its name).
3. The name hints — a convenience, never the gate.
4. Otherwise: **guarded**. An unrecognised tool is treated as in-scope for the
   control, because the cost of over-guarding is a visibly-refused call the
   operator can allowlist, while the cost of under-guarding is a scan that says
   a vulnerable target is clean.

``classify`` implements tiers 1/3/4 (declared list, name hint, fail-closed
default) for any control whose question is answered from the tool's NAME alone
(W2's "is this a read tool?", W4's "is this consequential?"). ``url_values`` /
``looks_like_destination`` implement the tier-2 structural check that only W3
(egress) has an analogue for: a network destination is a network destination
regardless of what the tool is called.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

# A bare hostname / domain: at least one label separator, label characters only.
# Deliberately permissive (this is a "could this be a destination?" heuristic
# feeding a REFUSAL path, not a strict RFC 1123 validator) — a false positive
# here costs a refusable call, a false negative costs a silent SSRF (DCR-0032).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def looks_like_destination(value: object) -> bool:
    """True for a URL, a bare hostname, or an IP literal.

    ``web_fetch(host="attacker.example")`` has no scheme, so the old
    ``"://" in value`` check (``control_shim._looks_like_url``) missed it
    entirely and the allowlist never ran (DCR-0032). This also accepts a bare
    IP literal and a ``host:port`` / ``host/path`` shape, so the structural
    check does not depend on the argument being a full URL.

    A single, dot-less label (``note-42``, ``hello``) is NOT treated as a
    destination — most tool arguments that look like that are ids or words,
    not hosts, and the false-positive rate would swamp the real signal. The
    one dot-less exception is ``localhost``: it is the single most common
    egress-allowlist entry (``DEFAULT_FETCH_ALLOWLIST``), and a control that
    cannot recognise its own allowlist's own default entry as a destination
    can never pass a call to it, defeating the allowlist's purpose.
    """
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    if "://" in candidate:
        return True
    # Peel off a trailing path and a trailing port so `attacker.example/exfil`
    # and `attacker.example:8080` are still recognised by their host part.
    host = candidate.split("/", 1)[0]
    if host.count(":") == 1:
        head, _, tail = host.partition(":")
        if tail.isdigit():
            host = head
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


def url_values(arguments: Mapping[str, Any]) -> list[str]:
    """Every argument value that could be a network destination.

    Walks nested lists and dicts, and accepts a scheme-less hostname (a bare
    ``attacker.example`` in a ``host=`` argument is still a destination). The
    old single-value extractor (``control_shim.EgressAllowlistControl._url_in``)
    returned ``None`` for both shapes — a list-valued argument and a
    scheme-less value — and ``None`` short-circuited the allowlist to
    pass-through (DCR-0032).
    """
    found: list[str] = []

    def _walk(value: object) -> None:
        if isinstance(value, str):
            if looks_like_destination(value):
                found.append(value)
        elif isinstance(value, Mapping):
            for v in value.values():
                _walk(v)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for v in value:
                _walk(v)

    for v in arguments.values():
        _walk(v)
    return found


#: Tool-NAME fragments that suggest a tool performs outbound network egress —
#: the same vocabulary ``control_shim.py``'s live ``_EGRESS_HINTS`` uses to
#: classify a W3 call, duplicated here (rather than imported) so this
#: discovery-only module has no dependency on the boundary-control module.
_EGRESS_NAME_HINTS: tuple[str, ...] = ("fetch", "http", "download", "curl", "request", "egress", "web")

#: Parameter-NAME fragments that suggest the argument itself holds a network
#: destination, independent of the tool's own name (``web_fetch(url=...)`` and
#: ``notify(webhook=...)`` both match on the parameter, not just the tool).
_DESTINATION_PARAM_HINTS: tuple[str, ...] = (
    "url",
    "host",
    "endpoint",
    "uri",
    "link",
    "address",
    "domain",
    "webhook",
)


def destination_tools(tools: Sequence[Any]) -> list[tuple[str, str, str]]:
    """``(tool_name, param_name, reason)`` for tools that plausibly egress.

    A DISCOVERY report, not a fail-closed gate: a tool with no destination-shaped
    signal at all is simply omitted, never flagged by default (unlike
    :func:`classify`'s runtime "fail-closed default" tier, which is calibrated
    for a live boundary control refusing an unrecognised call — flagging every
    unmatched tool here would bury the real signal under noise).

    ``reason`` is one of:

    * ``"schema default"`` — a string parameter's JSON-schema ``default`` or
      ``example`` value is itself destination-shaped (:func:`looks_like_destination`)
      — structural evidence, independent of any name.
    * ``"name hint"`` — the tool's own name matches :data:`_EGRESS_NAME_HINTS`,
      or the parameter's name matches :data:`_DESTINATION_PARAM_HINTS`.

    Each tool is reported at most once, at its highest-confidence match
    (schema default over name hint).
    """
    found: list[tuple[str, str, str]] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        if not name:
            continue
        schema = getattr(tool, "json_schema", {}) or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        if not isinstance(props, dict):
            continue
        best: tuple[str, str] | None = None
        for pname, pspec in props.items():
            if not isinstance(pspec, dict) or pspec.get("type") != "string":
                continue
            for sample_key in ("default", "example"):
                sample = pspec.get(sample_key)
                if isinstance(sample, str) and looks_like_destination(sample):
                    best = (pname, "schema default")
                    break
            if best is not None:
                break
            if pname.lower() in _DESTINATION_PARAM_HINTS:
                best = best or (pname, "name hint")
        if best is None and any(hint in name.lower() for hint in _EGRESS_NAME_HINTS):
            # The tool's own name hints at egress even with no matching param name
            # (e.g. a single unnamed positional-style "target" argument scored
            # differently) -- fall back to flagging the tool without a specific
            # param, so the operator still sees it.
            best = ("(unspecified)", "name hint")
        if best is not None:
            found.append((name, best[0], best[1]))
    return found


def classify(
    name: str,
    *,
    declared: frozenset[str] | None,
    hints: tuple[str, ...],
) -> tuple[bool, str]:
    """Three-tier name classification: declared list, then hint, then fail-closed.

    Returns ``(applies, reason)``. ``reason`` is ``"declared"`` when an explicit
    ``ControlConfig`` list decided the answer — the operator said so, and a
    caller should never warn about that. ``"name hint"`` and ``"fail-closed
    default"`` both mean ``applies`` is ``True`` on a tool the operator never
    named; callers use the distinction only for the message they log, not for
    the decision itself, which is the whole point of failing closed
    (DCR-0033/0034/0035): an unrecognised name is guarded exactly like a
    recognised one, not silently passed through.
    """
    if declared is not None:
        return name in declared, "declared"
    lowered = name.lower()
    if any(hint in lowered for hint in hints):
        return True, "name hint"
    return True, "fail-closed default"
