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
