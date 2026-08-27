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
_EGRESS_NAME_HINTS: tuple[str, ...] = (
    "fetch",
    "http",
    "download",
    "curl",
    "request",
    "egress",
    "web",
)

#: Parameter-NAME fragments that suggest the argument itself holds a network
#: destination, independent of the tool's own name (``web_fetch(url=...)`` and
#: ``notify(webhook=...)`` both match on the parameter, not just the tool).
#:
#: Matched as whole TOKENS (see :func:`hint_matches`), so ``webhook_url`` and
#: ``callbackUrl`` both hit. These are the UNAMBIGUOUS ones: a parameter carrying
#: any of these tokens is network-shaped whatever the surrounding tool does.
_DESTINATION_PARAM_HINTS_STRONG: tuple[str, ...] = (
    "url",
    "host",
    "endpoint",
    "uri",
    "link",
    "address",
    "domain",
    "webhook",
    "callback",
)

#: Fragments that name a destination WITHOUT saying what kind. `destination` and
#: `dest` were added in 0.8.3 to catch a live server exposing
#: ``export_report(destination=...)``, which had been reported as having no
#: network surface at all. They do catch it — and they also catch
#: ``copy_file(dest=...)`` and ``move_file(destination=...)``, the single most
#: common signature on a filesystem server, where the destination is a PATH.
#:
#: So they are matched only with corroboration (see :func:`_weak_hint_corroborated`):
#: something else about the tool has to say "network". That keeps the true
#: positive that motivated adding them while dropping the filesystem false ones.
_DESTINATION_PARAM_HINTS_WEAK: tuple[str, ...] = (
    "destination",
    "dest",
)

#: Back-compat alias: the union, for any caller that imported the old name.
_DESTINATION_PARAM_HINTS: tuple[str, ...] = (
    *_DESTINATION_PARAM_HINTS_STRONG,
    *_DESTINATION_PARAM_HINTS_WEAK,
)

#: Tokens that make a WEAK-hint parameter a reference to a thing rather than the
#: thing: ``destination_id`` is a key into someone's address book, not an address.
#: Deliberately not applied to the strong hints — ``host_name`` and ``url_key``
#: are still destinations, and a veto list that swallowed them would trade a rare
#: false positive for a common false negative.
_REFERENCE_TOKENS: frozenset[str] = frozenset({"id", "ids"})


#: Suffixes that make a dotted string a FILENAME rather than a hostname. Only
#: consulted on the discovery-report path — see :func:`_is_reportable_destination`.
#:
#: **Every entry here must be a file extension that is NOT also a real TLD.**
#: ``.md``, ``.py`` and ``.zip`` were originally in this list and have been
#: removed: they are the ccTLDs for Moldova and Paraguay and a Google gTLD, so a
#: genuine destination like ``notify.md`` was being suppressed from the report as
#: though it were a document. The case that motivated the list — a schema default
#: of ``README.md.gz`` — still suppresses, on ``.gz``, which is not a TLD.
#: Check https://data.iana.org/TLD/tlds-alpha-by-domain.txt before adding one.
_FILENAME_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".yaml",
    ".yml",
    ".txt",
    ".csv",
    ".xml",
    ".html",
    ".htm",
    ".log",
    ".gz",
    ".tar",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".js",
    ".ts",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sql",
    ".db",
    ".sqlite",
)


def _is_reportable_destination(sample: str) -> bool:
    """:func:`looks_like_destination`, recalibrated for a static REPORT.

    The permissive form is right for the live boundary control, where the cost
    of a false positive is a refusable call and the cost of a false negative is
    a silent SSRF. It is wrong here: ``_HOSTNAME_RE`` matches any dotted
    alphanumeric string, so a schema default of ``"README.md.gz"`` reads as a
    hostname and ``mylonite check`` reports the tool as taking a network
    destination. On a static report a false positive costs operator trust, which
    is the scarcer resource -- so a bare dotted string that looks like a filename
    is not reported.

    An explicit scheme or an IP literal is always reportable: those are
    unambiguous, whatever the rest of the string looks like.
    """
    candidate = sample.strip()
    if "://" in candidate:
        return True
    host = candidate.split("/", 1)[0].lower()
    if host.count(":") == 1:
        head, _, tail = host.partition(":")
        if tail.isdigit():
            host = head
    if host.endswith(_FILENAME_SUFFIXES):
        return False
    return looks_like_destination(candidate)


def _weak_hint_corroborated(tool_name: str, pspec: Mapping[str, Any], blurb: str) -> bool:
    """Does anything besides the parameter's name say this destination is a URL?

    ``destination`` and ``dest`` name a destination without saying what kind, and
    the commonest tool in the MCP ecosystem carrying them — ``copy_file(dest)``,
    ``move_file(destination)`` — means a filesystem path. Corroboration is any of:

    * the JSON-schema ``format`` is ``uri``/``url`` — the schema itself says so;
    * the tool's own name is egress-shaped (``_EGRESS_NAME_HINTS``, plus the
      send-shaped verbs that move data OUT without fetching anything);
    * the tool or parameter description names a scheme or a network noun.

    The live server that motivated adding these hints, ``export_report``, is
    caught by the last two: the verb exports, and the description reads *"Export
    a report to a destination. Default destination: https://..."*.
    """
    fmt = pspec.get("format")
    if isinstance(fmt, str) and fmt.lower() in {"uri", "url", "iri"}:
        return True
    lowered_name = tool_name.lower()
    if any(hint in lowered_name for hint in (*_EGRESS_NAME_HINTS, *_SEND_NAME_HINTS)):
        return True
    text = blurb.lower()
    if "://" in text:
        return True
    return any(word in text for word in _NETWORK_WORDS)


#: Verbs that move data OUT to somewhere. `_EGRESS_NAME_HINTS` is fetch-shaped
#: (it describes pulling something in); these are the mirror image, and a
#: `destination` on one of them is a place data is sent, not a file path.
_SEND_NAME_HINTS: tuple[str, ...] = (
    "export",
    "upload",
    "publish",
    "post",
    "send",
    "notify",
    "forward",
    "sync",
    "webhook",
)

#: Network nouns in a description, used only to corroborate a weak name hint.
_NETWORK_WORDS: tuple[str, ...] = (
    "url",
    "endpoint",
    "webhook",
    "http",
    "https",
    "api",
    "server",
    "remote",
    "hostname",
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
                if isinstance(sample, str) and _is_reportable_destination(sample):
                    best = (pname, "schema default")
                    break
            if best is not None:
                break
            # Token match, not exact equality. `pname.lower() in _DESTINATION_PARAM_HINTS`
            # compared the WHOLE parameter name against each hint, so `webhook_url`
            # matched neither "webhook" nor "url" and `destination` matched nothing
            # at all. A live server whose only egress tools were
            # `export_report(destination=...)` and `schedule_report(webhook_url=...)`
            # was therefore reported as having no network surface -- and, because
            # `seed_synth._egress_candidates` delegates here, no W3 seed was ever
            # synthesised for it either. `hint_matches` is the same tokeniser
            # `classify` already uses for exactly this question.
            if hint_matches(pname, _DESTINATION_PARAM_HINTS_STRONG):
                best = best or (pname, "name hint")
            elif hint_matches(pname, _DESTINATION_PARAM_HINTS_WEAK) and not (
                name_tokens(pname) & _REFERENCE_TOKENS
            ):
                # Ambiguous on its own -- `dest` is as likely to be a filesystem
                # path as a URL. Report only when something else about the tool
                # says network; see `_weak_hint_corroborated`.
                blurb = f"{getattr(tool, 'description', '') or ''} {pspec.get('description') or ''}"
                if _weak_hint_corroborated(name, pspec, blurb):
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


def _hint(annotations: Mapping[str, Any] | None, key: str) -> bool | None:
    """One MCP annotation hint as a tri-state: True / False / not declared."""
    if not annotations:
        return None
    value = annotations.get(key)
    return value if isinstance(value, bool) else None


def annotation_is_sink(annotations: Mapping[str, Any] | None) -> bool | None:
    """Does the server say this tool MODIFIES its environment?

    ``readOnlyHint`` is MCP's own answer to the question W2/W4 ask by guessing
    from a name. Per the spec ``readOnlyHint=true`` means "the tool does not
    modify its environment", so it is the one annotation that can positively
    clear a tool. ``destructiveHint`` is meaningful "only when readOnlyHint is
    false", so a destructive tool is a sink regardless.

    Returns ``None`` when the server declared nothing, leaving the caller on the
    name-hint / fail-closed tiers exactly as before.
    """
    read_only = _hint(annotations, "readOnlyHint")
    if read_only is True:
        return False
    if _hint(annotations, "destructiveHint") is True:
        return True
    if read_only is False:
        return True
    return None


def annotation_is_egress(annotations: Mapping[str, Any] | None) -> bool | None:
    """Does the server say this tool reaches an OPEN WORLD of external entities?

    That is MCP's framing of exactly what W3 gates. The spec's own example is
    the distinction this needs: "the world of a web search tool is open, whereas
    that of a memory tool is not".
    """
    return _hint(annotations, "openWorldHint")


def annotation_is_read(annotations: Mapping[str, Any] | None) -> bool | None:
    """Does the server say this tool only READS? (the W2 taint-source question)"""
    return _hint(annotations, "readOnlyHint")


def uniform_default_annotations(tools: Sequence[Any]) -> bool:
    """True when EVERY tool carries the IDENTICAL, non-empty annotation block.

    This is the signature of an SDK that serialises the MCP spec's conservative
    defaults on behalf of an author who declared nothing — observed with
    ``mcp-go``, which stamps ``destructiveHint=true, openWorldHint=true`` on every
    tool of a server whose source sets no annotations at all. Trusting those as
    tier-2 evidence turns every read-only tool into a destructive, open-world
    sink. A server that annotates MEANINGFULLY
    varies its annotations per tool (read_file readOnly vs write_file
    destructive), so a uniform block across the whole surface is the tell that
    the annotations are defaults, not declarations.
    """
    blocks = []
    for t in tools:
        ann = getattr(t, "annotations", None)
        if not ann:
            return False  # a tool with no annotation -> not the uniform-default shape
        blocks.append(tuple(sorted((k, str(v)) for k, v in dict(ann).items() if k != "title")))
    return len(blocks) > 1 and len(set(blocks)) == 1


def neutralize_uniform_default_annotations(tools: Sequence[Any]) -> list[Any]:
    """Return ``tools`` with annotations CLEARED when they are uniform-default.

    A no-op (returns the input unchanged) unless :func:`uniform_default_annotations`
    is true, so a server that annotates meaningfully is never touched. When it
    fires, the tools are treated as if the server said nothing — falling back to
    name-hint / structural / fail-closed classification, which is the honest
    handling of an SDK default.
    """
    if not uniform_default_annotations(tools):
        return list(tools)
    out = []
    for t in tools:
        try:
            out.append(t.model_copy(update={"annotations": None}))
        except Exception:
            out.append(t)
    return out


def annotation_behaviour_mismatch(
    annotations: Mapping[str, Any] | None, *, observed_write: bool
) -> str | None:
    """A human-readable mismatch between a tool's annotation and its behaviour.

    The MCP spec is explicit that annotations "are not guaranteed to provide a
    faithful description of tool behavior" and that clients "should never make
    tool use decisions based on ToolAnnotations received from untrusted
    servers". A server that annotates a tool ``readOnlyHint=true`` and then
    observably writes is therefore not a classification bug to work around — it
    is a defect in the target worth reporting, and one only a system that
    actually executes the tool (as Mylonite does) is positioned to catch.
    """
    if observed_write and _hint(annotations, "readOnlyHint") is True:
        return (
            "tool is annotated readOnlyHint=true but was observed modifying state — "
            "the annotation misrepresents the tool's behaviour, so any client "
            "trusting it (to skip an approval prompt, say) is misled"
        )
    return None


#: Splits on any non-alphanumeric run AND on a camelCase boundary, so
#: ``"send_email"`` -> {"send", "email"} and ``"sendEmail"`` -> {"send", "email"}.
#: Mirrors ``tool_roles._TOKEN_SPLIT_RE`` — the two modules answer the same
#: question ("does this hint describe this tool?") and must not disagree.
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def name_tokens(name: str) -> set[str]:
    """Lowercase word tokens of a tool name."""
    with_boundaries = _CAMEL_BOUNDARY_RE.sub("_", name)
    return {t for t in _TOKEN_SPLIT_RE.split(with_boundaries.lower()) if t}


def hint_matches(name: str, hints: tuple[str, ...]) -> bool:
    """True when a hint is a whole TOKEN of ``name`` — never a substring.

    Substring matching classified ``get_postal_code`` as consequential (``post``)
    and ``increatement_counter`` likewise (``create``). Because every control
    fails closed, the *decision* was unchanged — but ``reason`` was not, and
    ``reason`` is what ``consequential_tool_names`` filters on to build the
    ``mylonite check`` report, so a name-hint false positive surfaced to the user
    as a confirmed consequential tool. ``tool_roles`` already tokenised; this is
    the same rule, applied in the module the live controls actually call.
    """
    return bool(name_tokens(name) & set(hints))


def classify(
    name: str,
    *,
    declared: frozenset[str] | None,
    hints: tuple[str, ...],
    annotation_says: bool | None = None,
) -> tuple[bool, str]:
    """Four-tier classification: declared, MCP annotation, name token, fail-closed.

    Returns ``(applies, reason)``. ``reason`` is ``"declared"`` when an explicit
    ``ControlConfig`` list decided the answer — the operator said so, and a
    caller should never warn about that. ``"name hint"`` and ``"fail-closed
    default"`` both mean ``applies`` is ``True`` on a tool the operator never
    named; callers use the distinction only for the message they log, not for
    the decision itself, which is the whole point of failing closed
    (DCR-0033/0034/0035): an unrecognised name is guarded exactly like a
    recognised one, not silently passed through.

    ``annotation_says`` carries a verdict derived from the target's own MCP
    ``ToolAnnotations`` (``readOnlyHint``/``destructiveHint``/``openWorldHint``)
    — the protocol's own risk vocabulary, which Mylonite previously ignored
    entirely in favour of guessing from English words. It outranks the name
    hints because it is a statement by the server about its own tool, and is
    outranked by ``declared`` because the MCP spec is explicit that annotations
    are untrusted hints: "Clients should never make tool use decisions based on
    ToolAnnotations received from untrusted servers." So it informs
    classification, and an operator declaration still overrides it.

    ``annotation_says=False`` is load-bearing, not merely the absence of
    evidence: a server stating a tool is read-only is the one signal that can
    stop the fail-closed default from guarding a tool. That is also why the
    mismatch is worth reporting separately — a tool annotated read-only that
    observably writes is a finding about the target, not a classification bug.
    """
    if declared is not None:
        return name in declared, "declared"
    if annotation_says is not None:
        return annotation_says, "mcp tool annotation"
    if hint_matches(name, hints):
        return True, "name hint"
    return True, "fail-closed default"
