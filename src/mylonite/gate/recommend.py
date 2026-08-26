"""Structural recommendation engine (Workstream D).

Turns a proven finding into a TARGET-SPECIFIC, deterministic recommendation
that names the operator's actual tool and the actual argument that landed the
exploit, instead of the class-level markdown + imaginary-function diff
``gate/mitigation.py`` renders today.

Two axes stay orthogonal — conflating them is the one mistake that would undo
the whole point of this module:

* **confidence** — did we name the right tool/argument? Derived from how the
  tool was classified (declared > structural evidence > name hint >
  fail-closed) and whether the effect probe confirmed. Varies per finding.
* **tier** — does the prescribed control actually work? ``deterministic``
  gates the call in code; ``probabilistic`` changes what the model sees (and
  can be talked around); ``detective`` catches drift after the fact. This is
  a property of the CONTROL, not the finding.

Pure and deterministic. No I/O, no LLM (importing ``mylonite.scan._llm`` here
is a defect — see ``tests/gate/test_recommend.py``'s import-boundary test).
``recommend()`` never raises: any missing/malformed input degrades into
``Recommendation.degraded`` and a lowered confidence, because a finding that
already cost the differential oracle real work must still produce SOMETHING
usable, not a traceback.

Not yet wired into ``build_pr_body`` (that is PR2) — this module is
self-contained and independently testable via its own ``render_markdown``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any, Final, Literal

from mylonite._redaction import redact, redact_value
from mylonite.contracts import ExploitRecord, ValidationReport
from mylonite.gate.localize import Localization, localize
from mylonite.scan import control_shim
from mylonite.scan._control_primitives import host_allowed
from mylonite.scan.predicate_primitives import executed_calls, tool_call_sequence
from mylonite.scan.tool_classifier import looks_like_destination

ControlTier = Literal["deterministic", "probabilistic", "detective"]
Confidence = Literal["high", "medium", "low"]
EvidenceSource = Literal["effect_trace", "mcp_trace_planner", "payload", "tool_surface"]

#: Max characters of a redacted argument value quoted in a recommendation.
#: A trace result can be a whole file read; a recommendation is not the
#: place to reproduce it.
_MAX_QUOTE = 120


@dataclass(frozen=True)
class Evidence:
    """One quoted, REDACTED fact lifted from the recorded trace.

    ``value`` is already ``redact()``-ed and truncated to ``_MAX_QUOTE`` by
    the derivation helpers below — never construct one with a raw value.
    """

    tool: str
    argument: str | None
    value: str | None
    occurrence: int | None
    executed: bool
    source: EvidenceSource
    note: str | None = None


@dataclass(frozen=True)
class CodeSketch:
    """A framework-neutral (or framework-specific, from PR10 on) code sketch.

    Deliberately never a ``diff`` — a diff asserts we know the file and the
    surrounding lines. We do not: a remote MCP tool has no repo file, and
    even a local one is code we have never read.
    """

    language: Literal["python", "typescript", "pseudocode"]
    framework: str | None
    body: str


@dataclass(frozen=True)
class Prescription:
    """One control to implement. ``prescriptions[0]`` is the primary."""

    control_id: str
    tier: ControlTier
    headline: str
    rationale: str
    invariant: str | None
    config_snippet: str | None
    code_sketch: CodeSketch | None
    citations: tuple[str, ...] = ()
    residual: tuple[str, ...] = ()


@dataclass(frozen=True)
class Recommendation:
    """The complete structural recommendation for one exploit."""

    weakness_class: str
    localization: Localization
    evidence: tuple[Evidence, ...]
    prescriptions: tuple[Prescription, ...]
    confidence: Confidence
    confidence_reason: str
    proven: bool
    proven_layer: Literal["server", "boundary", "none"]
    degraded: tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetContext:
    """Everything about the operator's target a recommendation may quote.

    PURE DATA: no adapter, no launch, no filesystem, no network. Built by the
    plugin side (``plugins/_mcp/target_file.target_context_for``, PR2) from a
    ``TargetSpec`` plus an optional live tool inventory; every field is
    optional because a recommendation must degrade gracefully, never require
    plumbing a caller doesn't have.
    """

    target_id: str
    transport: str = "stdio"
    launch_command: str | None = None
    control_config: Any | None = None
    system_prompt: str | None = None
    tools: tuple[Any, ...] = ()
    framework: str | None = None


# --- citations ----------------------------------------------------------


@dataclass(frozen=True)
class Citation:
    title: str
    url: str
    retrieved_on: str
    quote: str


#: Every entry here was fetched and read directly (not taken from secondary
#: summary) before being added. Do not add an entry without doing the same —
#: a prescription's citation is a claim about a primary source, and a wrong
#: one costs more trust than having none.
_CITATIONS: dict[str, Citation] = {
    "mcp-spec-2026-07-28-tool-safety": Citation(
        title="Model Context Protocol specification (2026-07-28) — Security and Trust & Safety",
        url="https://modelcontextprotocol.io/specification/2026-07-28",
        retrieved_on="2026-08-23",
        quote=(
            "descriptions of tool behavior such as annotations should be considered "
            "untrusted, unless obtained from a trusted server"
        ),
    ),
    "mcp-spec-2026-07-28-consent": Citation(
        title="Model Context Protocol specification (2026-07-28) — Security and Trust & Safety",
        url="https://modelcontextprotocol.io/specification/2026-07-28",
        retrieved_on="2026-08-23",
        quote="Hosts must obtain explicit user consent before invoking any tool",
    ),
    "fides-ms-learn": Citation(
        title="Agent Security with FIDES (Microsoft Learn, updated 2026-08-10)",
        url="https://learn.microsoft.com/en-us/agent-framework/agents/security",
        retrieved_on="2026-08-23",
        quote=(
            "The model is still in charge of deciding what to do, but the framework is "
            "in charge of deciding what is allowed to happen. That split is what lets "
            "the security guarantee be deterministic instead of probabilistic."
        ),
    ),
}


def resolve_citation(citation_id: str) -> Citation:
    """Look up a citation by id. Raises KeyError for an unregistered id.

    Every ``Prescription.citations`` entry must resolve here — see
    ``tests/gate/test_recommend.py::test_every_citation_id_resolves`` — so a
    citation can never be a bare string nobody checked.
    """
    return _CITATIONS[citation_id]


# --- evidence derivation --------------------------------------------------


def _quote(value: Any) -> str:
    return redact(str(value))[:_MAX_QUOTE]


def _tool_calls_for(effect_trace: str, tool: str) -> list[tuple[int, dict[str, Any]]]:
    """Every executed occurrence of ``tool``, as ``(index, args)`` pairs."""
    return [(i, args) for i, name, args in executed_calls(effect_trace) if name == tool]


def _has_any_trace_entries(blob: str) -> bool:
    """True iff ``blob`` parses to a NON-EMPTY JSON list — i.e. the trace has
    at least one entry of any kind (executed, deferred, or errored).

    Deliberately NOT ``bool(blob)``: an empty-but-valid trace (the literal
    string ``"[]"``) is truthy as a Python string, so a naive truthiness
    check on the raw metadata value treats "recorded zero entries" the same
    as "genuinely has entries" — the exact gap that let a finding with no
    real evidence at all still read as un-degraded confidence. Malformed
    JSON or a non-list value is treated as "no entries", matching every
    other trace-parsing helper's fail-quiet contract (never raises).
    """
    try:
        parsed = json.loads(blob or "[]")
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, list) and len(parsed) > 0


def _destination_arg(args: dict[str, Any]) -> tuple[str, Any] | None:
    """First ``(arg_name, value)`` whose value looks like a network destination."""
    for key, value in args.items():
        if isinstance(value, str) and looks_like_destination(value):
            return key, value
    return None


def _hostname_of(value: str) -> str:
    """The bare hostname of a (possibly scheme-less) destination value.

    ``fetch_allowlist:`` entries are bare hostnames (``host_allowed`` checks
    ``urlparse(...).hostname`` against them, mirroring the same scheme-less
    normalisation it applies to the value being checked) — a full URL in the
    allowlist would never match. Falls back to the raw value if it doesn't
    parse as a hostname at all, so a malformed destination degrades rather
    than silently disappearing from the allowlist we're building.
    """
    from urllib.parse import urlparse

    candidate = value if "://" in value else f"//{value}"
    try:
        return urlparse(candidate).hostname or value
    except ValueError:
        return value


def _evidence_for_tool(
    exploit: ExploitRecord,
    tool: str,
    *,
    destination_only: bool = False,
    known_safe: tuple[str, ...] = control_shim.DEFAULT_FETCH_ALLOWLIST,
) -> Evidence:
    """Build one Evidence entry for ``tool`` from whatever trace data exists.

    Prefers ``effect_trace`` (execution-aware: is_error / deferred-marker
    rules already applied by ``executed_calls``) over the raw planner trace,
    and degrades to a payload-only Evidence with ``executed=False`` when
    neither trace exists — never raises.

    When ``destination_only`` and the tool executed more than once (a target
    can call the same tool for both a benign purpose and the attack), picks
    the FIRST occurrence whose destination is NOT in ``known_safe`` — the
    off-allowlist one — rather than blindly the last occurrence, which could
    pick a benign call and misidentify the evidence. Falls back to the last
    occurrence if every destination looks safe (nothing to distinguish on).
    """
    effect_trace = exploit.response.metadata.get("effect_trace", "")
    occurrences = _tool_calls_for(effect_trace, tool) if effect_trace else []
    if occurrences:
        occurrence, args = occurrences[-1]
        if destination_only:
            suspicious = next(
                (
                    (i, a, _destination_arg(a))
                    for i, a in occurrences
                    if (d := _destination_arg(a)) is not None and not host_allowed(d[1], known_safe)
                ),
                None,
            )
            if suspicious is not None:
                occurrence, args, _ = suspicious
        dest = _destination_arg(args) if destination_only else None
        if dest is not None:
            arg_name, value = dest
            return Evidence(
                tool=tool,
                argument=arg_name,
                value=_quote(value),
                occurrence=occurrence,
                executed=True,
                source="effect_trace",
            )
        # No destination-shaped arg identified; still real evidence that the
        # tool executed — quote the whole arg dict as the shape. MUST go
        # through redact_value() (key-name-aware) first, not straight into
        # _quote()/redact() (shape-only): redact() only masks a value that is
        # itself long/prefixed enough to look secret-shaped. A short credential
        # under an unambiguous key -- {"password": "abc123"} -- would  # pragma: allowlist secret
        # otherwise ride through untouched into the PR body / SARIF / JSON bundle.
        return Evidence(
            tool=tool,
            argument=None,
            value=_quote(redact_value(args)) if args else None,
            occurrence=occurrence,
            executed=True,
            source="effect_trace",
        )
    return Evidence(
        tool=tool,
        argument=None,
        value=None,
        occurrence=None,
        executed=tool in exploit.response.tool_calls,
        source="payload",
        note="no effect_trace recorded for this tool call",
    )


def _benign_destinations(
    exploit: ExploitRecord, tool: str, *, exclude_occurrence: int | None
) -> list[str]:
    """Other destinations' HOSTNAMES the SAME tool reached in this run, for
    seeding an allowlist from real traffic rather than a guess (W3's
    differentiator). Returns bare hostnames — the shape ``fetch_allowlist:``
    and ``host_allowed`` both expect, not full URLs.

    Re-derives the excluded HOSTNAME from the flagged occurrence's own RAW
    trace argument (looked up by ``exclude_occurrence``'s index), never from
    the caller's (redacted-and-truncated-to-``_MAX_QUOTE``) ``Evidence.value``
    — a >120-character attacker destination whose hostname portion itself
    ran past the truncation point would otherwise fail to string-match its
    own untruncated occurrence elsewhere in the trace, letting the
    attacker's own host leak into the "benign" allowlist this function
    seeds. Excluding by re-derived HOSTNAME (not just the one flagged
    occurrence's index) also correctly drops every OTHER occurrence of that
    same attacker host the tool was called with in this run, not only the
    specific occurrence that happened to be picked as evidence.
    """
    effect_trace = exploit.response.metadata.get("effect_trace", "")
    if not effect_trace:
        return []
    occurrences = _tool_calls_for(effect_trace, tool)
    exclude_host: str | None = None
    if exclude_occurrence is not None:
        for occurrence, args in occurrences:
            if occurrence != exclude_occurrence:
                continue
            dest = _destination_arg(args)
            if dest is not None:
                exclude_host = _hostname_of(str(dest[1]))
            break
    out: list[str] = []
    for _, args in occurrences:
        dest = _destination_arg(args)
        if dest is None:
            continue
        host = _hostname_of(str(dest[1]))
        if host != exclude_host and host not in out:
            out.append(host)
    return out


# --- confidence ------------------------------------------------------------


def _confidence_for_tool(
    target: TargetContext | None, declared_names: tuple[str, ...], tool: str, evidence: Evidence
) -> tuple[Confidence, str]:
    """Confidence table (kept as ONE function so it stays a single source of
    truth): declared > structural evidence > name hint > fail-closed default,
    downgraded by one tier if the effect probe never confirmed."""
    if target is not None and tool in declared_names:
        base: Confidence = "high"
        reason = "declared in control_config"
    elif evidence.argument is not None:
        base = "high"
        reason = "a destination/argument identified structurally in the trace"
    elif evidence.executed:
        base = "medium"
        reason = "the tool executed, but no destination/argument was identified structurally"
    else:
        base = "low"
        reason = "fail-closed default (no declaration, no trace evidence)"
    return base, reason


_DEGRADE_TABLE: dict[Confidence, Confidence] = {"high": "medium", "medium": "low", "low": "low"}


def _degrade(base: Confidence) -> Confidence:
    return _DEGRADE_TABLE[base]


# --- language / framework (Workstream D6, PR10) ------------------------------

#: D2 boundary: language is inferred ONLY from the launch command a target.yaml
#: already declares — never from reading pyproject.toml/package.json (charter
#: risk, low marginal value over a declared field). Matched against the
#: command's basename (path prefix and extension stripped), so `/usr/bin/uv`,
#: `uv.exe`, and `uv` all match the same way.
_PYTHON_COMMAND_NAMES: Final = frozenset({"python", "python3", "uv", "uvx", "poetry"})
_TYPESCRIPT_COMMAND_NAMES: Final = frozenset({"node", "npx", "bun", "tsx"})


def _infer_language(launch_command: str | None) -> Literal["python", "typescript", "pseudocode"]:
    """Infer a code sketch's language from the target's declared launch command.

    Falls back to ``"pseudocode"`` for an undeclared or unrecognised command —
    never guesses, since a wrong language label is worse than an honestly
    generic sketch. ``python3.11``/``python3.12``-style versioned binaries
    match via the ``python`` prefix.

    ``launch_command`` is ``TargetFile.command`` — documented as the bare
    executable/path, with arguments living separately in ``args:`` — so this
    does NOT split on whitespace looking for a first token: a Windows path
    containing a space (``C:\\Program Files\\nodejs\\node.exe``) would
    otherwise be cut at the space and misclassified.
    """
    if not launch_command or not launch_command.strip():
        return "pseudocode"
    # Split on BOTH separators regardless of the host OS running Mylonite —
    # `PurePath`'s OS-native flavour would silently fail to split a
    # backslash-separated Windows path when Mylonite itself runs on Linux CI
    # (a plain PurePosixPath does not treat "\\" as a separator at all).
    tail = launch_command.strip().replace("\\", "/").rsplit("/", 1)[-1]
    name = PurePath(tail).stem.lower()
    if name in _PYTHON_COMMAND_NAMES or name.startswith("python"):
        return "python"
    if name in _TYPESCRIPT_COMMAND_NAMES:
        return "typescript"
    return "pseudocode"


def _framework_note(framework: str | None, *, comment: str = "#") -> str | None:
    """A one-line pointer at the operator's declared framework, or ``None``.

    Deliberately does NOT fabricate a framework's actual hook/decorator
    syntax — nine of eleven surveyed agent frameworks expose SOME blocking
    pre-tool-call hook, but the exact API differs per framework and per
    version, and an invented-but-wrong snippet is worse than the honest,
    framework-neutral ``before_tool_call`` shape every sketch already uses.
    This note only NAMES the declared framework so the operator knows where
    to wire the sketch in; it is not a substitute for that framework's own
    middleware/callback documentation.
    """
    if not framework:
        return None
    return f"{comment} {framework}: wire this into its own pre-tool-call / tool-execution hook."


def _code_sketch(
    target: TargetContext | None,
    *,
    python: str,
    typescript: str,
    pseudocode: str | None = None,
) -> CodeSketch:
    """Build a `CodeSketch` in the target's inferred language, when known.

    ``pseudocode`` defaults to the ``python`` body — that shape (a
    ``before_tool_call``-style function) already reads as generic pseudocode
    for an operator in any language, so writing a THIRD near-identical
    variant would be pure duplication; pass it explicitly only when the
    python/pseudocode bodies should genuinely differ.
    """
    language = _infer_language(target.launch_command if target else None)
    framework = target.framework if target else None
    body = {
        "python": python,
        "typescript": typescript,
        "pseudocode": pseudocode if pseudocode is not None else python,
    }[language]
    note = _framework_note(framework, comment="//" if language == "typescript" else "#")
    return CodeSketch(
        language=language,
        framework=framework,
        body=f"{note}\n{body}" if note else body,
    )


# --- per-class recommendation builders --------------------------------------


def _w3_recommendation(
    exploit: ExploitRecord, target: TargetContext | None, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    tool = loc.tool or "the fetch tool"
    known_safe = (
        tuple(getattr(target.control_config, "fetch_allowlist", ()) or ())
        if target and target.control_config is not None
        else control_shim.DEFAULT_FETCH_ALLOWLIST
    )
    evidence = _evidence_for_tool(
        exploit,
        tool,
        destination_only=True,
        known_safe=known_safe or control_shim.DEFAULT_FETCH_ALLOWLIST,
    )
    declared = tuple(getattr(target.control_config, "egress_tools", ()) or ()) if target else ()
    confidence, reason = _confidence_for_tool(target, declared, tool, evidence)
    allowlist = _benign_destinations(exploit, tool, exclude_occurrence=evidence.occurrence)
    url_param = evidence.argument or "<the-argument-name-holding-the-destination>"
    config_snippet = control_shim.config_snippet_for(
        "W3", tool, url_param=url_param if evidence.argument else None, allowlist=tuple(allowlist)
    )
    primary = Prescription(
        control_id="egress-allowlist",
        tier="deterministic",
        headline=(
            f"`{tool}` reached an off-allowlist destination"
            + (f" (`{evidence.value}`)" if evidence.value else "")
            + " — enforce a host allowlist in the handler before the request is issued."
        ),
        rationale=(
            "The allowlist check runs in code, before the socket opens. The model's "
            "request cannot force the fetch through a host that is not on the list."
        ),
        invariant=f"{tool}(...) refuses unless the destination host is in ALLOWED_HOSTS",
        config_snippet=config_snippet,
        code_sketch=_code_sketch(
            target,
            python=(
                "def before_tool_call(tool_name, args):\n"
                f"    if tool_name == {tool!r}:\n"
                "        host = urlparse(args.get(" + repr(url_param) + ', "")).hostname\n'
                "        if host not in ALLOWED_HOSTS:\n"
                '            return Decision.deny(f"egress to {host!r} is not on the allowlist")\n'
                "    return Decision.allow()"
            ),
            typescript=(
                "function beforeToolCall(toolName: string, args: Record<string, unknown>) {\n"
                f"  if (toolName === {tool!r}) {{\n"
                f'    const host = new URL(String(args[{url_param!r}] ?? "")).hostname;\n'
                "    if (!ALLOWED_HOSTS.includes(host)) {\n"
                "      return Decision.deny(`egress to ${host} is not on the allowlist`);\n"
                "    }\n"
                "  }\n"
                "  return Decision.allow();\n"
                "}"
            ),
        ),
        residual=(
            "An allowlisted host that redirects off-list is not re-checked here — "
            "re-validate the host after every redirect, not only the initial URL.",
            "DNS rebinding: resolve and pin the IP at connect time, not just the hostname.",
        ),
    )
    return (evidence,), (primary,), confidence, reason


def _w4_recommendation(
    exploit: ExploitRecord, target: TargetContext | None, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    tool = loc.tool or exploit.payload.metadata.get("consequential_tool") or "the sink tool"
    evidence = _evidence_for_tool(exploit, tool)
    declared = (
        tuple(getattr(target.control_config, "consequential_tools", ()) or ()) if target else ()
    )
    confidence, reason = _confidence_for_tool(target, declared, tool, evidence)
    approval_tool = exploit.payload.metadata.get("approval_tool")
    approved_first = (
        tool_call_sequence(exploit.response.tool_calls, approval_tool, tool)
        if approval_tool
        else False
    )
    note = None if approved_first else "no approval tool ran before this call executed"
    evidence = Evidence(**{**evidence.__dict__, "note": note})
    config_snippet = control_shim.config_snippet_for("W4", tool)
    primary = Prescription(
        control_id="capability-attenuation",
        tier="deterministic",
        headline=f"`{tool}` executed with no prior approval call — bind it to a server-minted capability.",
        rationale=(
            "The model should never be able to supply a raw, sufficient argument for a "
            "consequential action. Resolve sensitive fields (recipient, destination "
            "account) server-side against an authenticated identity, and require a "
            "server-minted, model-unforgeable token before dispatch."
        ),
        invariant=f"{tool}(...) refuses unless called with a server-issued confirm_token",
        config_snippet=config_snippet,
        code_sketch=_code_sketch(
            target,
            python=(
                f"def {tool}(..., confirm_token=None):\n"
                "    if not confirm_token or not verify_token(confirm_token):\n"
                '        return {"status": "confirmation_required", "preview": {...}}\n'
                "    return dispatch(...)"
            ),
            typescript=(
                f"function {tool}(...args: unknown[], confirmToken?: string) {{\n"
                "  if (!confirmToken || !verifyToken(confirmToken)) {\n"
                '    return { status: "confirmation_required", preview: {} };\n'
                "  }\n"
                "  return dispatch(...args);\n"
                "}"
            ),
        ),
        citations=("mcp-spec-2026-07-28-consent",),
        residual=(
            "A staged/confirm split alone is still filterable if the token is guessable "
            "or reusable — mint it server-side, single-use, bound to the exact arguments.",
        ),
    )
    residual_approval = Prescription(
        control_id="human-approval",
        tier="deterministic",
        headline="Human approval as the ONLY gate is risk acceptance, not a control.",
        rationale=(
            "Measured data on agent tool-approval prompts shows the overwhelming "
            "majority are rubber-stamped rather than reviewed; an approval-only gate "
            "protects against nothing once that pattern sets in. Use it as a residual "
            "layer behind capability attenuation, never as the primary fix."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=None,
        residual=("A user who reflexively approves is not a security boundary.",),
    )
    return (evidence,), (primary, residual_approval), confidence, reason


def _w2_recommendation(
    exploit: ExploitRecord, target: TargetContext | None, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    read_tool = exploit.payload.metadata.get("target_tool") or loc.tool
    sink_tool = exploit.payload.metadata.get("consequential_tool") or (
        exploit.response.tool_calls[-1] if exploit.response.tool_calls else None
    )
    evidences = []
    if read_tool:
        evidences.append(_evidence_for_tool(exploit, read_tool))
    if sink_tool and sink_tool != read_tool:
        evidences.append(_evidence_for_tool(exploit, sink_tool))
    if not evidences:
        evidences.append(
            Evidence(
                tool=loc.tool or "the implicated tool",
                argument=None,
                value=None,
                occurrence=None,
                executed=False,
                source="payload",
                note="no read/sink pair identified in the trace",
            )
        )
    declared = tuple(getattr(target.control_config, "read_tool_names", ()) or ()) if target else ()
    confidence, reason = _confidence_for_tool(target, declared, evidences[0].tool, evidences[0])
    read_name = read_tool or "the read tool"
    sink_name = sink_tool or "the sink tool"
    config_snippet = control_shim.config_snippet_for("W2", read_name)
    primary = Prescription(
        control_id="ifc-label",
        tier="deterministic",
        headline=(
            f"`{sink_name}` acted on content `{read_name}` returned — label that content "
            "untrusted and refuse the sink call while it is in scope."
        ),
        rationale=(
            "Information-flow control (label the data, not filter the text): the model "
            "may still read and summarize the untrusted content, it just cannot reach a "
            "sink while untrusted content is in the active context. This is the pattern "
            "Microsoft's FIDES (agent_framework.security) ships as a production "
            "implementation."
        ),
        invariant=f"{sink_name}(...) refuses while untrusted content from {read_name} is in scope",
        config_snippet=config_snippet,
        code_sketch=_code_sketch(
            target,
            python=(
                f"# {read_name} output: integrity=untrusted\n"
                f"# {sink_name}: accepts_untrusted=False\n"
                "# -> sink refused while untrusted content is in the active context"
            ),
            typescript=(
                f"// {read_name} output: integrity=untrusted\n"
                f"// {sink_name}: acceptsUntrusted=false\n"
                "// -> sink refused while untrusted content is in the active context"
            ),
        ),
        citations=("fides-ms-learn",),
        residual=(
            "Most-restrictive-wins propagation can be conservative: once untrusted "
            "content enters, the rest of the run stays untrusted unless explicitly "
            "cleared.",
        ),
    )
    envelope = Prescription(
        control_id="untrusted-envelope",
        tier="probabilistic",
        headline="Data-marking envelope (defence in depth, not the primary fix).",
        rationale=(
            "Whether the envelope actually stops the attack depends on the target's "
            "model and system prompt respecting it — that dependency is exactly what "
            "the differential measures, and exactly why this is not the primary "
            "prescription."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=None,
        residual=(
            "A sufficiently different rephrasing of the injected instruction may "
            "still be followed even with the envelope in place.",
        ),
    )
    return tuple(evidences), (primary, envelope), confidence, reason


def _w1_recommendation(
    exploit: ExploitRecord, target: TargetContext | None, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    tool = loc.tool or "the implicated tool"
    description = None
    if target is not None:
        for t in target.tools:
            if getattr(t, "name", None) == tool:
                description = getattr(t, "description", None)
                break
    steered_into = exploit.response.tool_calls[-1] if exploit.response.tool_calls else None
    evidence = Evidence(
        tool=tool,
        argument=None,
        value=_quote(description) if description else _quote(exploit.payload.body),
        occurrence=None,
        executed=bool(exploit.response.tool_calls),
        source="tool_surface" if description else "payload",
        note=f"steered the planner into calling `{steered_into}`" if steered_into else None,
    )
    confidence: Confidence
    reason: str
    if description:
        confidence = "high"
        reason = "the tool's real description was available and inspected"
    elif loc.tool is not None or steered_into is not None:
        confidence = "medium"
        reason = "a tool was identified from the trace/metadata; no live tool inventory available"
    else:
        # Neither a live description NOR an identified tool name: the evidence
        # below is bound to the generic "the implicated tool" placeholder,
        # inferred from nothing but the payload body itself — the weakest
        # possible basis for a W1 finding, previously mislabelled "medium"
        # (the formula only ever checked `description`, ignoring whether ANY
        # real tool identity was known at all).
        confidence = "low"
        reason = "no tool identified and no live tool inventory available; inferred from the payload body alone"
    digest = (
        hashlib.sha256((description or "").encode("utf-8")).hexdigest() if description else None
    )
    pin = Prescription(
        control_id="description-fingerprint",
        tier="detective",
        headline=f"Pin `{tool}`'s description hash and fail CI on drift.",
        rationale=(
            "A tool description is untrusted per the MCP spec unless it comes from a "
            "trusted server. Hashing the approved text and refusing a changed one at "
            "load is the only real answer to a 'rug pull' — a description that changes "
            "after a user already approved the tool."
        ),
        invariant=f"{tool}(...) refuses if sha256(description) != {digest or '<pin-after-review>'}",
        config_snippet=(
            f"control_config:\n  description_pins:\n    {tool}: {digest!r}" if digest else None
        ),
        code_sketch=None,
        citations=("mcp-spec-2026-07-28-tool-safety",),
        residual=("A pin only catches CHANGE, not a malicious description approved once.",),
    )
    attenuation = Prescription(
        control_id="capability-attenuation",
        tier="deterministic",
        headline=(
            f"`{tool}`'s description should not be able to authorize `{steered_into}`."
            if steered_into
            else f"`{tool}`'s description should not be able to authorize a consequential action."
        ),
        rationale=(
            "No description, however phrased, should be able to talk the planner into "
            "minting a capability it was not already holding. Gate the consequential "
            "tool on a server-issued token (shared machinery with the W4 prescription), "
            "not on trusting what any tool's description claims."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=None,
        residual=(),
    )
    sanitizer = Prescription(
        control_id="description-sanitizer",
        tier="probabilistic",
        headline="Regex-based description sanitizing (defence in depth, not the fix).",
        rationale=(
            "Plain-prose cross-tool steering with no smuggle form (no <IMPORTANT> block, "
            "no bracketed directive) is a documented gap in denylist sanitizing."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=None,
        residual=("A rephrasing outside the denylist's known forms is not caught.",),
    )
    return (evidence,), (pin, attenuation, sanitizer), confidence, reason


#: Mirrors ``mylonite.plugins._mcp.twins.INPUT_FRAME_CONTROL`` — duplicated as
#: a literal (not imported) because this module must not import anything
#: under ``mylonite.plugins`` (see the module docstring). The two must stay
#: in sync by convention; ``tests/gate/test_recommend.py`` pins the literal.
_INPUT_FRAME_WEAKNESS: Final = "input-frame"


def _rest_recommendation(
    exploit: ExploitRecord, target: TargetContext | None, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    """Workstream D6: a ``transport: rest`` target has no ``tools/list``, so the
    W1-W4 tool-identity-keyed prescriptions above do not apply. Built on what
    DOES generalise to any HTTP agent, regardless of which pattern fired:
    collapsed authorization (the highest-value REST finding — most wrapped
    APIs end up single-principal), input framing (the primary control for the
    ``input-frame`` differential specifically), and endpoint-boundary
    enforcement (the REST analogue of a tool allowlist, since there is no
    tool boundary to attach one to).
    """
    evidence = Evidence(
        tool=loc.tool or "the agent endpoint",
        argument=None,
        value=_quote(exploit.payload.body) if exploit.payload.body else None,
        occurrence=None,
        executed=bool(exploit.response.tool_calls),
        source="payload",
        note="rest transport — no tool identity to key evidence on",
    )
    input_framing = Prescription(
        control_id="rest-input-framing",
        tier="probabilistic",
        headline=(
            "Frame the caller's message as structured, labelled DATA — never string-"
            "concatenated into the system/instruction prompt."
        ),
        rationale=(
            "A collapsed HTTP wrapper that builds one prompt string from "
            "`system_instructions + user_message` gives the model no structural signal "
            "that the two have different trust levels. Passing them as separate, "
            "labelled fields (e.g. distinct chat-message roles, or an explicit "
            '`{"instructions": ..., "untrusted_input": ...}` envelope) is the REST '
            "analogue of W2's untrusted-content labelling — it changes what the model "
            "sees, so whether it holds still depends on the model respecting the label."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=_code_sketch(
            target,
            python=(
                "messages = [\n"
                '    {"role": "system", "content": SYSTEM_INSTRUCTIONS},\n'
                '    {"role": "user", "content": untrusted_user_message},\n'
                "]  # never: SYSTEM_INSTRUCTIONS + untrusted_user_message"
            ),
            typescript=(
                "const messages = [\n"
                '  { role: "system", content: SYSTEM_INSTRUCTIONS },\n'
                '  { role: "user", content: untrustedUserMessage },\n'
                "]; // never: SYSTEM_INSTRUCTIONS + untrustedUserMessage"
            ),
        ),
        residual=(
            "Structural framing narrows the attack surface but does not eliminate "
            "instruction-following: a sufficiently persuasive user-role message can "
            "still be followed if nothing downstream enforces what the response is "
            "allowed to do.",
        ),
    )
    collapsed_authz = Prescription(
        control_id="rest-on-behalf-of-identity",
        tier="deterministic",
        headline=(
            "Propagate the CALLER's identity through to every downstream action, "
            "instead of one shared service credential for the whole agent."
        ),
        rationale=(
            "The most common REST-agent failure is architectural, not a specific "
            "prompt: the wrapper holds ONE service token for the API it fronts, so "
            "every caller effectively acts with the same (often over-broad) "
            "permissions. An on-behalf-of token (or a per-caller scoped credential, "
            "resolved server-side from an authenticated session) means a successful "
            "prompt injection can only reach what THAT caller was already allowed to "
            "reach — it gates the call in code, not in the prompt."
        ),
        invariant="every downstream call is scoped to the authenticated caller's own permissions",
        config_snippet=None,
        code_sketch=None,
        residual=(
            "Does not by itself stop a caller from misusing their OWN legitimate "
            "permissions via a successful injection — it bounds the blast radius to "
            "that caller's scope, not to zero.",
        ),
    )
    endpoint_boundary = Prescription(
        control_id="rest-endpoint-allowlist",
        tier="deterministic",
        headline="Enforce an explicit allowlist of upstream endpoints/actions the wrapper may invoke.",
        rationale=(
            "With no MCP tool boundary to attach a control to, the equivalent gate "
            "lives in the wrapper's own dispatch code: before issuing an upstream "
            "call on the model's behalf, check the target endpoint/action against an "
            "explicit allowlist, exactly as `mylonite.scan.control_shim`'s W3 egress "
            "control does for a tool-identity-keyed target."
        ),
        invariant="the dispatcher refuses any upstream call whose endpoint is not on ALLOWED_ENDPOINTS",
        config_snippet=None,
        code_sketch=None,
        residual=(
            "An allowlisted endpoint that itself accepts attacker-influenced "
            "parameters (e.g. a generic `/execute?action=...`) still needs its OWN "
            "parameter-level validation — endpoint allowlisting bounds WHERE, not "
            "WHAT.",
        ),
    )
    return (
        (evidence,),
        (input_framing, collapsed_authz, endpoint_boundary),
        "medium",
        "rest transport — declared by the target, not derived from a tool-identity trace",
    )


def _generic_recommendation(
    exploit: ExploitRecord, loc: Localization
) -> tuple[tuple[Evidence, ...], tuple[Prescription, ...], Confidence, str]:
    evidence = Evidence(
        tool=loc.tool or "unknown",
        argument=None,
        value=None,
        occurrence=None,
        executed=False,
        source="payload",
        note="weakness class could not be determined",
    )
    prescription = Prescription(
        control_id="declare-weakness-class",
        tier="probabilistic",
        headline="Declare `weakness_classes:` in your target file for a specific control.",
        rationale=(
            "Mylonite cannot prescribe a structural control without knowing which of "
            "W1-W4 this finding belongs to."
        ),
        invariant=None,
        config_snippet=None,
        code_sketch=None,
    )
    return (evidence,), (prescription,), "low", "weakness class unresolved"


# --- entry point -------------------------------------------------------------


def recommend(
    exploit: ExploitRecord,
    report: ValidationReport | None = None,
    *,
    target: TargetContext | None = None,
) -> Recommendation:
    """Build the structural recommendation for a proven (or pending) exploit.

    Never raises. Every failure mode (no trace, no target, unresolved
    weakness class) degrades into ``Recommendation.degraded`` and a lowered
    ``confidence`` rather than an exception — the PR body is the last mile of
    a run that already cost real work, and it must always produce something.
    """
    from mylonite.gate.mitigation import weakness_class_for

    degraded: list[str] = []
    # A rest target's finding is never really "W2"/"generic" — the transport
    # (when a target is supplied) or the exploit's own stamped `input-frame`
    # weakness (when it isn't — e.g. a bare report/generate call with no
    # target_context plumbed through) decides the recommendation shape below,
    # not weakness_class_for's W1-W4/compliance-tag inference, which is built
    # for a tool-identity-keyed MCP target and has no "input-frame" case.
    is_rest_target = (target is not None and target.transport == "rest") or (
        exploit.payload.metadata.get("weakness") == _INPUT_FRAME_WEAKNESS
    )
    # Overriding the LABEL here too keeps it from disagreeing with the
    # REST-specific prescriptions actually rendered below.
    wc = "rest" if is_rest_target else weakness_class_for(exploit)
    system_prompt = target.system_prompt if target is not None else None
    try:
        loc = localize(exploit, system_prompt=system_prompt)
    except Exception:  # localize is pure/typed; defensive only, per "never raise"
        degraded.append("localization failed")
        loc = Localization(kind="tool", label="unknown", tool=None, field=None, line=None, why="")

    try:
        if is_rest_target:
            # D6: a rest target has no tools/list, so the W1-W4 tool-identity-keyed
            # builders below do not apply regardless of which class weakness_class_for
            # inferred — the transport itself, not the specific weakness, decides.
            evidence, prescriptions, confidence, reason = _rest_recommendation(exploit, target, loc)
        elif wc == "W1":
            evidence, prescriptions, confidence, reason = _w1_recommendation(exploit, target, loc)
        elif wc == "W2":
            evidence, prescriptions, confidence, reason = _w2_recommendation(exploit, target, loc)
        elif wc == "W3":
            evidence, prescriptions, confidence, reason = _w3_recommendation(exploit, target, loc)
        elif wc == "W4":
            evidence, prescriptions, confidence, reason = _w4_recommendation(exploit, target, loc)
        else:
            evidence, prescriptions, confidence, reason = _generic_recommendation(exploit, loc)
    except Exception as exc:  # pragma: no cover - defensive, see docstring
        degraded.append(f"derivation failed: {exc}")
        evidence, prescriptions, confidence, reason = _generic_recommendation(exploit, loc)

    # W1's primary evidence is the tool's DESCRIPTION (from a live tool
    # inventory) or the tool NAME (from the exploit's own metadata/trace via
    # localize()) — neither needs an `effect_trace`/`mcp_trace_planner`
    # execution trace to be meaningful, unlike every other class, whose
    # evidence genuinely IS trace-derived. A W1 finding with NEITHER signal
    # (evidence bound to the generic "the implicated tool" placeholder) is
    # correctly trace-degradable — it has nothing else to fall back on.
    evidence_is_trace_derived = not (
        wc == "W1" and ((evidence and evidence[0].source == "tool_surface") or loc.tool is not None)
    )
    if (
        evidence_is_trace_derived
        and not _has_any_trace_entries(exploit.response.metadata.get("effect_trace", ""))
        and not _has_any_trace_entries(exploit.response.metadata.get("mcp_trace_planner", ""))
    ):
        degraded.append("no trace metadata recorded")
        confidence = _degrade(confidence)

    effect_confirmed = exploit.response.metadata.get("effect_confirmed")
    if effect_confirmed == "unprobed":
        degraded.append("effect probe did not confirm")
        confidence = _degrade(confidence)

    proven = bool(report and report.kept)
    proven_layer: Literal["server", "boundary", "none"] = "none"
    if report is not None:
        notes = getattr(report, "notes", "") or ""
        if "guarded-twin=server-layer" in notes:
            proven_layer = "server"
        elif "guarded-twin=synthetic-boundary" in notes:
            proven_layer = "boundary"

    return Recommendation(
        weakness_class=wc,
        localization=loc,
        evidence=evidence,
        prescriptions=prescriptions,
        confidence=confidence,
        confidence_reason=reason,
        proven=proven,
        proven_layer=proven_layer,
        degraded=tuple(degraded),
    )


# --- rendering ---------------------------------------------------------------


def _render_evidence(ev: Evidence) -> str:
    parts = [f"`{ev.tool}`"]
    if ev.argument:
        parts.append(f"argument `{ev.argument}`")
    if ev.value:
        parts.append(f"value `{ev.value}`")
    parts.append("executed" if ev.executed else "not confirmed executed")
    line = ", ".join(parts)
    if ev.note:
        line += f" — {ev.note}"
    return line


def render_markdown(rec: Recommendation) -> str:
    """Render a Recommendation as a PR-body-ready markdown section.

    Pure string assembly; every quoted value in ``rec.evidence``/prescriptions
    is already redacted by the derivation helpers above.
    """
    lines = [
        f"**Confidence: {rec.confidence}** ({rec.confidence_reason})",
        "",
        "**Evidence:**",
    ]
    for ev in rec.evidence:
        lines.append(f"- {_render_evidence(ev)}")
    lines.append("")
    for i, p in enumerate(rec.prescriptions):
        tier_label = {
            "deterministic": "Deterministic",
            "probabilistic": "Probabilistic",
            "detective": "Detective",
        }[p.tier]
        lead = "**Do this" if i == 0 else "**Also consider"
        lines.append(f"{lead} ({tier_label}):** {p.headline}")
        lines.append("")
        lines.append(p.rationale)
        if p.invariant:
            lines.append("")
            lines.append(f"    invariant: {p.invariant}")
        if p.config_snippet:
            lines.append("")
            lines.append("```yaml")
            lines.append(p.config_snippet)
            lines.append("```")
        if p.code_sketch:
            lines.append("")
            lines.append(f"```{p.code_sketch.language}")
            lines.append(p.code_sketch.body)
            lines.append("```")
        if p.citations:
            cites = ", ".join(f"[{c}]({resolve_citation(c).url})" for c in p.citations)
            lines.append("")
            lines.append(f"_Source: {cites}_")
        if p.residual:
            lines.append("")
            lines.append("**Residual risk:** " + " ".join(p.residual))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_dict(rec: Recommendation) -> dict[str, Any]:
    """Machine-readable serialization shared by SARIF and the JSON bundle
    (PR3/PR6) — one function so those two surfaces cannot drift apart."""
    return {
        "weakness_class": rec.weakness_class,
        "confidence": rec.confidence,
        "confidence_reason": rec.confidence_reason,
        "proven": rec.proven,
        "proven_layer": rec.proven_layer,
        "degraded": list(rec.degraded),
        "evidence": [
            {
                "tool": e.tool,
                "argument": e.argument,
                "value": e.value,
                "occurrence": e.occurrence,
                "executed": e.executed,
                "source": e.source,
                "note": e.note,
            }
            for e in rec.evidence
        ],
        "prescriptions": [
            {
                "control_id": p.control_id,
                "tier": p.tier,
                "headline": p.headline,
                "rationale": p.rationale,
                "invariant": p.invariant,
                "config_snippet": p.config_snippet,
                "code_sketch": (
                    {
                        "language": p.code_sketch.language,
                        "framework": p.code_sketch.framework,
                        "body": p.code_sketch.body,
                    }
                    if p.code_sketch
                    else None
                ),
                "citations": list(p.citations),
                "residual": list(p.residual),
            }
            for p in rec.prescriptions
        ],
    }
