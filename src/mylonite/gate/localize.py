"""Localize a finding to the precise locus a developer should fix (R4).

In-PR, on-the-spot findings cut remediation time sharply — devs fix where they
read. Because Mylonite ingests the AI layer, it can point at the exact place a
weakness lives instead of only describing it: which tool's *description* carries
smuggled instructions, which tool's *returned content* was treated as commands,
which action *handler* fired without a guard, or which *system-prompt* line is at
fault. This module derives that locus deterministically from data every
``ExploitRecord`` already carries (the delivery channel, the implicated tool, and
— for prompt findings — the prompt text), so it generalises across all targets.

It does NOT guess source character spans: a remote MCP tool description has no
file/line in the scanning repo, so the honest unit is the tool + field (a
"logical location"), with a real file line only when the system-prompt text is
available. The PR body, the SARIF location, and the live check-run annotation all
render from this single structure.
"""

from __future__ import annotations

from dataclasses import dataclass

from mylonite.contracts import ExploitRecord

# channel -> (locus kind, the field within that locus)
_CHANNEL: dict[str, tuple[str, str | None]] = {
    "tool-description": ("tool", "description"),
    "system-prompt-injection": ("system_prompt", None),
    "tool-result": ("data", "returned content"),
    "rag-document": ("data", "returned content"),
    "user-message": ("tool", "handler"),
}

# Payload-metadata keys that name the security-relevant tool, most-specific first.
_TOOL_KEYS = ("consequential_tool", "sink_tool", "approval_tool", "target_tool", "tool")

_WHY: dict[str, str] = {
    "description": (
        "A tool description carried the injected instruction — sanitise tool descriptions "
        "before they reach the planner."
    ),
    "returned content": (
        "Untrusted content returned by this tool was treated as instructions — wrap it in an "
        "untrusted-data envelope."
    ),
    "handler": (
        "This tool acted on a hijacked instruction without a guard — gate it behind explicit "
        "confirmation or an egress allowlist."
    ),
    "system_prompt": (
        "The model followed instructions the system prompt should constrain — add an "
        "untrusted-data / least-authority guard there."
    ),
}


@dataclass(frozen=True)
class Localization:
    """Where a finding lives, for annotation. ``line`` is 1-based and only set when
    the system-prompt text was available and the offending text was found in it."""

    kind: str  # "tool" | "system_prompt" | "data"
    label: str  # human one-liner, e.g. "tool `send_email` -> handler"
    tool: str | None
    field: str | None  # "description" | "returned content" | "handler" | None
    line: int | None
    why: str


def _pick_tool(exploit: ExploitRecord) -> str | None:
    md = exploit.payload.metadata
    for key in _TOOL_KEYS:
        value = md.get(key)
        if value:
            return value
    if exploit.response.tool_calls:
        return exploit.response.tool_calls[0]
    return None


def _prompt_line(system_prompt: str | None, body: str) -> int | None:
    """The 1-based line of ``system_prompt`` that best matches the injected text.

    Matches on the first non-empty line of the payload body (the marker) so a
    multi-line payload still resolves to one anchor line. Returns ``None`` when no
    prompt was supplied or the marker isn't present (the common case — the injected
    text is the attack, not part of the operator's prompt; we never fabricate a line).
    """
    if not system_prompt or not body.strip():
        return None
    marker = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    if not marker:
        return None
    for i, line in enumerate(system_prompt.splitlines(), start=1):
        if marker in line:
            return i
    return None


def localize(exploit: ExploitRecord, *, system_prompt: str | None = None) -> Localization:
    """Deterministically locate ``exploit`` to its fixable locus."""
    kind, field = _CHANNEL.get(exploit.payload.channel, ("tool", "handler"))

    if kind == "system_prompt":
        line = _prompt_line(system_prompt, exploit.payload.body)
        label = "system prompt" if line is None else f"system prompt, line {line}"
        return Localization(
            kind=kind, label=label, tool=None, field=None, line=line, why=_WHY["system_prompt"]
        )

    tool = _pick_tool(exploit)
    label = f"tool `{tool}` -> {field}" if tool else f"the implicated tool's {field}"
    return Localization(
        kind=kind,
        label=label,
        tool=tool,
        field=field,
        line=None,
        why=_WHY.get(field or "", _WHY["handler"]),
    )
