"""A static inventory of a target's tools: each tool's role and where it came from.

No model call and no live call: it reads the described tool surface only. It
answers the question a user has before spending anything: "what will the scan
treat each of my tools as, and why?"

It is not a second classifier. Every column calls the same classification the
live boundary controls call, with the same hint vocabularies, annotation
readers and declared lists:

* consequential: the confirm-gate control's ``classify`` over
  ``_CONSEQUENTIAL_HINTS`` and the ``readOnlyHint``/``destructiveHint`` reading;
* egress: a declared list, then a destination-shaped parameter (the static
  shadow of the egress control's argument check), then ``classify`` over
  ``_EGRESS_HINTS`` and ``openWorldHint``;
* read: ``classify`` over ``READ_HINTS`` and ``readOnlyHint``;
* store / recall: the scan's own auto-wire pick (``_classify_tools``);
* verdict read: whether the verdict's trace reading (``effect_verdict.is_read_tool``)
  counts a call to the tool as a read rather than a dispatch, with the declared
  ``read_tool_names`` and ``verdict_read_tools`` the scan hands it. Its name rule
  is its own (a read verb first or last; no transport or state-changing word), so
  it can disagree with the confirm gate both ways: ``list_notes`` is guarded by
  the gate's fail-closed default and ``get_issue`` by the gate's name hint
  ``issue``, yet the verdict counts calls to either as reads. The inventory shows
  that rather than smoothing it over. This column is a per-tool, name-only guess:
  the live verdict also reads each actual call's arguments, and a call whose
  arguments carry a network-scheme URL, or a bare host/IP in an argument
  actually named as a destination, is never a read — whatever its tool's name
  or declared list says (``get_page(url=...)``, #304) — unless that
  destination is loopback or in the target's own egress allowlist, or the
  tool is the probe's own ``verify_tool``/``recall_tool`` (always exempt).
  The inventory has no call to look at, so it cannot show that half of the
  rule.

A tool that no tier recognises is "unknown", and the confirm-gate control
already treats it as consequential (the fail-closed default); the egress
control likewise refuses an unknown tool's call that carries no destination. The inventory
shows that instead of hiding it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from mylonite.scan.control_shim import _CONSEQUENTIAL_HINTS, _EGRESS_HINTS, READ_HINTS
from mylonite.scan.effect_verdict import is_read_tool
from mylonite.scan.tool_classifier import (
    annotation_is_egress,
    annotation_is_read,
    annotation_is_sink,
    classify,
    destination_tools,
)
from mylonite.scan.tool_roles import _classify_tools

SOURCE_DECLARED = "declared"
SOURCE_ANNOTATION = "annotation"
SOURCE_SCHEMA = "schema"
SOURCE_NAME = "name"
SOURCE_UNKNOWN = "unknown"

#: ``classify``'s reason strings, mapped to the inventory's source words.
_REASON_TO_SOURCE = {
    "declared": SOURCE_DECLARED,
    "mcp tool annotation": SOURCE_ANNOTATION,
    "name hint": SOURCE_NAME,
    "fail-closed default": SOURCE_UNKNOWN,
}


@dataclass(frozen=True)
class RoleEvidence:
    """One role a tool plays, and which tier said so."""

    role: str
    source: str


@dataclass(frozen=True)
class InventoryEntry:
    """One tool's row: its roles, and whether the confirm gate treats it as
    consequential (and on what basis)."""

    name: str
    roles: tuple[RoleEvidence, ...]
    consequential: bool
    consequential_source: str
    #: The verdict reads a call to this tool as a read, not a dispatch.
    verdict_read: bool = False

    @property
    def unknown(self) -> bool:
        """No tier recognised the tool, so it is guarded by the fail-closed default."""
        return not self.roles and self.consequential_source == SOURCE_UNKNOWN


def _declared(cc: Any, field: str) -> frozenset[str] | None:
    """A ``control_config`` list as the controls receive it: ``None`` when empty
    (see ``twins.boundary_control_for``)."""
    if cc is None:
        return None
    return frozenset(getattr(cc, field, None) or ()) or None


def _source(reason: str) -> str:
    return _REASON_TO_SOURCE.get(reason, SOURCE_UNKNOWN)


def tool_inventory(tools: Sequence[Any], *, control_config: Any = None) -> list[InventoryEntry]:
    """Every tool on the surface with its roles and their sources, in listing order."""
    declared_consequential = _declared(control_config, "consequential_tools")
    declared_egress = _declared(control_config, "egress_tools")
    declared_read = _declared(control_config, "read_tool_names")
    # Verdict-only reads: the scan adds these to the read list it hands the
    # verdict, and to nothing else.
    verdict_reads = _declared(control_config, "verdict_read_tools") or frozenset()
    # A named parameter, not the tool-name fallback: the name tier is decided by
    # `classify` below, with the egress control's own token rule.
    destination_params = {
        name for name, param, _reason in destination_tools(tools) if param != "(unspecified)"
    }
    auto_wire = _classify_tools(list(tools))

    entries: list[InventoryEntry] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        if not name:
            continue
        annotations = getattr(tool, "annotations", None)
        roles: list[RoleEvidence] = []

        cons_applies, cons_reason = classify(
            name,
            declared=declared_consequential,
            hints=_CONSEQUENTIAL_HINTS,
            annotation_says=annotation_is_sink(annotations),
        )
        cons_source = _source(cons_reason)
        if cons_applies and cons_source != SOURCE_UNKNOWN:
            roles.append(RoleEvidence("consequential", cons_source))

        if declared_egress is not None:
            if name in declared_egress:
                roles.append(RoleEvidence("egress", SOURCE_DECLARED))
        elif name in destination_params:
            roles.append(RoleEvidence("egress", SOURCE_SCHEMA))
        else:
            egress_applies, egress_reason = classify(
                name,
                declared=None,
                hints=_EGRESS_HINTS,
                annotation_says=annotation_is_egress(annotations),
            )
            if egress_applies and _source(egress_reason) != SOURCE_UNKNOWN:
                roles.append(RoleEvidence("egress", _source(egress_reason)))

        read_applies, read_reason = classify(
            name,
            declared=declared_read,
            hints=READ_HINTS,
            annotation_says=annotation_is_read(annotations),
        )
        if read_applies and _source(read_reason) != SOURCE_UNKNOWN:
            roles.append(RoleEvidence("read", _source(read_reason)))

        if name == auto_wire.seed_arm_tool:
            roles.append(RoleEvidence("store", SOURCE_NAME))
        if name == auto_wire.retrieve_tool:
            roles.append(RoleEvidence("recall", SOURCE_NAME))

        entries.append(
            InventoryEntry(
                name=name,
                roles=tuple(roles),
                consequential=cons_applies,
                consequential_source=cons_source,
                verdict_read=is_read_tool(
                    name,
                    read_tool_names=(declared_read or frozenset()) | verdict_reads,
                    annotations=annotations,
                    # The list the scan passes: declared consequential plus
                    # declared egress tools. The seed's own tool is added per
                    # attempt and cannot be known here; see treated_as_text.
                    consequential_tool_names=(declared_consequential or frozenset())
                    | (declared_egress or frozenset()),
                    # As the verdict reads a call: the server's own
                    # readOnlyHint needs a declaration or a read verb too.
                    annotation_needs_corroboration=True,
                ),
            )
        )
    return entries


def unknown_tools(entries: Sequence[InventoryEntry]) -> list[str]:
    """Names of the tools no tier recognised."""
    return [e.name for e in entries if e.unknown]


def role_text(entry: InventoryEntry) -> str:
    """``consequential (name), read (annotation)``; ``unknown`` when nothing
    recognised the tool; ``none (declared)`` when the operator's lists leave it out."""
    if entry.roles:
        return ", ".join(f"{r.role} ({r.source})" for r in entry.roles)
    if entry.unknown:
        return "unknown"
    return f"none ({entry.consequential_source})"


def treated_as_text(entry: InventoryEntry) -> str:
    """Whether the confirm gate treats the tool as consequential, and why."""
    if not entry.consequential:
        return f"no ({entry.consequential_source})"
    if entry.consequential_source == SOURCE_UNKNOWN:
        text = "yes (fail-closed default)"
    else:
        text = f"yes ({entry.consequential_source})"
    if entry.verdict_read:
        # The confirm gate guards it, but the verdict does not count a call to
        # it as a dispatch: say so instead of letting the two disagree silently.
        text += "; the verdict counts its calls as reads unless a seed targets this tool"
    return text


def inventory_comment_lines(entries: Sequence[InventoryEntry]) -> list[str]:
    """The inventory as plain-ASCII YAML comment lines, for ``scan --scaffold``."""
    lines = [
        "# Tool inventory (no model call): each tool's role, where the role came from",
        "# (declared / annotation / schema / name / unknown), and whether the scan's",
        "# confirm gate treats it as consequential. Unknown counts as consequential",
        "# (and the egress control guards it too).",
    ]
    for e in entries:
        lines.append(f"#   {e.name}: {role_text(e)}; consequential: {treated_as_text(e)}")
    unknown = unknown_tools(entries)
    if unknown:
        lines.append(
            f"# {len(unknown)} tool(s) have an unknown role. To confirm them, list every "
            "consequential tool under"
        )
        lines.append(
            "# control_config.consequential_tools; every tool left off that list is then "
            "treated as not"
        )
        lines.append("# consequential, so include the ones already recognised.")
    return lines
