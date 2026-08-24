"""Machine-readable JSON finding bundle (R5).

SARIF (``report/sarif.py``) is the portal to GitHub code scanning; this is the
portal to everything else — dashboards, SIEM, Slack bots, custom CI for teams not on
GitHub/pytest. One self-contained ``finding.json`` per scan/validation, reusing the
exact data Mylonite already computes: the weakness class, severity, compliance tags,
the R4 localization, the R2 differential proof, and the proven control. No new
analysis — just a stable, documented serialization.
"""

from __future__ import annotations

from typing import Any

from mylonite._redaction import redact
from mylonite.gate.localize import localize
from mylonite.gate.mitigation import weakness_class_for
from mylonite.report.severity import severity_for
from mylonite.version import __version__

#: Bump on any backward-incompatible change to the finding shape.
#: 1.1 (PR6): added the optional "recommendation" key (present only when a
#: TargetContext was supplied to to_bundle) -- additive, but every consumer
#: of the finding shape should know the version moved.
SCHEMA_VERSION = "1.1"


def _proof(report: Any | None) -> dict[str, Any] | None:
    repro = getattr(report, "reproducibility", None) if report is not None else None
    if repro is None or not getattr(repro, "iterations", 0):
        return None
    return {
        "iterations": repro.iterations,
        "vuln_fired": repro.vuln_fired,
        "guard_resisted": repro.guard_resisted,
        "kept": bool(getattr(report, "kept", False)),
    }


def _recommendation(exploit: Any, report: Any | None, target: Any | None) -> dict[str, Any] | None:
    """PR6: the structural recommendation, when a TargetContext is available.

    ``None`` (the key is simply omitted by the caller) when no target was
    supplied — every existing consumer of a 1.0-shaped bundle keeps working
    unchanged, since this is purely additive.
    """
    if target is None:
        return None
    from mylonite.gate.recommend import recommend, to_dict

    return to_dict(recommend(exploit, report, target=target))


def _finding(exploit: Any, report: Any | None, target: Any | None = None) -> dict[str, Any]:
    md = getattr(exploit.payload, "metadata", {}) or {}
    weakness = str(md.get("weakness", "")) or weakness_class_for(exploit)
    effect = str(getattr(exploit.response, "metadata", {}).get("effect_confirmed", "unprobed"))
    loc = localize(exploit)
    return {
        "pattern_id": str(exploit.pattern_id),
        "target_id": str(exploit.target_id),
        # Prefer the payload's stamped weakness (W1-W4); fall back to the
        # seed-catalogue / compliance inference for un-stamped findings.
        "weakness_class": weakness
        if weakness in {"W1", "W2", "W3", "W4"}
        else weakness_class_for(exploit),
        "severity": severity_for(weakness, effect),
        # static / obfuscated / ... (attack tier or shape metadata, generic)
        "attack_shape": str(md.get("attack_shape") or md.get("attack_tier") or "static"),
        # Mirrors the sarif.py fix (DCR-0021): a real exfil finding's narration can
        # carry the exfiltrated value itself, and this bundle is written to disk
        # unconditionally (no console-boundary redaction applies to a file write).
        "success_reason": redact(str(exploit.success_reason)),
        "compliance": {
            "owasp_llm": list(exploit.compliance.owasp_llm),
            "owasp_asi": list(exploit.compliance.owasp_asi),
            "mitre_atlas": list(exploit.compliance.mitre_atlas),
            "nist_ai_rmf": list(exploit.compliance.nist_ai_rmf),
        },
        "localization": {
            "kind": loc.kind,
            "label": loc.label,
            "tool": loc.tool,
            "field": loc.field,
            "line": loc.line,
        },
        "proof": _proof(report),
        "proven_control": md.get("synthetic_control") or None,
        "recommendation": _recommendation(exploit, report, target),
    }


def to_bundle(
    findings: list[tuple[Any, Any | None]],
    *,
    tool_version: str = __version__,
    target: Any | None = None,
) -> dict[str, Any]:
    """Build the JSON finding bundle from ``(exploit, validation_report | None)`` pairs.

    Mirrors ``to_sarif``: a scan dir yields exploits with no report (no proof); a
    validation yields the exploit + its ``ValidationReport`` (the differential proof).

    ``target`` (PR6): an optional ``mylonite.gate.recommend.TargetContext``,
    shared across every finding in this call (a bundle is built from one
    scan/validation of one target). When supplied, each finding's
    ``recommendation`` key carries the same structural, evidence-anchored
    recommendation ``build_pr_body`` renders — reusing
    ``recommend.to_dict`` so the bundle and SARIF (``report/sarif.py``)
    cannot describe the same finding two different ways.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "Mylonite", "version": tool_version},
        "findings": [_finding(exploit, report, target) for exploit, report in findings],
    }
