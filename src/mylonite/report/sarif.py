"""SARIF 2.1.0 output — the portal to GitHub code scanning (the Security tab + PR
checks), where developers already triage every other finding.

Reuses the data Mylonite already captures: the ``ExploitRecord`` (pattern, target,
compliance), the ``severity_for`` rule (shared with the JSON bundle), and the
``ValidationReport``'s differential proof. The proof rides in each result's message
so the GitHub UI shows *why a finding is real* (fired N/N on the vulnerable target,
resisted M/M with the control) — our anti-false-positive trust signal.
"""

from __future__ import annotations

import hashlib
from typing import Any

from mylonite._redaction import redact
from mylonite.gate.localize import localize
from mylonite.report.severity import severity_for
from mylonite.version import __version__

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"High": "error", "Medium": "warning", "Low": "note"}
#: GitHub code scanning reads `security-severity` (0-10) to bucket findings.
_SECURITY_SEVERITY = {"High": "8.0", "Medium": "5.0", "Low": "3.0"}


def _tags(compliance: Any) -> list[str]:
    tags: list[str] = []
    for ids in (
        getattr(compliance, "owasp_llm", []) or [],
        getattr(compliance, "owasp_asi", []) or [],
        getattr(compliance, "mitre_atlas", []) or [],
        getattr(compliance, "nist_ai_rmf", []) or [],
    ):
        tags.extend(ids)
    return tags


def _proof_text(report: Any | None) -> str | None:
    repro = getattr(report, "reproducibility", None) if report is not None else None
    if repro is None or not getattr(repro, "iterations", 0):
        return None
    it = repro.iterations
    vf = repro.vuln_fired
    gr = repro.guard_resisted
    if gr is None:
        return f"Reproducible: the attack fired {vf}/{it} times on the target (no guarded twin)."
    return (
        f"Differential proof: the attack fired {vf}/{it} on the vulnerable target and was "
        f"resisted {gr}/{it} with the control applied — the safeguard, not the model, "
        "carries the security."
    )


def _result(
    exploit: Any, report: Any | None, *, system_prompt: str | None = None
) -> dict[str, Any]:
    weakness = str((getattr(exploit.payload, "metadata", {}) or {}).get("weakness", ""))
    effect = str(getattr(exploit.response, "metadata", {}).get("effect_confirmed", "unprobed"))
    sev = severity_for(weakness, effect)
    # R4: pin the finding to its locus (the implicated tool/field or prompt line) so
    # GitHub code scanning shows WHERE to fix, not just what.
    loc = localize(exploit, system_prompt=system_prompt)
    # This artefact is uploaded to GitHub code scanning; a real exfil finding's
    # success_reason can narrate the exfiltrated value itself (DCR-0021).
    message = redact(f"{exploit.success_reason}\n\nLocated at: {loc.label}. {loc.why}")
    proof = _proof_text(report)
    if proof:
        message = f"{message}\n\n{proof}"
    is_custom = not str(exploit.target_id).startswith("reference:")
    uri = "target.yaml" if is_custom else str(exploit.target_id)
    # A remote MCP tool has no source file in this repo, so the honest unit is a
    # SARIF logicalLocation (tool + field); the physicalLocation gets the real prompt
    # line only when we localized one, else the conventional startLine 1.
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": loc.line or 1},
        }
    }
    if loc.tool:
        location["logicalLocations"] = [
            {
                "name": loc.tool,
                "kind": "function",
                "fullyQualifiedName": f"{loc.tool}.{loc.field}" if loc.field else loc.tool,
            }
        ]
    props: dict[str, Any] = {
        "security-severity": _SECURITY_SEVERITY.get(sev, "5.0"),
        "tags": _tags(exploit.compliance),
        "weakness": weakness,
    }
    if report is not None:
        props["kept"] = bool(getattr(report, "kept", False))
    # GitHub code scanning dedups alerts across commits by partialFingerprints. Our
    # AI-layer findings have no stable source-line hash (the locus is a tool/field, and
    # a remote MCP tool has no repo file at all), so key the fingerprint on the STABLE
    # identity of the finding — pattern + weakness class + implicated locus + target —
    # not a line number. This keeps the same weakness on the same tool a single alert
    # even as line numbers or scan order move.
    fp_seed = "|".join(
        [
            str(exploit.pattern_id),
            weakness,
            loc.tool or "",
            loc.field or "",
            uri,
        ]
    )
    fingerprint = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]
    return {
        "ruleId": str(exploit.pattern_id),
        "level": _LEVEL.get(sev, "warning"),
        "message": {"text": message},
        "locations": [location],
        "partialFingerprints": {"mylonitePatternLocus/v1": fingerprint},
        "properties": props,
    }


def _rule(exploit: Any) -> dict[str, Any]:
    weakness = str((getattr(exploit.payload, "metadata", {}) or {}).get("weakness", ""))
    pid = str(exploit.pattern_id)
    return {
        "id": pid,
        "name": pid.replace("-", " ").title().replace(" ", ""),
        "shortDescription": {"text": f"AI-layer weakness ({weakness or 'AI'}): {pid}"},
        "properties": {"tags": _tags(exploit.compliance)},
    }


def to_sarif(
    findings: list[tuple[Any, Any | None]], *, tool_version: str = __version__
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from ``(exploit, validation_report | None)`` pairs.

    A scan dir yields exploits with no report (no proof); a validation yields the
    exploit + its ``ValidationReport`` (the differential proof). Both render.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for exploit, report in findings:
        pid = str(exploit.pattern_id)
        if pid not in rules:
            rules[pid] = _rule(exploit)
        results.append(_result(exploit, report))
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Mylonite",
                        "informationUri": "https://github.com/Abidemialade/mylonite",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
