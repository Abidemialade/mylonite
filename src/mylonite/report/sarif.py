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
from mylonite._twin_fidelity import guarded_twin_layer, proof_claim
from mylonite._verdict import verdict_reason
from mylonite.gate.localize import localize
from mylonite.report.severity import severity_for
from mylonite.report.verdict import (
    KEPT,
    REJECTED,
    UNVALIDATED,
    finding_verdict,
    proof_status,
)
from mylonite.version import __version__

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
#: The level each verdict maps to. GitHub code scanning shows `level` on every
#: alert, so only a KEPT finding (a passing build and a passing differential or
#: effect leg) is an `error`. A scan finding nobody validated and a keep that
#: proved no safeguard are `warning`; a rejected finding is a `note`.
_VERDICT_LEVEL = {KEPT: "error", UNVALIDATED: "warning", REJECTED: "note"}
_DEFAULT_LEVEL = "warning"
#: GitHub code scanning reads `security-severity` (0-10) to bucket findings
#: (7.0 and up is High). Emitted for KEPT findings only: an unproven finding
#: carries no severity, so it can never be bucketed as High.
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
    """The validation result, claimed only as strongly as the verdict allows.

    This artefact is uploaded to GitHub code scanning, where it persists in the
    Security tab and gets quoted back months later, so it is the worst surface on
    which to overstate what a run proved. The guarded-twin claim appears only on a
    KEPT verdict, worded for the twin that ran (``_twin_fidelity``). Any other
    verdict reports the counts and says what they showed.
    """
    if report is None:
        return (
            "Not validated: a scan finding from a single run. Run `mylonite validate` "
            "on it before treating it as real."
        )
    repro = getattr(report, "reproducibility", None)
    label = finding_verdict(report)
    if label == KEPT:
        verdict = "Verdict: KEPT."
    elif label == REJECTED:
        verdict = (
            f"Verdict: REJECTED ({proof_status(report)}); "
            "this run proves nothing about a safeguard."
        )
    else:
        verdict = f"Verdict: {label}: {verdict_reason(report)}"
    if repro is None or not getattr(repro, "iterations", 0):
        return verdict
    it = repro.iterations
    vf = repro.vuln_fired
    gr = repro.guard_resisted
    if label != KEPT:
        guard = "" if gr is None else f" and was resisted {gr}/{it} with the control applied"
        return f"Validation: the attack fired {vf}/{it} on the target{guard}. {verdict}"
    if gr is None:
        return (
            f"Reproducible: the attack fired {vf}/{it} times on the target "
            f"(no guarded twin). {verdict}"
        )
    return (
        f"Differential proof: the attack fired {vf}/{it} on the vulnerable target and was "
        f"resisted {gr}/{it} with the control applied — "
        f"{proof_claim(guarded_twin_layer(report))}. {verdict}"
    )


def _result(
    exploit: Any,
    report: Any | None,
    *,
    system_prompt: str | None = None,
    target: Any | None = None,
) -> dict[str, Any]:
    weakness = str((getattr(exploit.payload, "metadata", {}) or {}).get("weakness", ""))
    effect = str(getattr(exploit.response, "metadata", {}).get("effect_confirmed", "unprobed"))
    sev = severity_for(weakness, effect)
    # PR6: fall back to the target's own system prompt so this result's
    # localize() call agrees with the one recommend() makes internally below
    # — a caller that passes target= but not system_prompt= must not get two
    # different line numbers for the same finding across the two calls.
    if system_prompt is None and target is not None:
        system_prompt = getattr(target, "system_prompt", None)
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
    verdict = finding_verdict(report)
    props: dict[str, Any] = {
        "verdict": verdict,
        "tags": _tags(exploit.compliance),
        "weakness": weakness,
    }
    if verdict == KEPT:
        props["security-severity"] = _SECURITY_SEVERITY.get(sev, "5.0")
    proof_level = (getattr(exploit.payload, "metadata", {}) or {}).get("proof_level")
    if proof_level:
        # How strongly the trace showed this finding (effect-confirmed, dispatched
        # or dispatched-tool-linked). Absent for a finding with no trace.
        props["mylonite.proofLevel"] = str(proof_level)
    if report is not None:
        props["kept"] = bool(getattr(report, "kept", False))
        # Machine-readable alongside the prose claim, so a consumer triaging SARIF
        # programmatically can tell a server-layer proof from a boundary proxy
        # without parsing the message text.
        props["guardedTwinLayer"] = guarded_twin_layer(report)
    # PR6: the structural recommendation, when a TargetContext is available.
    # Deliberately in `properties`, not SARIF's `result.fixes` -- `fixes[].
    # artifactChanges` requires a real artifact URI + region to apply a
    # patch against, and a remote MCP tool has no repo file to point one at
    # (the same honesty `localize.py`'s docstring is built on). GitHub code
    # scanning renders `properties` fine; it just isn't a one-click "Apply
    # fix" the way `fixes` would be, which is the correct level of claim.
    if target is not None:
        from mylonite.gate.recommend import recommend, to_dict

        props["mylonite.recommendation"] = to_dict(recommend(exploit, report, target=target))
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
        "level": _VERDICT_LEVEL.get(verdict, _DEFAULT_LEVEL),
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
    findings: list[tuple[Any, Any | None]],
    *,
    tool_version: str = __version__,
    target: Any | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from ``(exploit, validation_report | None)`` pairs.

    A scan dir yields exploits with no report (no proof); a validation yields the
    exploit + its ``ValidationReport`` (the differential proof). Both render.

    ``target`` (PR6): an optional ``mylonite.gate.recommend.TargetContext``,
    shared across every finding (mirrors ``report/bundle.to_bundle``). When
    supplied, each result's ``properties["mylonite.recommendation"]`` carries
    the same structural recommendation ``build_pr_body``/the JSON bundle
    render, via the shared ``recommend.to_dict`` serializer.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for exploit, report in findings:
        pid = str(exploit.pattern_id)
        if pid not in rules:
            rules[pid] = _rule(exploit)
        results.append(_result(exploit, report, target=target))
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
