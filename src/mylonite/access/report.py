"""The access report: Markdown and JSON, with a digest of its inputs."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mylonite._markdown import code_span, strip_controls
from mylonite.access.compare import Finding
from mylonite.access.drill import ArmResult, DrillResult
from mylonite.access.github_client import API_VERSION
from mylonite.access.grants import Grant, NotTested
from mylonite.access.intent import Intent
from mylonite.exit_codes import EXIT_FINDINGS, EXIT_SUCCESS

__all__ = [
    "AccessReport",
    "build_report",
    "exit_code",
    "input_digest",
    "to_json",
    "to_markdown",
]

# (item, reason) rows that are always listed, after the collected ones.
_FIXED_NOT_TESTED = (
    ("required review", "not checked in this version"),
    ("approval for destructive actions", "not checked in this version"),
    ("user revocation", "not drilled in this version"),
    ("attribution", "not checked in this version"),
    ("what the agent did in real runs", "no seeded runs in this version"),
    ("fine-grained tokens", "only classic tokens and GitHub App installations are read"),
    ("the model provider's key", "not read or drilled"),
    ("anything outside <organisation>", "the run is limited to <organisation>"),
)


@dataclass(frozen=True)
class AccessReport:
    tool_version: str
    api_version: str
    generated_at: str
    intent: Intent
    grant: Grant
    findings: tuple[Finding, ...]
    drill: DrillResult
    not_tested: tuple[NotTested, ...]
    digest: str


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def input_digest(intent: Intent, grant: Grant, *, tool_version: str, api_version: str) -> str:
    """sha256 over the intent, the grant and the versions. Time is not an input."""
    payload = {
        "intent": intent.model_dump(mode="json"),
        "grant": dataclasses.asdict(grant),
        "tool_version": tool_version,
        "api_version": api_version,
    }
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def build_report(
    intent: Intent,
    grant: Grant,
    findings: list[Finding] | tuple[Finding, ...],
    drill: DrillResult,
    extra_not_tested: tuple[NotTested, ...] | list[NotTested],
    *,
    tool_version: str,
    now: datetime,
) -> AccessReport:
    collected = {*grant.not_tested, *extra_not_tested}
    if drill.status == "not_tested":
        collected.add(NotTested("revocation drill", drill.reason))
    sorted_findings = sorted(
        findings, key=lambda f: (f.status, f.code, f.subject, f.detail, f.change)
    )
    return AccessReport(
        tool_version=tool_version,
        api_version=API_VERSION,
        generated_at=now.astimezone(UTC).isoformat(timespec="seconds"),
        intent=intent,
        grant=grant,
        findings=tuple(sorted_findings),
        drill=drill,
        not_tested=tuple(sorted(collected, key=lambda n: (n.item, n.reason))),
        digest=input_digest(intent, grant, tool_version=tool_version, api_version=API_VERSION),
    )


def _clean(value: Any) -> Any:
    """Strip control characters from every string in a JSON-bound structure."""
    if isinstance(value, str):
        return strip_controls(value)
    if isinstance(value, dict):
        return {strip_controls(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def to_json(report: AccessReport) -> str:
    data = {
        "digest": report.digest,
        "tool_version": report.tool_version,
        "api_version": report.api_version,
        "generated_at": report.generated_at,
        "intent": report.intent.model_dump(mode="json"),
        "grant": dataclasses.asdict(report.grant),
        "findings": [dataclasses.asdict(f) for f in report.findings],
        "drill": dataclasses.asdict(report.drill),
        "not_tested": [dataclasses.asdict(n) for n in report.not_tested],
    }
    return json.dumps(_clean(data), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def exit_code(report: AccessReport) -> int:
    if any(f.status in ("over_grant", "escalation") for f in report.findings):
        return EXIT_FINDINGS
    if report.drill.status in ("not_held", "invalid"):
        return EXIT_FINDINGS
    return EXIT_SUCCESS


def _arm(name: str, arm: ArmResult | None) -> str:
    if arm is None:
        return f"| {name} | not run | | | |"
    revoked = "yes" if arm.revoked else "no"
    return f"| {name} | {revoked} | {arm.status_before} | {arm.status_after} | {arm.seconds:.1f} |"


def _cell(value: Any) -> str:
    return code_span(value, table=True)


def to_markdown(report: AccessReport) -> str:
    intent = report.intent
    org = intent.organisation
    approved_on = intent.approved_on.isoformat() if intent.approved_on else "an unknown date"
    lines = [
        f"# Access report: {code_span(report.grant.identity_label)} in {code_span(org)}",
        "",
        "## Summary",
        "",
        f"Compared with the intent approved by {strip_controls(intent.approved_by)} "
        f"on {approved_on}. This result is only as good as that file.",
        "",
        "## Could",
        "",
    ]
    if report.findings:
        lines += [
            "| Code | Status | Subject | Detail | Change |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {_cell(f.code)} | {_cell(f.status)} | {_cell(f.subject)} "
            f"| {_cell(f.detail)} | {_cell(f.change)} |"
            for f in report.findings
        ]
    else:
        lines.append("The grant matches the intent.")
    drill = report.drill
    lines += [
        "",
        "## Held",
        "",
        f"Revocation drill: {drill.status}. {code_span(drill.reason)}",
        "",
        "| Arm | Revoked | Status before | Status after | Seconds |",
        "|---|---|---|---|---|",
        _arm("with the control", drill.with_control),
        _arm("control removed", drill.control_removed),
        "",
        "## Not tested",
        "",
        "| Item | Reason |",
        "|---|---|",
    ]
    lines += [f"| {_cell(n.item)} | {_cell(n.reason)} |" for n in report.not_tested]
    seen = {n.item for n in report.not_tested}
    for item, reason in _FIXED_NOT_TESTED:
        if item.replace("<organisation>", org) in seen:
            continue
        shown = code_span(org, table=True)
        lines.append(
            f"| {item.replace('<organisation>', shown)} | {reason.replace('<organisation>', shown)} |"
        )
    lines += [
        "",
        "## About this report",
        "",
        f"- Digest: `{report.digest}`",
        f"- Tool version: {report.tool_version}",
        f"- API version: {report.api_version}",
        f"- Plan tier: {code_span(report.grant.plan) if report.grant.plan else 'unknown'}",
        f"- Generated at: {report.generated_at}",
        "",
        "This report goes stale when the intent file or the grant changes.",
        "",
    ]
    return "\n".join(lines)
