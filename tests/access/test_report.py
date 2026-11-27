"""Tests for the access report, its digest and its exit code."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

from mylonite.access.compare import Finding
from mylonite.access.drill import ArmResult, DrillResult, not_tested_drill
from mylonite.access.github_client import API_VERSION
from mylonite.access.grants import Grant, NotTested, RepoGrant
from mylonite.access.intent import Intent
from mylonite.access.report import (
    AccessReport,
    build_report,
    exit_code,
    input_digest,
    to_json,
    to_markdown,
)
from mylonite.exit_codes import EXIT_FINDINGS, EXIT_SUCCESS

T1 = datetime(2026, 12, 1, 9, 0, tzinfo=UTC)
T2 = datetime(2026, 12, 2, 17, 30, tzinfo=UTC)

INTENT = Intent.model_validate(
    {
        "intent_version": 0,
        "approved_by": "A. Owner",
        "approved_on": "2026-12-01",
        "organisation": "my-test-org",
        "environment": "test",
        "identity": {"kind": "github_app", "app_slug": "agent-app"},
        "repositories": [{"name": "my-test-org/app", "access": "read"}],
    }
)
GRANT = Grant(
    identity_kind="github_app",
    identity_label="agent-app",
    app_id=1,
    installation_id=7,
    scopes=(),
    permissions={"contents": "read"},
    repository_selection="selected",
    repos=(RepoGrant("my-test-org/app", "read", True),),
    repos_outside_org=0,
    plan=None,
    not_tested=(NotTested("rulesets", "forbidden (403)"),),
)
ARM = ArmResult(revoked=True, status_before=200, status_after=401, seconds=3.5)
HELD = DrillResult("revocation", "held", ARM, replace(ARM, revoked=False, status_after=200), "ok")
FINDING = Finding("REPO_NOT_INTENDED", "over_grant", "my-test-org/x", "not in intent", "remove it")
VERSIONS = {"tool_version": "0.13.0", "now": T1}

REPORT_CLEAN = build_report(INTENT, GRANT, [], HELD, (), **VERSIONS)
REPORT_WITH_FINDINGS = build_report(INTENT, GRANT, [FINDING], HELD, (), **VERSIONS)


def _digest(intent: Intent = INTENT, grant: Grant = GRANT) -> str:
    return input_digest(intent, grant, tool_version="0.13.0", api_version=API_VERSION)


def _with_drill(report: AccessReport, status: str) -> AccessReport:
    return replace(report, drill=replace(report.drill, status=status))  # type: ignore[arg-type]


def test_digest_is_stable_and_ignores_time() -> None:
    a = build_report(INTENT, GRANT, [], HELD, (), tool_version="0.13.0", now=T1)
    b = build_report(INTENT, GRANT, [], HELD, (), tool_version="0.13.0", now=T2)
    assert a.digest == b.digest and a.digest.startswith("sha256:")
    assert a.generated_at != b.generated_at


def test_digest_changes_with_the_grant_and_with_the_intent() -> None:
    other_grant = replace(GRANT, repos=(RepoGrant("my-test-org/x", "read", True),))
    other_intent = INTENT.model_copy(
        update={"escalation": INTENT.escalation.model_copy(update={"workflow_write": "allowed"})}
    )
    assert _digest(grant=other_grant) != _digest()
    assert _digest(intent=other_intent) != _digest()
    assert input_digest(INTENT, GRANT, tool_version="0.14.0", api_version=API_VERSION) != _digest()


def test_markdown_never_says_safe_or_compliant() -> None:
    for report in (REPORT_CLEAN, REPORT_WITH_FINDINGS):
        text = to_markdown(report).lower()
        assert "safe" not in text and "compliant" not in text


def test_markdown_headings_in_order() -> None:
    text = to_markdown(REPORT_CLEAN)
    heads = [
        "# Access report: agent-app in my-test-org",
        "## Summary",
        "## Could",
        "## Held",
        "## Not tested",
        "## About this report",
    ]
    positions = [text.index(h) for h in heads]
    assert positions == sorted(positions)
    assert "The grant matches the intent." in text
    assert "This report goes stale when the intent file or the grant changes." in text
    assert "unknown" in text and REPORT_CLEAN.digest in text


def test_not_tested_always_lists_the_fixed_rows() -> None:
    text = to_markdown(REPORT_CLEAN)
    for row in (
        "required review",
        "approval for destructive actions",
        "user revocation",
        "attribution",
        "what the agent did in real runs",
        "fine-grained tokens",
        "the model provider's key",
        "anything outside my-test-org",
        "rulesets",
    ):
        assert row in text


def test_summary_names_the_approver() -> None:
    expected = (
        "Compared with the intent approved by A. Owner on 2026-12-01. "
        "This result is only as good as that file."
    )
    assert expected in to_markdown(REPORT_CLEAN)


def test_held_section_shows_both_arms_and_seconds() -> None:
    text = to_markdown(REPORT_CLEAN)
    assert "held" in text and "3.5" in text


def test_json_round_trips_and_carries_the_digest() -> None:
    data = json.loads(to_json(REPORT_WITH_FINDINGS))
    assert data["digest"] == REPORT_WITH_FINDINGS.digest
    assert data["findings"][0]["code"] == "REPO_NOT_INTENDED"
    for key in ("tool_version", "api_version", "generated_at", "intent", "grant", "drill"):
        assert key in data
    assert data["not_tested"][0]["item"]


def test_not_tested_is_merged_deduplicated_and_sorted() -> None:
    extra = (NotTested("rulesets", "forbidden (403)"), NotTested("a thing", "why"))
    drill = not_tested_drill("no key")
    report = build_report(INTENT, GRANT, [], drill, extra, **VERSIONS)
    items = [(n.item, n.reason) for n in report.not_tested]
    assert items == sorted(set(items))
    assert items.count(("rulesets", "forbidden (403)")) == 1
    assert any("no key" in reason for _, reason in items)


def test_exit_codes() -> None:
    assert exit_code(REPORT_CLEAN) == EXIT_SUCCESS
    assert exit_code(REPORT_WITH_FINDINGS) == EXIT_FINDINGS
    assert exit_code(_with_drill(REPORT_CLEAN, "not_held")) == EXIT_FINDINGS
    assert exit_code(_with_drill(REPORT_CLEAN, "invalid")) == EXIT_FINDINGS
    assert exit_code(_with_drill(REPORT_CLEAN, "not_tested")) == EXIT_SUCCESS
    info = Finding("X", "info", "s", "d", "c")
    assert exit_code(build_report(INTENT, GRANT, [info], HELD, (), **VERSIONS)) == EXIT_SUCCESS


def test_markdown_table_cells_escape_pipes_and_newlines() -> None:
    finding = replace(FINDING, subject="my-test-org/a|b\nc")
    report = build_report(INTENT, GRANT, [finding], HELD, (), **VERSIONS)
    assert "a\\|b c" in to_markdown(report)
