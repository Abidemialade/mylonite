"""Tests for the access report, its digest and its exit code."""

from __future__ import annotations

import json
import re
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
        "# Access report: `agent-app` in `my-test-org`",
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
        "anything outside `my-test-org`",
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


def test_an_escalation_finding_exits_with_findings() -> None:
    escalation = Finding("ESC_WORKFLOW_WRITE", "escalation", "my-test-org/app", "d", "c")
    report = build_report(INTENT, GRANT, [escalation], HELD, (), **VERSIONS)
    assert exit_code(report) == EXIT_FINDINGS


def test_summary_without_approved_on_says_an_unknown_date() -> None:
    intent = INTENT.model_copy(update={"approved_on": None})
    report = build_report(intent, GRANT, [], HELD, (), **VERSIONS)
    expected = (
        "Compared with the intent approved by A. Owner on an unknown date. "
        "This result is only as good as that file."
    )
    assert expected in to_markdown(report)


ESC = chr(0x1B)
BIDI = chr(0x202E)
LSEP = chr(0x2028)
HOSTILE = (
    "a" + chr(92) + "|b",
    "<script>x</script>",
    "[a](http://b)",
    "tick`here",
    ESC + "[31mred",
    "bidi" + BIDI + "evil" + LSEP + "line",
)
_BAD_CHARS = re.compile(
    "["
    + chr(0)
    + "-"
    + chr(8)
    + chr(0x0B)
    + "-"
    + chr(0x1F)
    + chr(0x7F)
    + "-"
    + chr(0x9F)
    + chr(0x2028)
    + chr(0x2029)
    + chr(0x202A)
    + "-"
    + chr(0x202E)
    + chr(0x2066)
    + "-"
    + chr(0x2069)
    + "]"
)


def _outside_code_spans(text: str) -> str:
    return re.sub(r"(`+)(?:(?!\1).)+?\1", "", text, flags=re.S)


def _hostile_report() -> AccessReport:
    findings = [replace(FINDING, subject=v, detail=v, change=v) for v in HOSTILE]
    grant = replace(GRANT, identity_label=HOSTILE[1], plan=HOSTILE[2])
    drill = replace(HELD, reason="line one|x" + chr(10) + "line two " + ESC + "[31m<b>")
    extra = (NotTested(HOSTILE[2], HOSTILE[0]),)
    return build_report(INTENT, grant, findings, drill, extra, **VERSIONS)


def test_hostile_values_stay_inside_code_spans() -> None:
    text = to_markdown(_hostile_report())
    outside = _outside_code_spans(text)
    for raw in ("<script>", "[a](", "<b>", ESC):
        assert raw not in outside
    assert not _BAD_CHARS.search(text.replace("\n", ""))
    held = next(line for line in text.splitlines() if line.startswith("Revocation drill"))
    assert held == "Revocation drill: held. `line one|xline two [31m<b>`"


def test_a_backslash_cannot_let_a_pipe_split_the_cell() -> None:
    finding = replace(FINDING, subject="a\\|b")
    report = build_report(INTENT, GRANT, [finding], HELD, (), **VERSIONS)
    row = next(r for r in to_markdown(report).splitlines() if "REPO_NOT_INTENDED" in r)
    # Cells split on a pipe not preceded by a backslash: five columns remain.
    assert len(re.split(r"(?<!\\)\|", row.strip())) == 7
    assert "a\\\\|b" in row


def test_table_cell_newline_and_pipe_do_not_split_the_row() -> None:
    finding = replace(FINDING, subject="my-test-org/a|b\nc")
    report = build_report(INTENT, GRANT, [finding], HELD, (), **VERSIONS)
    row = next(r for r in to_markdown(report).splitlines() if "REPO_NOT_INTENDED" in r)
    assert "a\\|bc" in row
    assert len(re.split(r"(?<!\\)\|", row.strip())) == 7


def test_json_strips_control_characters() -> None:
    finding = replace(FINDING, subject="x" + ESC + "[31m" + BIDI + "y")
    raw = to_json(build_report(INTENT, GRANT, [finding], HELD, (), **VERSIONS))
    assert ESC not in raw and BIDI not in raw and "\u001b" not in raw
    assert json.loads(raw)["findings"][0]["subject"] == "x[31my"


def test_collected_not_tested_replaces_the_fixed_row() -> None:
    extra = (NotTested("attribution", "checked by hand"),)
    text = to_markdown(build_report(INTENT, GRANT, [], HELD, extra, **VERSIONS))
    assert text.count("attribution") == 1
    assert "checked by hand" in text


def test_json_strips_control_characters_inside_grant_tuples() -> None:
    grant = replace(
        GRANT,
        scopes=("repo" + ESC + "x",),
        repos=(RepoGrant("my-test-org/a" + ESC + "b", "read", True),),
    )
    raw = to_json(build_report(INTENT, grant, [], HELD, (), **VERSIONS))
    assert ESC not in raw and "\u001b" not in raw
    data = json.loads(raw)["grant"]
    assert data["scopes"] == ["repox"]
    assert data["repos"][0]["name"] == "my-test-org/ab"
