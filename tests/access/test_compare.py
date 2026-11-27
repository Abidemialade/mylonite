"""Compare a grant with the intent, and the two escalation rules."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Any

import httpx
import pytest
from tests.access.conftest import Route, mock_client

from mylonite.access import (
    Finding,
    GitHubClient,
    Grant,
    Intent,
    Level,
    RepoGrant,
    compare_grant,
    escalation_findings,
)

ORG = "my-test-org"
APP_ID = 4242

INTENT_APP = Intent.model_validate(
    {
        "intent_version": 0,
        "approved_by": "owner",
        "approved_on": date(2026, 11, 20),
        "organisation": ORG,
        "environment": "test",
        "identity": {"kind": "github_app", "app_slug": "coding-agent"},
        "repositories": [
            {"name": f"{ORG}/service-a", "access": "write"},
            {"name": f"{ORG}/docs", "access": "read"},
        ],
        "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"},
    }
)

GRANT_MATCHING = Grant(
    identity_kind="github_app",
    identity_label="coding-agent",
    app_id=APP_ID,
    installation_id=99,
    scopes=(),
    permissions={"contents": "write", "pull_requests": "write", "metadata": "read"},
    repository_selection="selected",
    repos=(
        RepoGrant(f"{ORG}/service-a", "write", True),
        RepoGrant(f"{ORG}/docs", "read", False),
    ),
    repos_outside_org=0,
    plan="team",
    not_tested=(),
)

INTENT_CLASSIC = Intent.model_validate(
    {
        "intent_version": 0,
        "approved_by": "owner",
        "approved_on": date(2026, 11, 20),
        "organisation": ORG,
        "environment": "test",
        "identity": {"kind": "classic_token"},
        "repositories": [{"name": f"{ORG}/service-a", "access": "write"}],
        "scopes": ["repo"],
    }
)

GRANT_CLASSIC = Grant(
    identity_kind="classic_token",
    identity_label="agent-bot",
    app_id=None,
    installation_id=None,
    scopes=("repo",),
    permissions={},
    repository_selection=None,
    repos=(RepoGrant(f"{ORG}/service-a", "write", True),),
    repos_outside_org=0,
    plan="team",
    not_tested=(),
)

GRANT_MESSY = replace(
    GRANT_MATCHING,
    repository_selection="all",
    permissions={
        "contents": "write",
        "pull_requests": "write",
        "metadata": "read",
        "issues": "write",
        "administration": "write",
        "workflows": "write",
    },
    repos=(
        RepoGrant(f"{ORG}/service-a", "admin", True),
        RepoGrant(f"{ORG}/payroll", "admin", True),
        RepoGrant(f"{ORG}/infra", "admin", True),
        RepoGrant(f"{ORG}/billing", "admin", False),
    ),
    repos_outside_org=3,
)


# -- helpers -------------------------------------------------------------------


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


def with_repo(grant: Grant, name: str, level: Level) -> Grant:
    return replace(grant, repos=(*grant.repos, RepoGrant(name, level, True)))


def without_repo(grant: Grant, name: str) -> Grant:
    return replace(grant, repos=tuple(r for r in grant.repos if r.name != name))


def with_permission(grant: Grant, key: str, value: str) -> Grant:
    return replace(grant, permissions={**grant.permissions, key: value})


def with_intent_permission(intent: Intent, key: str, value: str) -> Intent:
    return intent.model_copy(update={"permissions": {**intent.permissions, key: value}})


def with_scopes(grant: Grant, *scopes: str) -> Grant:
    return replace(grant, scopes=tuple(scopes))


def with_escalation(intent: Intent, **fields: str) -> Intent:
    return intent.model_copy(update={"escalation": intent.escalation.model_copy(update=fields)})


def shuffled(grant: Grant) -> Grant:
    """The same grant with every collection in reverse order."""
    return replace(
        grant,
        repos=tuple(reversed(grant.repos)),
        permissions=dict(reversed(list(grant.permissions.items()))),
        scopes=tuple(reversed(grant.scopes)),
    )


def _repo_names() -> set[str]:
    return {r.name for g in (GRANT_MATCHING, GRANT_CLASSIC, GRANT_MESSY) for r in g.repos}


def reader_from(
    rulesets: dict[str, list[dict[str, Any]]] | None = None,
    details: dict[tuple[str, int], Route] | None = None,
    list_status: int = 200,
) -> GitHubClient:
    """A reader whose rulesets come from ``rulesets`` (default: none per repo)."""
    rulesets = rulesets or {}
    routes: dict[tuple[str, str], Route] = {}
    for name in _repo_names():
        if list_status != 200:
            routes[("GET", f"/repos/{name}/rulesets")] = httpx.Response(
                list_status, json={"message": "Not allowed"}
            )
        else:
            routes[("GET", f"/repos/{name}/rulesets")] = httpx.Response(
                200, json=rulesets.get(name, [])
            )
    for (name, rid), route in (details or {}).items():
        routes[("GET", f"/repos/{name}/rulesets/{rid}")] = route
    return mock_client(routes)


@pytest.fixture
def reader() -> GitHubClient:
    return reader_from()


def reader_with_bypass(
    *, actor_type: str, actor_id: int | None, repo: str = f"{ORG}/service-a"
) -> GitHubClient:
    return reader_from(
        rulesets={repo: [{"id": 7, "name": "protect main"}]},
        details={
            (repo, 7): httpx.Response(
                200,
                json={
                    "id": 7,
                    "name": "protect main",
                    "bypass_actors": [
                        {"actor_id": actor_id, "actor_type": actor_type, "bypass_mode": "always"}
                    ],
                },
            )
        },
    )


def reader_with_rulesets_status(status: int) -> GitHubClient:
    return reader_from(list_status=status)


# -- compare_grant -------------------------------------------------------------


def test_exact_match_has_no_findings() -> None:
    assert compare_grant(INTENT_APP, GRANT_MATCHING) == []


def test_classic_exact_match_has_no_findings() -> None:
    assert compare_grant(INTENT_CLASSIC, GRANT_CLASSIC) == []


def test_extra_repository_is_an_over_grant() -> None:
    [f] = compare_grant(INTENT_APP, with_repo(GRANT_MATCHING, f"{ORG}/payroll", "write"))
    assert (f.code, f.status, f.subject) == ("REPO_NOT_INTENDED", "over_grant", f"{ORG}/payroll")
    assert "remove" in f.change.lower()


def test_repository_names_compare_case_insensitively_and_keep_github_spelling() -> None:
    grant = replace(
        GRANT_MATCHING,
        repos=(
            RepoGrant("My-Test-Org/Service-A", "write", True),
            RepoGrant("my-test-org/DOCS", "admin", False),
        ),
    )
    [f] = compare_grant(INTENT_APP, grant)
    assert (f.code, f.subject) == ("REPO_LEVEL_ABOVE_INTENT", "my-test-org/DOCS")


def test_level_above_intent() -> None:
    grant = replace(
        GRANT_MATCHING,
        repos=(
            RepoGrant(f"{ORG}/service-a", "write", True),
            RepoGrant(f"{ORG}/docs", "write", False),
        ),
    )
    [f] = compare_grant(INTENT_APP, grant)
    assert (f.code, f.status, f.subject) == (
        "REPO_LEVEL_ABOVE_INTENT",
        "over_grant",
        f"{ORG}/docs",
    )
    assert "write" in f.detail and "read" in f.detail


def test_write_intent_is_exceeded_only_by_admin() -> None:
    lower = without_repo(GRANT_MATCHING, f"{ORG}/service-a")
    for level, expected in (("read", []), ("write", []), ("admin", ["REPO_LEVEL_ABOVE_INTENT"])):
        grant = with_repo(lower, f"{ORG}/service-a", level)  # type: ignore[arg-type]
        assert codes(compare_grant(INTENT_APP, grant)) == expected, level


def test_all_repositories_selection_fires() -> None:
    findings = compare_grant(INTENT_APP, replace(GRANT_MATCHING, repository_selection="all"))
    assert "ALL_REPOS_SELECTED" in codes(findings)
    [f] = [f for f in findings if f.code == "ALL_REPOS_SELECTED"]
    assert "selected repositories" in f.change.lower()


def test_permission_above_intent() -> None:
    grant = with_permission(GRANT_MATCHING, "pull_requests", "write")
    intent = with_intent_permission(INTENT_APP, "pull_requests", "read")
    assert codes(compare_grant(intent, grant)) == ["PERMISSION_ABOVE_INTENT"]


def test_permission_not_intended() -> None:
    [f] = compare_grant(INTENT_APP, with_permission(GRANT_MATCHING, "issues", "read"))
    assert (f.code, f.status, f.subject) == ("PERMISSION_NOT_INTENDED", "over_grant", "issues")


def test_permissions_do_not_apply_to_a_classic_token() -> None:
    intent = with_intent_permission(INTENT_CLASSIC, "contents", "read")
    assert compare_grant(intent, GRANT_CLASSIC) == []


def test_scope_not_intended() -> None:
    [f] = compare_grant(INTENT_CLASSIC, with_scopes(GRANT_CLASSIC, "repo", "delete_repo"))
    assert (f.code, f.status, f.subject) == ("SCOPE_NOT_INTENDED", "over_grant", "delete_repo")


def test_scopes_do_not_apply_to_an_app() -> None:
    intent = INTENT_APP.model_copy(update={"scopes": []})
    assert compare_grant(intent, with_scopes(GRANT_MATCHING, "admin:org")) == []


def test_identity_kind_mismatch() -> None:
    assert "IDENTITY_MISMATCH" in codes(compare_grant(INTENT_APP, GRANT_CLASSIC))


def test_app_slug_mismatch_and_case_insensitive_match() -> None:
    assert "IDENTITY_MISMATCH" in codes(
        compare_grant(INTENT_APP, replace(GRANT_MATCHING, identity_label="other-app"))
    )
    assert compare_grant(INTENT_APP, replace(GRANT_MATCHING, identity_label="Coding-Agent")) == []


def test_intended_but_not_granted_is_info_only() -> None:
    [f] = compare_grant(INTENT_APP, without_repo(GRANT_MATCHING, f"{ORG}/service-a"))
    assert (f.code, f.status) == ("INTENDED_NOT_GRANTED", "info")


def test_outside_org_repos_are_counted_not_named() -> None:
    [f] = [
        f
        for f in compare_grant(INTENT_CLASSIC, replace(GRANT_CLASSIC, repos_outside_org=14))
        if f.code == "REPO_NOT_INTENDED"
    ]
    assert "14" in f.subject
    assert "/" not in f.subject


def test_findings_are_in_a_stable_order() -> None:
    a = compare_grant(INTENT_APP, GRANT_MESSY)
    b = compare_grant(INTENT_APP, shuffled(GRANT_MESSY))
    assert a == b
    keys = [(f.status, f.code, f.subject) for f in a]
    assert keys == sorted(keys)


def test_change_text_is_plain() -> None:
    for f in compare_grant(INTENT_APP, GRANT_MESSY):
        assert f.change.endswith(".")
        assert "safe" not in f.change.lower()


# -- escalation_findings: workflow write ---------------------------------------


def test_workflow_write_fires_for_app_and_for_classic(reader: GitHubClient) -> None:
    app = escalation_findings(
        INTENT_APP, with_permission(GRANT_MATCHING, "workflows", "write"), reader
    )
    assert "ESC_WORKFLOW_WRITE" in codes(app[0])
    classic = escalation_findings(
        INTENT_CLASSIC, with_scopes(GRANT_CLASSIC, "repo", "workflow"), reader
    )
    assert "ESC_WORKFLOW_WRITE" in codes(classic[0])
    [f] = [f for f in app[0] if f.code == "ESC_WORKFLOW_WRITE"]
    assert f.status == "escalation"
    assert "secrets" in f.detail


def test_workflow_read_or_workflow_scope_alone_is_silent(reader: GitHubClient) -> None:
    app = escalation_findings(
        INTENT_APP, with_permission(GRANT_MATCHING, "workflows", "read"), reader
    )
    assert "ESC_WORKFLOW_WRITE" not in codes(app[0])
    classic = escalation_findings(INTENT_CLASSIC, with_scopes(GRANT_CLASSIC, "workflow"), reader)
    assert "ESC_WORKFLOW_WRITE" not in codes(classic[0])


def test_workflow_write_allowed_by_intent_is_silent(reader: GitHubClient) -> None:
    intent = with_escalation(INTENT_APP, workflow_write="allowed")
    findings = escalation_findings(
        intent, with_permission(GRANT_MATCHING, "workflows", "write"), reader
    )[0]
    assert "ESC_WORKFLOW_WRITE" not in codes(findings)


# -- escalation_findings: branch-rule bypass -----------------------------------


def test_app_listed_as_bypass_actor_fires() -> None:
    findings, _ = escalation_findings(
        INTENT_APP,
        GRANT_MATCHING,
        reader_with_bypass(actor_type="Integration", actor_id=GRANT_MATCHING.app_id),
    )
    assert "ESC_BRANCH_RULE_BYPASS" in codes(findings)
    [f] = findings
    assert f.status == "escalation"
    assert f"{ORG}/service-a" in f.subject


def test_other_integration_as_bypass_actor_is_silent() -> None:
    findings, _ = escalation_findings(
        INTENT_APP, GRANT_MATCHING, reader_with_bypass(actor_type="Integration", actor_id=1)
    )
    assert findings == []


def test_classic_admin_with_role_bypass_fires_and_write_does_not() -> None:
    admin = replace(GRANT_CLASSIC, repos=(RepoGrant(f"{ORG}/service-a", "admin", True),))
    for actor_type in ("OrganizationAdmin", "RepositoryRole"):
        findings, _ = escalation_findings(
            INTENT_CLASSIC, admin, reader_with_bypass(actor_type=actor_type, actor_id=5)
        )
        assert codes(findings) == ["ESC_BRANCH_RULE_BYPASS"], actor_type
    findings, _ = escalation_findings(
        INTENT_CLASSIC,
        GRANT_CLASSIC,
        reader_with_bypass(actor_type="RepositoryRole", actor_id=5),
    )
    assert findings == []


def test_unreadable_rulesets_are_not_tested_never_clean() -> None:
    findings, not_tested = escalation_findings(
        INTENT_APP, GRANT_MATCHING, reader_with_rulesets_status(403)
    )
    assert "ESC_BRANCH_RULE_BYPASS" not in codes(findings)
    assert any(f"branch-rule bypass on {ORG}/service-a" == n.item for n in not_tested)
    [n] = [n for n in not_tested if n.item == f"branch-rule bypass on {ORG}/service-a"]
    assert n.reason == "403 reading rulesets"


def test_unreadable_ruleset_detail_is_not_tested() -> None:
    reader = reader_from(
        rulesets={f"{ORG}/service-a": [{"id": 7, "name": "protect main"}]},
        details={(f"{ORG}/service-a", 7): httpx.Response(404, json={"message": "Not Found"})},
    )
    findings, not_tested = escalation_findings(INTENT_APP, GRANT_MATCHING, reader)
    assert findings == []
    assert any(
        n.item == f"branch-rule bypass on {ORG}/service-a" and n.reason == "404 reading rulesets"
        for n in not_tested
    )


def test_ruleset_without_bypass_actors_is_not_tested() -> None:
    reader = reader_from(
        rulesets={f"{ORG}/service-a": [{"id": 7, "name": "protect main"}]},
        details={(f"{ORG}/service-a", 7): httpx.Response(200, json={"id": 7, "name": "x"})},
    )
    findings, not_tested = escalation_findings(INTENT_APP, GRANT_MATCHING, reader)
    assert findings == []
    assert any(n.item == f"branch-rule bypass on {ORG}/service-a" for n in not_tested)


def test_no_response_reading_rulesets_is_not_tested() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    routes: dict[tuple[str, str], Route] = {
        ("GET", f"/repos/{r.name}/rulesets"): boom for r in GRANT_MATCHING.repos
    }
    findings, not_tested = escalation_findings(INTENT_APP, GRANT_MATCHING, mock_client(routes))
    assert findings == []
    items = {n.item for n in not_tested}
    assert {f"branch-rule bypass on {r.name}" for r in GRANT_MATCHING.repos} <= items


def test_classic_branch_protection_is_always_not_tested(reader: GitHubClient) -> None:
    _, not_tested = escalation_findings(INTENT_APP, GRANT_MATCHING, reader)
    assert any(
        (n.item, n.reason) == ("classic branch protection bypass", "only rulesets are read")
        for n in not_tested
    )


def test_bypass_allowed_by_intent_makes_no_calls() -> None:
    intent = with_escalation(INTENT_APP, branch_rule_bypass="allowed")
    findings, _ = escalation_findings(intent, GRANT_MATCHING, mock_client({}))
    assert findings == []


def test_no_repositories_makes_no_ruleset_calls() -> None:
    grant = replace(GRANT_MATCHING, repos=())
    findings, not_tested = escalation_findings(INTENT_APP, grant, mock_client({}))
    assert findings == []
    assert [n.item for n in not_tested] == ["classic branch protection bypass"]
