"""Tests for reading a real GitHub grant."""

from __future__ import annotations

import httpx
import pytest
from tests.access.conftest import Route, mock_client

from mylonite.access.grants import (
    GrantError,
    read_app_grant,
    read_classic_token_grant,
)

ORG = "my-test-org"


def _repo(full: str, *, push: bool = False, pull: bool = True, admin: bool = False, private=True):
    return {
        "full_name": full,
        "private": private,
        "owner": {"login": full.split("/")[0]},
        "permissions": {"admin": admin, "push": push, "pull": pull},
    }


def _classic_routes(scopes: str = "repo, workflow, read:org", repos=None) -> dict:
    if repos is None:
        repos = [
            _repo("my-test-org/a", push=True),
            _repo("my-test-org/b"),
            _repo("other-org/secret", admin=True, push=True),
        ]
    return {
        ("GET", "/user"): httpx.Response(
            200, json={"login": "octo-owner"}, headers={"X-OAuth-Scopes": scopes}
        ),
        ("GET", "/user/repos"): httpx.Response(200, json=repos),
        ("GET", f"/orgs/{ORG}"): httpx.Response(200, json={"plan": {"name": "team"}}),
    }


def test_classic_scopes_come_from_the_header():
    grant = read_classic_token_grant(mock_client(_classic_routes()), ORG)
    assert grant.scopes == ("read:org", "repo", "workflow")
    assert grant.identity_label == "octo-owner"
    assert grant.identity_kind == "classic_token"
    assert grant.permissions == {}
    assert grant.app_id is None and grant.installation_id is None
    assert grant.repository_selection is None
    assert grant.plan == "team"


def test_classic_repo_levels_and_outside_count():
    grant = read_classic_token_grant(mock_client(_classic_routes()), ORG)
    assert {r.name: r.level for r in grant.repos} == {
        "my-test-org/a": "write",
        "my-test-org/b": "read",
    }
    assert grant.repos_outside_org == 1
    assert "other-org" not in repr(grant)
    assert "secret" not in repr(grant)


def test_classic_org_match_is_case_insensitive_and_keeps_spelling():
    routes = _classic_routes(repos=[_repo("My-Test-Org/A", push=True)])
    grant = read_classic_token_grant(mock_client(routes), ORG)
    assert [r.name for r in grant.repos] == ["My-Test-Org/A"]
    assert grant.repos_outside_org == 0


def test_classic_admin_and_maintain_levels():
    repos = [
        _repo("my-test-org/adm", admin=True, push=True),
        {
            "full_name": "my-test-org/mnt",
            "private": True,
            "owner": {"login": ORG},
            "permissions": {"maintain": True, "pull": True},
        },
    ]
    grant = read_classic_token_grant(mock_client(_classic_routes(repos=repos)), ORG)
    assert {r.name: r.level for r in grant.repos} == {
        "my-test-org/adm": "admin",
        "my-test-org/mnt": "write",
    }


def test_classic_without_repo_scope_is_read_only():
    grant = read_classic_token_grant(mock_client(_classic_routes(scopes="read:org")), ORG)
    assert grant.repos
    assert all(r.level == "read" for r in grant.repos)


def test_classic_public_repo_scope_caps_private_repos_only():
    repos = [
        _repo("my-test-org/pub", push=True, private=False),
        _repo("my-test-org/priv", push=True, private=True),
    ]
    grant = read_classic_token_grant(
        mock_client(_classic_routes(scopes="public_repo", repos=repos)), ORG
    )
    assert {r.name: r.level for r in grant.repos} == {
        "my-test-org/pub": "write",
        "my-test-org/priv": "read",
    }


def test_classic_unreadable_plan_goes_to_not_tested():
    routes = _classic_routes()
    routes[("GET", f"/orgs/{ORG}")] = httpx.Response(403, json={"message": "no"})
    grant = read_classic_token_grant(mock_client(routes), ORG)
    assert grant.plan is None
    assert any(n.item == "plan tier" for n in grant.not_tested)


def test_fine_grained_token_is_refused_by_name():
    with pytest.raises(GrantError, match="fine-grained"):
        read_classic_token_grant(mock_client({}, token="github_pat_" + "x" * 30), ORG)


def test_unknown_token_is_refused_by_name():
    with pytest.raises(GrantError, match="not covered yet"):
        read_classic_token_grant(mock_client({}, token="weird-token"), ORG)  # noqa: S106


def test_refused_token_is_one_plain_line():
    routes: dict[tuple[str, str], Route] = {
        ("GET", "/user"): httpx.Response(401, json={"message": "Bad credentials"})
    }
    with pytest.raises(GrantError, match=r"the token was refused \(401\)") as exc:
        read_classic_token_grant(mock_client(routes), ORG)
    assert "\n" not in str(exc.value)


def test_classic_repo_listing_failure_keeps_the_status():
    routes = _classic_routes()
    routes[("GET", "/user/repos")] = httpx.Response(500, json={})
    with pytest.raises(GrantError, match="500"):
        read_classic_token_grant(mock_client(routes), ORG)


def _app_routes(*, installations=None, plan: httpx.Response | None = None) -> dict:
    if installations is None:
        installations = [
            {
                "id": 77,
                "app_id": 12,
                "app_slug": "my-coding-agent",
                "repository_selection": "selected",
                "permissions": {"contents": "write", "metadata": "read", "workflows": "write"},
            }
        ]
    return {
        ("GET", f"/orgs/{ORG}/installations"): httpx.Response(
            200, json={"total_count": len(installations), "installations": installations}
        ),
        ("GET", "/user/installations/77/repositories"): httpx.Response(
            200,
            json={
                "total_count": 1,
                "repositories": [_repo("my-test-org/service-a")],
            },
        ),
        ("GET", f"/orgs/{ORG}"): plan or httpx.Response(200, json={"plan": {"name": "free"}}),
    }


def test_app_grant_reads_permissions_and_selected_repos():
    grant = read_app_grant(mock_client(_app_routes()), ORG, "my-coding-agent")
    assert grant.permissions == {"contents": "write", "metadata": "read", "workflows": "write"}
    assert grant.repository_selection == "selected"
    assert [r.name for r in grant.repos] == ["my-test-org/service-a"]
    assert grant.repos[0].level == "write"
    assert grant.identity_kind == "github_app"
    assert grant.identity_label == "my-coding-agent"
    assert (grant.app_id, grant.installation_id) == (12, 77)
    assert grant.plan == "free"
    assert grant.repos_outside_org == 0


def test_app_levels_from_contents_permission():
    for contents, level in (("read", "read"), (None, "none")):
        perms = {"metadata": "read"}
        if contents:
            perms["contents"] = contents
        inst = [{"id": 77, "app_id": 12, "app_slug": "my-coding-agent", "permissions": perms}]
        grant = read_app_grant(mock_client(_app_routes(installations=inst)), ORG, "my-coding-agent")
        assert grant.repos[0].level == level


def test_app_administration_write_makes_every_level_admin():
    perms = {"contents": "read", "administration": "write"}
    inst = [{"id": 77, "app_id": 12, "app_slug": "my-coding-agent", "permissions": perms}]
    grant = read_app_grant(mock_client(_app_routes(installations=inst)), ORG, "my-coding-agent")
    assert all(r.level == "admin" for r in grant.repos)


def test_missing_installation_is_a_clear_error():
    routes = _app_routes(installations=[])
    with pytest.raises(GrantError, match="no installation of my-coding-agent in my-test-org"):
        read_app_grant(mock_client(routes), ORG, "my-coding-agent")


def test_unreadable_plan_goes_to_not_tested():
    routes = _app_routes(plan=httpx.Response(403, json={"message": "no"}))
    grant = read_app_grant(mock_client(routes), ORG, "my-coding-agent")
    assert grant.plan is None
    assert any(n.item == "plan tier" for n in grant.not_tested)


def test_plan_without_name_goes_to_not_tested():
    routes = _app_routes(plan=httpx.Response(200, json={"plan": None}))
    grant = read_app_grant(mock_client(routes), ORG, "my-coding-agent")
    assert grant.plan is None
    assert any(n.item == "plan tier" for n in grant.not_tested)


@pytest.mark.parametrize("status", [403, 404])
def test_installation_list_denied_says_owner_access_needed(status):
    routes = _app_routes()
    routes[("GET", f"/orgs/{ORG}/installations")] = httpx.Response(status, json={})
    with pytest.raises(GrantError, match="organisation-owner access"):
        read_app_grant(mock_client(routes), ORG, "my-coding-agent")


def test_installation_list_401_is_refused_token():
    routes = _app_routes()
    routes[("GET", f"/orgs/{ORG}/installations")] = httpx.Response(401, json={})
    with pytest.raises(GrantError, match=r"the token was refused \(401\)"):
        read_app_grant(mock_client(routes), ORG, "my-coding-agent")


def test_app_repo_listing_failure_keeps_the_status():
    routes = _app_routes()
    routes[("GET", "/user/installations/77/repositories")] = httpx.Response(500, json={})
    with pytest.raises(GrantError, match="500"):
        read_app_grant(mock_client(routes), ORG, "my-coding-agent")


def test_classic_absent_scopes_header_is_not_treated_as_no_scopes():
    routes = _classic_routes()
    routes[("GET", "/user")] = httpx.Response(200, json={"login": "octo-owner"})
    grant = read_classic_token_grant(mock_client(routes), ORG)
    assert grant.scopes == ()
    assert any(n.item == "token scopes" for n in grant.not_tested)
    assert {r.name: r.level for r in grant.repos}["my-test-org/a"] == "write"


def test_classic_empty_scopes_header_is_real_no_scopes():
    grant = read_classic_token_grant(mock_client(_classic_routes(scopes="")), ORG)
    assert grant.scopes == ()
    assert not any(n.item == "token scopes" for n in grant.not_tested)
    assert all(r.level == "read" for r in grant.repos)


def test_classic_repo_without_full_name_is_noted_not_dropped_silently():
    repos = [
        _repo("my-test-org/a", push=True),
        {"owner": {"login": ORG}, "private": True, "permissions": {"push": True}},
        {"owner": {"login": ORG}, "private": True, "permissions": {"push": True}},
    ]
    grant = read_classic_token_grant(mock_client(_classic_routes(repos=repos)), ORG)
    assert [r.name for r in grant.repos] == ["my-test-org/a"]
    notes = [n for n in grant.not_tested if n.item == "a repository with no name"]
    assert len(notes) == 2
    assert grant.repos_outside_org == 0


def test_app_outside_repo_counted_and_mixed_case_org_matches():
    routes = _app_routes()
    routes[("GET", "/user/installations/77/repositories")] = httpx.Response(
        200,
        json={
            "total_count": 2,
            "repositories": [_repo("My-Test-ORG/service-a"), _repo("other-org/secret")],
        },
    )
    grant = read_app_grant(mock_client(routes), ORG, "my-coding-agent")
    assert [r.name for r in grant.repos] == ["My-Test-ORG/service-a"]
    assert grant.repos_outside_org == 1
    assert "other-org" not in repr(grant)
