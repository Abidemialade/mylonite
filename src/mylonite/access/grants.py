"""Read what a classic token or a GitHub App installation can reach.

Both paths produce one :class:`Grant`. Only metadata is read: scopes,
permissions, repository names and levels. Repositories outside the intent's
organisation are counted, never named.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mylonite.access.github_client import GitHubClient, GitHubError

Level = Literal["none", "read", "write", "admin"]


class GrantError(Exception):
    """The grant could not be read; the message is one plain line."""


@dataclass(frozen=True)
class RepoGrant:
    name: str
    level: Level
    private: bool


@dataclass(frozen=True)
class NotTested:
    item: str
    reason: str


@dataclass(frozen=True)
class Grant:
    identity_kind: Literal["github_app", "classic_token"]
    identity_label: str
    app_id: int | None
    installation_id: int | None
    scopes: tuple[str, ...]
    permissions: dict[str, str]
    repository_selection: Literal["all", "selected"] | None
    repos: tuple[RepoGrant, ...]
    repos_outside_org: int
    plan: str | None
    not_tested: tuple[NotTested, ...]


_REFUSED = "the token was refused (401)"
_OWNER_NEEDED = (
    "could not list the organisation's app installations: the owner token needs "
    "organisation-owner access"
)
_NO_APP_ID = "GitHub returned no app id for the installation"


def _read_error(exc: GitHubError) -> GrantError:
    if exc.status == 401:
        return GrantError(_REFUSED)
    return GrantError(" ".join(str(exc).split()))


def _owner_login(repo: dict[str, Any]) -> str:
    owner = repo.get("owner")
    if isinstance(owner, dict) and isinstance(owner.get("login"), str):
        return str(owner["login"])
    full = repo.get("full_name")
    return str(full).split("/", 1)[0] if isinstance(full, str) else ""


def _in_org(repo: dict[str, Any], org: str) -> bool:
    return _owner_login(repo).casefold() == org.casefold()


def _split_org(
    repos: list[dict[str, Any]], org: str
) -> tuple[list[dict[str, Any]], int, tuple[NotTested, ...]]:
    """In-org repos with a name, the outside count, and one note per nameless repo."""
    in_org = [r for r in repos if _in_org(r, org)]
    inside = [r for r in in_org if isinstance(r.get("full_name"), str)]
    nameless = tuple(
        NotTested("a repository with no name", "GitHub returned a repository without full_name")
        for r in in_org
        if not isinstance(r.get("full_name"), str)
    )
    return inside, len(repos) - len(in_org), nameless


def _read_plan(client: GitHubClient, org: str) -> tuple[str | None, tuple[NotTested, ...]]:
    try:
        response = client.get(f"/orgs/{org}")
    except GitHubError as exc:
        return None, (NotTested("plan tier", " ".join(str(exc).split())),)
    if response.status_code != 200:
        return None, (NotTested("plan tier", f"GET /orgs/{org} returned {response.status_code}"),)
    try:
        body = response.json()
    except ValueError:
        body = None
    plan = body.get("plan") if isinstance(body, dict) else None
    name = plan.get("name") if isinstance(plan, dict) else None
    if not isinstance(name, str) or not name:
        return None, (NotTested("plan tier", f"GET /orgs/{org} returned no plan name"),)
    return name, ()


def _classic_level(perms: Any, *, private: bool, has_repo: bool, has_public: bool) -> Level:
    perms = perms if isinstance(perms, dict) else {}
    if perms.get("admin"):
        level: Level = "admin"
    elif perms.get("push") or perms.get("maintain"):
        level = "write"
    elif perms.get("pull"):
        level = "read"
    else:
        level = "none"
    if level == "none":
        return level
    if not has_repo and (not has_public or private):
        return "read"
    return level


def _refuse_kind(client: GitHubClient) -> None:
    kind = client.kind
    if kind == "classic":
        return
    names = {
        "fine_grained": "a fine-grained token",
        "oauth_user": "an OAuth user token",
        "installation": "an installation token",
        "unknown": "a token of an unknown kind",
    }
    raise GrantError(f"{names.get(kind, kind)} is not covered yet; use a classic token")


def read_classic_token_grant(agent: GitHubClient, org: str) -> Grant:
    """Read the grant of a classic personal access token for ``org``."""
    _refuse_kind(agent)
    try:
        who = agent.get("/user")
    except GitHubError as exc:
        raise _read_error(exc) from None
    if who.status_code == 401:
        raise GrantError(_REFUSED)
    if who.status_code != 200:
        raise GrantError(f"GitHub GET /user returned {who.status_code}")
    try:
        body = who.json()
    except ValueError:
        body = None
    login = body.get("login") if isinstance(body, dict) else None
    if not isinstance(login, str) or not login:
        raise GrantError("GitHub GET /user returned no login")
    header = who.headers.get("X-OAuth-Scopes")
    scopes = tuple(sorted(s for s in (p.strip() for p in (header or "").split(",")) if s))
    try:
        all_repos = agent.get_all("/user/repos")
    except GitHubError as exc:
        raise _read_error(exc) from None
    inside, outside, nameless = _split_org(all_repos, org)
    # An absent header is unknown, not "no scopes": do not cap, report as-is.
    has_repo = header is None or "repo" in scopes
    has_public = "public_repo" in scopes
    repos = tuple(
        RepoGrant(
            name=str(r["full_name"]),
            level=_classic_level(
                r.get("permissions"),
                private=bool(r.get("private")),
                has_repo=has_repo,
                has_public=has_public,
            ),
            private=bool(r.get("private")),
        )
        for r in inside
    )
    plan, plan_note = _read_plan(agent, org)
    not_tested = nameless + plan_note
    if header is None:
        not_tested = (
            NotTested("token scopes", "GitHub did not return X-OAuth-Scopes"),
            *not_tested,
        )
    return Grant(
        identity_kind="classic_token",
        identity_label=login,
        app_id=None,
        installation_id=None,
        scopes=scopes,
        permissions={},
        repository_selection=None,
        repos=repos,
        repos_outside_org=outside,
        plan=plan,
        not_tested=not_tested,
    )


def _app_level(permissions: dict[str, str]) -> Level:
    if permissions.get("administration") == "write":
        return "admin"
    contents = permissions.get("contents")
    if contents == "write":
        return "write"
    if contents == "read":
        return "read"
    return "none"


def read_app_grant(owner: GitHubClient, org: str, app_slug: str) -> Grant:
    """Read the grant of ``app_slug``'s installation in ``org``.

    ``owner`` is an organisation owner's token, not the App's own.
    """
    try:
        installations = owner.get_all(f"/orgs/{org}/installations", key="installations")
    except GitHubError as exc:
        if exc.status in (403, 404):
            raise GrantError(_OWNER_NEEDED) from None
        raise _read_error(exc) from None
    row = next((i for i in installations if i.get("app_slug") == app_slug), None)
    if row is None:
        raise GrantError(f"no installation of {app_slug} in {org}")
    installation_id = row.get("id")
    if not isinstance(installation_id, int):
        raise GrantError(f"the installation of {app_slug} in {org} has no id")
    row_notes: list[NotTested] = []
    raw_app_id = row.get("app_id")
    app_id = (
        raw_app_id if isinstance(raw_app_id, int) and not isinstance(raw_app_id, bool) else None
    )
    if app_id is None:
        row_notes.append(NotTested("branch-rule bypass", _NO_APP_ID))
    raw_perms = row.get("permissions")
    if isinstance(raw_perms, dict):
        permissions = {str(k): str(v) for k, v in raw_perms.items()}
    else:
        permissions = {}
        row_notes.append(
            NotTested("app permissions", "GitHub returned no permissions for the installation")
        )
    raw_selection = row.get("repository_selection")
    selection: Literal["all", "selected"] | None = None
    if raw_selection == "all":
        selection = "all"
    elif raw_selection == "selected":
        selection = "selected"
    else:
        row_notes.append(
            NotTested("repository selection", "GitHub returned an unknown repository_selection")
        )
    try:
        listed = owner.get_all(
            f"/user/installations/{installation_id}/repositories", key="repositories"
        )
    except GitHubError as exc:
        raise _read_error(exc) from None
    inside, outside, nameless = _split_org(listed, org)
    level = _app_level(permissions)
    repos = tuple(
        RepoGrant(name=str(r["full_name"]), level=level, private=bool(r.get("private")))
        for r in inside
    )
    plan, plan_note = _read_plan(owner, org)
    not_tested = tuple(row_notes) + nameless + plan_note
    return Grant(
        identity_kind="github_app",
        identity_label=app_slug,
        app_id=app_id,
        installation_id=installation_id,
        scopes=(),
        permissions=permissions,
        repository_selection=selection,
        repos=repos,
        repos_outside_org=outside,
        plan=plan,
        not_tested=not_tested,
    )
