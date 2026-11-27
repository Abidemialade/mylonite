"""Compare a real grant with the owner-approved intent, and check two escalations.

:func:`compare_grant` is pure: it turns the intent and the grant into findings
with no network call. :func:`escalation_findings` reads repository rulesets to
check whether the agent can bypass branch rules; any read that fails becomes a
"not tested" entry, never a clean result. Every finding names the configuration
change that would clear it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mylonite.access.github_client import GitHubClient, GitHubError
from mylonite.access.grants import Grant, NotTested, RepoGrant
from mylonite.access.intent import Intent

Status = Literal["over_grant", "escalation", "info"]

_RANK = {"none": 0, "read": 1, "write": 2, "admin": 3}

_WORKFLOW_DETAIL = (
    "The agent can change what the pipeline runs, and so reach the secrets the pipeline holds."
)
_CLASSIC_PROTECTION = NotTested("classic branch protection bypass", "only rulesets are read")
# Every GitHub App holds metadata: read; the owner cannot remove it.
_MANDATORY_APP_PERMISSIONS = {"metadata": "read"}


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    subject: str
    detail: str
    change: str


def _rank(level: str) -> int:
    # An unknown level is treated as the highest, so it is reported, not hidden.
    return _RANK.get(level.casefold(), _RANK["admin"])


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.status, f.code, f.subject, f.detail, f.change))


def _holder(grant: Grant) -> str:
    if grant.identity_kind == "github_app":
        return "the installation"
    return "the token's user"


def _identity(intent: Intent, grant: Grant) -> list[Finding]:
    want = intent.identity
    if want.kind != grant.identity_kind:
        return [
            Finding(
                code="IDENTITY_MISMATCH",
                status="over_grant",
                subject=grant.identity_label,
                detail=f"The intent names a {want.kind} identity; the grant is a "
                f"{grant.identity_kind}.",
                change=f"Point the check at the {want.kind} the intent names, "
                "or correct identity.kind in the intent file.",
            )
        ]
    if want.kind == "github_app" and (want.app_slug or "").casefold() != (
        grant.identity_label.casefold()
    ):
        return [
            Finding(
                code="IDENTITY_MISMATCH",
                status="over_grant",
                subject=grant.identity_label,
                detail=f"The intent names the app {want.app_slug}; the grant belongs to "
                f"{grant.identity_label}.",
                change=f"Point the check at the {want.app_slug} installation, "
                "or correct identity.app_slug in the intent file.",
            )
        ]
    return []


def _repositories(intent: Intent, grant: Grant) -> list[Finding]:
    findings: list[Finding] = []
    wanted = {r.name.casefold(): r for r in intent.repositories}
    granted = {r.name.casefold() for r in grant.repos}
    holder = _holder(grant)
    for repo in grant.repos:
        want = wanted.get(repo.name.casefold())
        if want is None:
            if grant.identity_kind == "github_app":
                change = f"Remove {repo.name} from the installation's repository access."
            else:
                change = f"Remove the token's user from {repo.name}, or use a token whose "
                change += "user cannot reach it."
            findings.append(
                Finding(
                    code="REPO_NOT_INTENDED",
                    status="over_grant",
                    subject=repo.name,
                    detail=f"{holder.capitalize()} has {repo.level} access to {repo.name}, "
                    "which the intent does not list.",
                    change=change,
                )
            )
        elif _rank(repo.level) > _rank(want.access):
            findings.append(
                Finding(
                    code="REPO_LEVEL_ABOVE_INTENT",
                    status="over_grant",
                    subject=repo.name,
                    detail=f"{holder.capitalize()} has {repo.level} access to {repo.name}; "
                    f"the intent allows {want.access}.",
                    change=f"Lower {holder}'s access to {repo.name} to {want.access}.",
                )
            )
    for want in intent.repositories:
        if want.name.casefold() not in granted:
            findings.append(
                Finding(
                    code="INTENDED_NOT_GRANTED",
                    status="info",
                    subject=want.name,
                    detail=f"The intent lists {want.name} with {want.access} access, "
                    f"but {holder} cannot reach it.",
                    change=f"Give {holder} {want.access} access to {want.name}, "
                    "or remove it from the intent file.",
                )
            )
    if grant.repos_outside_org > 0:
        count = grant.repos_outside_org
        noun = "repository" if count == 1 else "repositories"
        findings.append(
            Finding(
                code="REPO_NOT_INTENDED",
                status="over_grant",
                subject=f"{count} {noun} outside {intent.organisation}",
                detail=f"{holder.capitalize()} can reach {count} {noun} outside "
                f"{intent.organisation}; their names are not recorded.",
                change=f"Use an identity that can reach only {intent.organisation}.",
            )
        )
    if grant.repository_selection == "all":
        findings.append(
            Finding(
                code="ALL_REPOS_SELECTED",
                status="over_grant",
                subject=grant.identity_label,
                detail="The installation can reach every repository in the organisation, "
                "including ones created later.",
                change="Switch the installation's repository access to selected repositories.",
            )
        )
    return findings


def _permissions(intent: Intent, grant: Grant) -> list[Finding]:
    findings: list[Finding] = []
    wanted = {k.casefold(): v for k, v in intent.permissions.items()}
    for name, level in grant.permissions.items():
        want = wanted.get(name.casefold())
        if want is None and _MANDATORY_APP_PERMISSIONS.get(name.casefold()) == level.casefold():
            continue
        if want is None:
            findings.append(
                Finding(
                    code="PERMISSION_NOT_INTENDED",
                    status="over_grant",
                    subject=name,
                    detail=f"The installation holds {name}: {level}, which the intent "
                    "does not list.",
                    change=f"Remove the {name} permission from the app.",
                )
            )
        elif _rank(level) > _rank(want):
            findings.append(
                Finding(
                    code="PERMISSION_ABOVE_INTENT",
                    status="over_grant",
                    subject=name,
                    detail=f"The installation holds {name}: {level}; the intent allows {want}.",
                    change=f"Lower the app's {name} permission to {want}.",
                )
            )
    return findings


def _scopes(intent: Intent, grant: Grant) -> list[Finding]:
    wanted = {s.casefold() for s in intent.scopes}
    return [
        Finding(
            code="SCOPE_NOT_INTENDED",
            status="over_grant",
            subject=scope,
            detail=f"The token carries the {scope} scope, which the intent does not list.",
            change=f"Issue a new token without the {scope} scope and revoke this one.",
        )
        for scope in grant.scopes
        if scope.casefold() not in wanted
    ]


def compare_grant(intent: Intent, grant: Grant) -> list[Finding]:
    """Compare ``grant`` with ``intent``. Pure: no network call."""
    findings = _identity(intent, grant) + _repositories(intent, grant)
    if grant.identity_kind == "github_app":
        findings += _permissions(intent, grant)
    else:
        findings += _scopes(intent, grant)
    return _sorted(findings)


def _workflow_write(grant: Grant) -> Finding | None:
    if grant.identity_kind == "github_app":
        perms = {k.casefold(): v.casefold() for k, v in grant.permissions.items()}
        if perms.get("workflows") != "write":
            return None
        return Finding(
            code="ESC_WORKFLOW_WRITE",
            status="escalation",
            subject=grant.identity_label,
            detail=_WORKFLOW_DETAIL,
            change="Lower the app's workflows permission to read or remove it.",
        )
    scopes = {s.casefold() for s in grant.scopes}
    if not {"repo", "workflow"} <= scopes:
        return None
    return Finding(
        code="ESC_WORKFLOW_WRITE",
        status="escalation",
        subject=grant.identity_label,
        detail=_WORKFLOW_DETAIL,
        change="Issue a new token without the workflow scope and revoke this one.",
    )


def _read_failed(exc: GitHubError) -> str:
    if exc.status is not None and exc.status != 200:
        return f"{exc.status} reading rulesets"
    return "no usable response reading rulesets"


def _app_bypasses(actors: list[Any], grant: Grant) -> bool:
    """True when the App itself is listed as a bypass actor."""
    if grant.app_id is None:
        return False
    return any(
        isinstance(actor, dict)
        and actor.get("actor_type") == "Integration"
        and actor.get("actor_id") == grant.app_id
        for actor in actors
    )


def _classic_unjudged(actors: list[Any], item: str) -> list[NotTested]:
    """One note per non-Integration actor type a classic token cannot be judged against.

    Whether the token's user is covered by a role, team, organisation-admin or
    other actor needs membership data this slice does not read.
    """
    kinds: set[str] = set()
    for actor in actors:
        if not isinstance(actor, dict):
            continue
        kind = actor.get("actor_type")
        label = kind if isinstance(kind, str) and kind else "of unknown type"
        if label != "Integration":
            kinds.add(label)
    return [
        NotTested(item, f"bypass actor {kind} not evaluated for a classic token")
        for kind in sorted(kinds)
    ]


def _repo_bypass(
    reader: GitHubClient, grant: Grant, repo: RepoGrant
) -> tuple[list[Finding], list[NotTested]]:
    item = f"branch-rule bypass on {repo.name}"
    base = f"/repos/{repo.name}/rulesets"
    try:
        listed = reader.get_all(base)
    except GitHubError as exc:
        return [], [NotTested(item, _read_failed(exc))]
    findings: list[Finding] = []
    not_tested: list[NotTested] = []
    for row in listed:
        rid = row.get("id")
        if not isinstance(rid, int) or isinstance(rid, bool):
            not_tested.append(NotTested(item, "GitHub returned a ruleset with no id"))
            continue
        try:
            response = reader.get(f"{base}/{rid}")
        except GitHubError as exc:
            not_tested.append(NotTested(item, _read_failed(exc)))
            continue
        if response.status_code != 200:
            not_tested.append(NotTested(item, f"{response.status_code} reading rulesets"))
            continue
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or not isinstance(body.get("bypass_actors"), list):
            not_tested.append(NotTested(item, f"ruleset {rid} returned no bypass_actors"))
            continue
        actors: list[Any] = body["bypass_actors"]
        if grant.identity_kind != "github_app":
            not_tested += _classic_unjudged(actors, item)
            continue
        if _app_bypasses(actors, grant):
            raw_name = body.get("name")
            name = raw_name if isinstance(raw_name, str) and raw_name else str(rid)
            enforcement = body.get("enforcement")
            state = (
                f" The ruleset's enforcement is {enforcement}."
                if isinstance(enforcement, str) and enforcement
                else ""
            )
            findings.append(
                Finding(
                    code="ESC_BRANCH_RULE_BYPASS",
                    status="escalation",
                    subject=f"{repo.name} ruleset {name} ({rid})",
                    detail=f"The app {grant.identity_label} is a bypass actor on the ruleset "
                    f"{name} on {repo.name}, so the branch rules it sets do not bind the "
                    f"agent.{state}",
                    change=f"Remove the app {grant.identity_label} from the bypass list of "
                    f"the ruleset {name} on {repo.name}.",
                )
            )
    return findings, not_tested


def escalation_findings(
    intent: Intent, grant: Grant, reader: GitHubClient
) -> tuple[list[Finding], list[NotTested]]:
    """Check the workflow-write and branch-rule-bypass escalations.

    ``reader`` reads rulesets: the owner client for an App, the agent client
    for a classic token. A ruleset read that fails is reported as not tested.
    """
    findings: list[Finding] = []
    not_tested: list[NotTested] = []
    if intent.escalation.workflow_write == "forbidden":
        workflow = _workflow_write(grant)
        if workflow is not None:
            findings.append(workflow)
    if intent.escalation.branch_rule_bypass == "forbidden":
        for repo in sorted(grant.repos, key=lambda r: r.name.casefold()):
            repo_findings, repo_not_tested = _repo_bypass(reader, grant, repo)
            findings += repo_findings
            not_tested += repo_not_tested
        not_tested.append(_CLASSIC_PROTECTION)
    return _sorted(findings), sorted(set(not_tested), key=lambda n: (n.item, n.reason))
