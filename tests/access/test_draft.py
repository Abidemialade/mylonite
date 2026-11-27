"""Draft an unapproved intent file from a grant."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
from tests.access.test_compare import (
    GRANT_CLASSIC,
    GRANT_MATCHING,
    ORG,
    reader_from,
    with_permission,
    with_scopes,
)

from mylonite.access.compare import escalation_findings
from mylonite.access.draft import draft_intent_yaml
from mylonite.access.grants import RepoGrant
from mylonite.access.intent import IntentError, load_intent, require_approved


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "intent.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_draft_round_trips_but_is_not_approved(tmp_path: Path) -> None:
    intent = load_intent(write(tmp_path, draft_intent_yaml(GRANT_MATCHING, ORG)))
    assert [r.name for r in intent.repositories] == [f"{ORG}/docs", f"{ORG}/service-a"]
    assert intent.permissions["contents"] == "write"
    assert intent.identity.app_slug == "coding-agent"
    assert intent.approved_on is None
    with pytest.raises(IntentError, match="not approved"):
        require_approved(intent)


def test_classic_draft_uses_scopes(tmp_path: Path) -> None:
    intent = load_intent(write(tmp_path, draft_intent_yaml(GRANT_CLASSIC, ORG)))
    assert intent.identity.kind == "classic_token"
    assert intent.scopes == sorted(set(GRANT_CLASSIC.scopes))
    assert intent.permissions == {}


def test_draft_starts_with_the_comment() -> None:
    first = draft_intent_yaml(GRANT_MATCHING, ORG).splitlines()[0]
    assert first == (
        "# Drafted from the current grant. Remove what the agent should not have, "
        "then fill in approved_by and approved_on."
    )


def test_draft_never_allows_an_escalation(tmp_path: Path) -> None:
    text = draft_intent_yaml(with_permission(GRANT_MATCHING, "workflows", "write"), ORG)
    assert "workflow_write: forbidden" in text
    assert "branch_rule_bypass: forbidden" in text
    assert "allowed" not in text


def test_a_draft_approved_unchanged_still_reports_workflow_write(tmp_path: Path) -> None:
    grant = with_permission(GRANT_MATCHING, "workflows", "write")
    intent = load_intent(write(tmp_path, draft_intent_yaml(grant, ORG)))
    approved = intent.model_copy(update={"approved_by": "owner", "approved_on": date(2026, 11, 27)})
    findings, _ = escalation_findings(approved, grant, reader_from())
    assert "ESC_WORKFLOW_WRITE" in [f.code for f in findings]


def test_classic_workflow_scope_is_still_forbidden(tmp_path: Path) -> None:
    grant = with_scopes(GRANT_CLASSIC, "repo", "workflow")
    intent = load_intent(write(tmp_path, draft_intent_yaml(grant, ORG)))
    assert intent.escalation.workflow_write == "forbidden"


def test_admin_is_written_as_write_with_a_comment(tmp_path: Path) -> None:
    grant = replace(
        GRANT_MATCHING,
        repos=(RepoGrant(f"{ORG}/service-a", "admin", True),),
        permissions={"contents": "admin", "metadata": "read"},
    )
    text = draft_intent_yaml(grant, ORG)
    assert "    access: write  # the grant is admin, which is higher than write" in text
    assert '"contents": write  # the grant is admin' in text
    intent = load_intent(write(tmp_path, text))
    assert intent.repositories[0].access == "write"
    assert intent.permissions["contents"] == "write"


def test_hostile_repository_name_cannot_inject_yaml(tmp_path: Path) -> None:
    hostile = f'{ORG}/x"\napproved_by: attacker\n#'
    grant = replace(GRANT_MATCHING, repos=(RepoGrant(hostile, "write", True),))
    text = draft_intent_yaml(grant, ORG)
    assert "\napproved_by: attacker" not in text
    intent = load_intent(write(tmp_path, text))
    assert intent.approved_by == ""
    assert intent.repositories[0].name == hostile


def test_draft_is_deterministic_under_reordering() -> None:
    flipped = replace(GRANT_MATCHING, repos=tuple(reversed(GRANT_MATCHING.repos)))
    assert draft_intent_yaml(flipped, ORG) == draft_intent_yaml(GRANT_MATCHING, ORG)
