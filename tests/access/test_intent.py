from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.access.intent import IntentError, load_intent, require_approved

VALID_APP = """\
intent_version: 0
approved_by: "A. Owner"
approved_on: 2026-12-01
organisation: my-test-org
environment: test
identity:
  kind: github_app
  app_slug: my-coding-agent
repositories:
  - name: my-test-org/service-a
    access: write
permissions:
  contents: write
  pull_requests: write
  metadata: read
scopes: []
escalation:
  workflow_write: forbidden
  branch_rule_bypass: forbidden
controls:
  revocation: expected
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "intent.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_a_valid_app_intent(tmp_path):
    intent = load_intent(write(tmp_path, VALID_APP))
    assert intent.organisation == "my-test-org"
    assert intent.identity.kind == "github_app"
    assert intent.repositories[0].access == "write"
    assert intent.escalation.workflow_write == "forbidden"


def test_unknown_field_is_refused(tmp_path):
    with pytest.raises(IntentError, match="repositorys"):
        load_intent(write(tmp_path, VALID_APP.replace("repositories:", "repositorys:")))


def test_environment_other_than_test_is_refused(tmp_path):
    with pytest.raises(IntentError, match="environment"):
        load_intent(
            write(tmp_path, VALID_APP.replace("environment: test", "environment: production"))
        )


def test_repository_outside_the_organisation_is_refused(tmp_path):
    with pytest.raises(IntentError, match="other-org/x"):
        load_intent(write(tmp_path, VALID_APP.replace("my-test-org/service-a", "other-org/x")))


def test_app_identity_needs_a_slug(tmp_path):
    with pytest.raises(IntentError, match="app_slug"):
        load_intent(write(tmp_path, VALID_APP.replace("  app_slug: my-coding-agent\n", "")))


def test_unapproved_intent_is_refused(tmp_path):
    intent = load_intent(
        write(tmp_path, VALID_APP.replace('approved_by: "A. Owner"', 'approved_by: ""'))
    )
    with pytest.raises(IntentError, match="not approved"):
        require_approved(intent)


def test_missing_file_and_bad_yaml_give_one_line(tmp_path):
    with pytest.raises(IntentError):
        load_intent(tmp_path / "absent.yaml")
    with pytest.raises(IntentError) as exc:
        load_intent(write(tmp_path, "intent_version: [0"))
    assert "\n" not in str(exc.value)
