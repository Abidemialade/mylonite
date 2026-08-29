"""Tests for ``scripts/check_sensitive_paths.py``.

The interesting property is the pairing: the guard must fire on every file that
controls a control, and stay quiet on ordinary source — a tripwire that fires on
routine pull requests gets labelled reflexively, which is the same as not having
one.
"""

from __future__ import annotations

import pytest
from scripts import check_sensitive_paths as guard


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/actions/setup/action.yml",
        "gate-action/action.yml",
        ".pre-commit-config.yaml",
        "pyproject.toml",
        "scripts/check_reference_target_inert.py",
        "scripts/check_sensitive_paths.py",
        ".secrets.baseline",
        "reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/server_vulnerable.py",
        "reference_targets/mcp_kitchen_sink/seeds/seeds.yaml",
    ],
)
def test_flags_trust_base_files(path: str) -> None:
    assert guard.classify([path]), f"{path} should be treated as sensitive"


@pytest.mark.parametrize(
    "path",
    [
        "src/mylonite/cli.py",
        "src/mylonite/scan/engine.py",
        "tests/test_cli_keyless.py",
        "docs/quickstart.md",
        "README.md",
        "CHANGELOG.md",
        "verification/campaign.py",
        "scripts/regenerate_schemas.py",  # a script, but not a check_* guard
    ],
)
def test_ignores_ordinary_files(path: str) -> None:
    assert guard.classify([path]) == [], f"{path} should not trip the guard"


def test_each_hit_carries_a_reason() -> None:
    """The failure message has to say why, or it reads as bureaucracy."""
    for path, reason in guard.classify([".github/workflows/ci.yml", "pyproject.toml"]):
        assert reason.strip(), f"{path} was flagged with no explanation"


def test_a_file_is_reported_once_even_if_two_patterns_match() -> None:
    hits = guard.classify(["reference_targets/mcp_kitchen_sink/pyproject.toml"])
    assert len(hits) == 1


def test_override_label_is_not_self_grantable_by_name() -> None:
    """Guards against someone 'fixing' this by keying off a PR-body string.

    Labels need write access; text a contributor controls does not. If this
    constant ever stops being a label, the override stops being a gate.
    """
    assert guard.OVERRIDE_LABEL == "reviewed:sensitive-paths"
