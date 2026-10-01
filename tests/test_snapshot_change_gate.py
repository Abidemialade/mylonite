"""Tests for ``scripts/check_snapshot_changes.py``, which the ``Docs and
writing`` CI job runs alongside ``check_docs_sync.py``.

Hermetic: every case feeds the check file lists and labels directly, so
nothing depends on the state of the working tree.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(relative: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load("scripts/check_snapshot_changes.py", "check_snapshot_changes")

_SNAPSHOT = "tests/fixtures/exit_codes.snapshot.json"


def test_no_snapshot_changed_passes_regardless_of_labels_or_changelog() -> None:
    assert not gate.check(["src/mylonite/cli.py", "tests/test_cli.py"])


def test_snapshot_changed_with_no_label_and_no_changelog_fails_both() -> None:
    problems = gate.check([_SNAPSHOT])
    assert len(problems) == 2
    assert "snapshot-change" in problems[0].message
    assert "CHANGELOG.md" in problems[1].message


def test_snapshot_changed_with_label_but_no_changelog_fails() -> None:
    problems = gate.check([_SNAPSHOT], labels=["snapshot-change"])
    assert len(problems) == 1
    assert "CHANGELOG.md" in problems[0].message


def test_snapshot_changed_with_changelog_but_no_label_fails() -> None:
    problems = gate.check([_SNAPSHOT, "CHANGELOG.md"])
    assert len(problems) == 1
    assert "snapshot-change" in problems[0].message


def test_snapshot_changed_with_label_and_changelog_passes() -> None:
    assert not gate.check([_SNAPSHOT, "CHANGELOG.md"], labels=["snapshot-change"])


def test_label_matching_is_case_and_whitespace_insensitive() -> None:
    assert not gate.check([_SNAPSHOT, "CHANGELOG.md"], labels=[" Snapshot-Change "])


def test_unrelated_label_does_not_count() -> None:
    problems = gate.check([_SNAPSHOT, "CHANGELOG.md"], labels=["no-docs"])
    assert len(problems) == 1
    assert "snapshot-change" in problems[0].message


def test_reason_codes_snapshot_is_covered_by_the_same_glob() -> None:
    assert not gate.check(
        ["tests/fixtures/reason_codes.snapshot.json", "CHANGELOG.md"],
        labels=["snapshot-change"],
    )
    problems = gate.check(["tests/fixtures/reason_codes.snapshot.json"])
    assert len(problems) == 2


def test_non_snapshot_fixture_is_not_covered() -> None:
    assert not gate.check(["tests/fixtures/scan_report_0_10_4.json"])


def test_windows_backslash_paths_are_normalised() -> None:
    problems = gate.check(["tests\\fixtures\\exit_codes.snapshot.json"])
    assert len(problems) == 2
