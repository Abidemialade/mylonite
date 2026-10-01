#!/usr/bin/env python3
"""Fail when a frozen snapshot changes without a deliberate sign-off.

``tests/fixtures/*.snapshot.json`` freeze stability-promised surfaces: reason
codes, testkit signatures, CLI exit codes, and the schema/contract-version
pairing. They are allowed to change -- that is how a reviewed, intentional
addition or break ships -- but never by accident and never silently. A change
needs both:

* the ``snapshot-change`` pull-request label (a maintainer's own action, not
  something a contributor's commit message can grant), and
* a ``CHANGELOG.md`` entry in the same diff, so the change is documented where
  users read it.

Mirrors ``scripts/check_docs_sync.py``'s ``--base``/``--labels-env`` shape.

Usage::

    python scripts/check_snapshot_changes.py --base origin/main --labels-env PR_LABELS
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

CHANGELOG = "CHANGELOG.md"
SNAPSHOT_GLOB = "tests/fixtures/*.snapshot.json"
SNAPSHOT_LABEL = "snapshot-change"


@dataclass(frozen=True)
class Problem:
    message: str


def _is_snapshot(path: str) -> bool:
    return fnmatch.fnmatch(path, SNAPSHOT_GLOB)


def check(changed: Sequence[str], labels: Iterable[str] = ()) -> list[Problem]:
    """Return the sign-off this change set is missing (empty when it's fine).

    No frozen snapshot in ``changed`` -> always fine, regardless of labels.
    """
    changed_set = {p.replace("\\", "/") for p in changed}
    snapshots = sorted(p for p in changed_set if _is_snapshot(p))
    if not snapshots:
        return []

    has_label = SNAPSHOT_LABEL in {label.strip().lower() for label in labels if label.strip()}
    has_changelog = CHANGELOG in changed_set
    if has_label and has_changelog:
        return []

    sample = ", ".join(snapshots[:3]) + (" ..." if len(snapshots) > 3 else "")
    problems: list[Problem] = []
    if not has_label:
        problems.append(
            Problem(
                f"a frozen snapshot changed ({sample}) without the '{SNAPSHOT_LABEL}' label. "
                "Ask a maintainer to add it once the change is reviewed as intentional."
            )
        )
    if not has_changelog:
        problems.append(
            Problem(
                f"a frozen snapshot changed ({sample}) but {CHANGELOG} has no entry for it. "
                "Add a line under ## [Unreleased]."
            )
        )
    return problems


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        # A stalled git (lock, credential prompt) fails the gate fast
        # instead of hanging the CI job.
        timeout=60,
    ).stdout


def changed_files(base: str) -> list[str]:
    # Same shape as check_docs_sync.py: everything since the branch left
    # `base`, tracked and untracked, so this also sees uncommitted local work.
    fork = _git("merge-base", base, "HEAD").strip()
    tracked = _git("diff", "--name-only", fork).splitlines()
    untracked = _git("ls-files", "--others", "--exclude-standard").splitlines()
    return sorted(set(tracked) | set(untracked))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base", required=True, help="compare HEAD with this ref")
    parser.add_argument(
        "--labels-env", help="environment variable holding comma-separated PR labels"
    )
    args = parser.parse_args(argv)

    labels = os.environ.get(args.labels_env, "").split(",") if args.labels_env else []
    problems = check(changed_files(args.base), labels)
    if not problems:
        print("frozen snapshots unchanged, or changed with sign-off")
        return 0
    print("A frozen snapshot changed without the required sign-off:\n", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
