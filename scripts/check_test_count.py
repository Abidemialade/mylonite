#!/usr/bin/env python3
"""Fail the build when the test suite shrinks without saying so.

Compares ``pytest --collect-only -q``'s collected-test count against a floor
committed in ``tests/test_count_floor.txt``. A count at or above the floor
passes silently; a count below it fails, unless the PR carries the
``tests-removed`` label (the same ``--labels-env`` shape
``scripts/check_docs_sync.py`` uses for its own label-gated opt-out).

This is a floor, not an exact match: the count is free to grow (a PR that
adds tests never has to remember to bump this file), but it can only ever be
LOWERED by raising the floor in the same PR -- a deliberate, reviewable
edit, not a side effect of deleting tests. Raise the floor to the new count
whenever you want to lock in a gain.

Usage::

    python scripts/check_test_count.py
    python scripts/check_test_count.py --labels-env PR_LABELS
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLOOR_FILE = ROOT / "tests" / "test_count_floor.txt"
ALLOW_LABELS = frozenset({"tests-removed"})

_COUNT_RE = re.compile(r"(\d+)\s+tests?\s+collected")


class CollectionError(RuntimeError):
    """``pytest --collect-only`` did not produce a readable count."""


def read_floor(path: Path = FLOOR_FILE) -> int:
    text = path.read_text(encoding="utf-8").strip()
    try:
        return int(text)
    except ValueError as exc:
        raise CollectionError(f"{path} does not contain a single integer: {text!r}") from exc


def collected_count(*, cwd: Path | None = None) -> int:
    """Run ``pytest --collect-only -q`` and return the number collected.

    Raises :class:`CollectionError` if pytest exited non-zero (a real
    collection error -- a broken import, a bad conftest -- is never silently
    read as "fewer tests") or if the final summary line's count can't be
    parsed (a pytest output-format change should fail loudly here, not be
    misread as a regression).
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=cwd or ROOT,
    )
    tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-15:])
    if proc.returncode != 0:
        raise CollectionError(f"pytest --collect-only -q exited {proc.returncode}:\n{tail}")
    match = None
    for line in reversed(proc.stdout.splitlines()):
        found = _COUNT_RE.search(line)
        if found:
            match = found
            break
    if match is None:
        raise CollectionError(f"could not find a '<N> tests collected' line:\n{tail}")
    return int(match.group(1))


def _labels_from_env(var: str | None) -> set[str]:
    if not var:
        return set()
    raw = os.environ.get(var, "")
    return {label.strip().lower() for label in raw.split(",") if label.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--labels-env", help="environment variable holding comma-separated PR labels"
    )
    args = parser.parse_args(argv)

    try:
        floor = read_floor()
        count = collected_count()
    except CollectionError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if count >= floor:
        extra = f" (above the floor of {floor})" if count > floor else " (matches the floor)"
        print(f"{count} tests collected{extra}")
        return 0

    labels = _labels_from_env(args.labels_env)
    if ALLOW_LABELS & labels:
        print(
            f"{count} tests collected, below the floor of {floor} in "
            f"{FLOOR_FILE.relative_to(ROOT)} -- allowed by the 'tests-removed' label. "
            "Lower the floor in this PR to lock in the new count."
        )
        return 0

    print(
        f"test count dropped to {count}, below the committed floor of {floor} in "
        f"{FLOOR_FILE.relative_to(ROOT)}.\n"
        "If tests were deliberately removed, add the 'tests-removed' label to the PR "
        "and lower the floor in the same PR. Otherwise this is a real regression -- "
        "find what stopped collecting.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
