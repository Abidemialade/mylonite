#!/usr/bin/env python3
"""Fail when a factual claim and ``docs/claims.md`` have drifted apart.

A claim in ``README.md`` or a ``docs/journey/*.md`` page carries an inline
``<!-- claim:some-id -->`` comment on its own line, immediately above the
sentence it covers. ``docs/claims.md`` has one row per id: the claim in
short, and a real file/test/result path as its evidence.

Two directions, both checked:

* **Forward.** Every marker found in a source file has a row in the
  register. A marker with no row is a claim nobody has written evidence
  for.
* **Backward.** Every row in the register is still referenced by a marker
  somewhere. A row with no marker is stale: either the claim was removed
  from the docs and the row should go too, or the id was typo'd.

Usage::

    python scripts/check_claims_register.py
    python scripts/check_claims_register.py --repo-root /path/to/checkout
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER_PATH = "docs/claims.md"

#: Files a factual claim may live in. README.md is explicit; the journey
#: pages are the other launch-facing surface DOC-C adds. Widen this list if
#: another page starts carrying claim markers.
CLAIM_SOURCE_GLOBS = ("README.md", "docs/journey/*.md")

_MARKER_RE = re.compile(r"<!--\s*claim:([a-z0-9][a-z0-9-]*)\s*-->")
_REGISTER_ROW_RE = re.compile(r"^\|\s*`([a-z0-9][a-z0-9-]*)`\s*\|", re.MULTILINE)


@dataclass(frozen=True)
class Problem:
    message: str


def _claim_sources(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in CLAIM_SOURCE_GLOBS:
        paths.extend(sorted(repo_root.glob(pattern)))
    return [p for p in paths if p.is_file()]


def find_markers(repo_root: Path) -> dict[str, list[str]]:
    """``{claim_id: ["path:line", ...]}`` for every marker found."""
    found: dict[str, list[str]] = {}
    for path in _claim_sources(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for match in _MARKER_RE.finditer(line):
                found.setdefault(match.group(1), []).append(f"{rel}:{lineno}")
    return found


def find_register_ids(repo_root: Path) -> list[str]:
    """Every id in ``docs/claims.md``'s table, in file order, duplicates kept
    (the caller decides what to do with a repeat)."""
    text = (repo_root / REGISTER_PATH).read_text(encoding="utf-8")
    return _REGISTER_ROW_RE.findall(text)


def check(repo_root: Path) -> list[Problem]:
    markers = find_markers(repo_root)
    register_ids = find_register_ids(repo_root)
    register_set = set(register_ids)

    problems: list[Problem] = []

    missing_rows = sorted(set(markers) - register_set)
    for claim_id in missing_rows:
        locations = ", ".join(markers[claim_id])
        problems.append(
            Problem(
                f"claim:{claim_id} is marked at {locations} but has no row in "
                f"{REGISTER_PATH}. Add one: the claim in short, and a real file/test/"
                "result path as evidence."
            )
        )

    stale_rows = sorted(register_set - set(markers))
    for claim_id in stale_rows:
        problems.append(
            Problem(
                f"{REGISTER_PATH} has a row for claim:{claim_id}, but no "
                f"<!-- claim:{claim_id} --> marker exists in {' or '.join(CLAIM_SOURCE_GLOBS)}. "
                "Delete the row, or restore the marker if the claim is still made."
            )
        )

    seen: set[str] = set()
    for claim_id in register_ids:
        if claim_id in seen:
            problems.append(Problem(f"{REGISTER_PATH} has more than one row for claim:{claim_id}."))
        seen.add(claim_id)

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    problems = check(args.repo_root)
    if not problems:
        print(f"claims register in sync ({len(find_register_ids(args.repo_root))} claims)")
        return 0
    print(f"{REGISTER_PATH} is out of sync with the docs:\n", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
