#!/usr/bin/env python3
"""Fail when code changes without the docs that describe it.

Two rules, both from ``docs/contributing/writing-style.md``:

1. A change under ``src/``, a reference target's package or the reusable
   ``gate-action/`` needs a ``CHANGELOG.md`` entry.
2. A change to a user-facing module needs its doc page, for example
   ``src/mylonite/cli.py`` needs ``docs/cli-reference.md``.

A change that genuinely needs no docs (an internal refactor, a test-only fix)
opts out with a reason, in a commit message or the pull-request description::

    Docs-Impact: none - internal refactor of the scan loop, no behaviour change

or, in CI only, with the ``no-docs`` label. The reason is required so a reviewer
can agree with it at a glance.

Usage::

    python scripts/check_docs_sync.py --base origin/main          # branch vs base
    python scripts/check_docs_sync.py --staged --message "$MSG"   # before a commit
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

CHANGELOG = "CHANGELOG.md"

# Paths whose changes are user-visible enough to need a changelog entry.
CODE_PREFIXES = ("src/mylonite/", "reference_targets/mcp_kitchen_sink/src/", "gate-action/")

# Generated or non-behavioural files under the code prefixes.
CODE_EXEMPT = (
    re.compile(r"(^|/)__pycache__/"),
    re.compile(r"\.pyc$"),
    re.compile(r"(^|/)py\.typed$"),
)


@dataclass(frozen=True)
class DocRule:
    """A user-facing area of the code and the pages that document it."""

    code: str  # path prefix
    docs: tuple[str, ...]  # any one of these must change
    why: str


DOC_RULES: tuple[DocRule, ...] = (
    DocRule("src/mylonite/cli.py", ("docs/cli-reference.md",), "CLI flags and commands"),
    DocRule(
        "src/mylonite/plugins/_mcp/target_file.py",
        ("docs/target-file.md",),
        "the target.yaml schema",
    ),
    DocRule("src/mylonite/gate/", ("docs/ci-gating.md",), "the gate command and CI workflows"),
    DocRule("gate-action/", ("docs/ci-gating.md",), "the reusable gate action"),
    DocRule("src/mylonite/report/", ("docs/reading-results.md",), "report formats"),
    DocRule("src/mylonite/testkit/", ("docs/validation.md",), "the pytest gate"),
    DocRule(
        "src/mylonite/contracts/",
        ("docs/plugin-authoring.md", "docs/architecture.md"),
        "the public extension contracts",
    ),
    DocRule(
        "src/mylonite/taxonomy/data/",
        ("src/mylonite/taxonomy/data/SOURCE.md", "docs/standards-mapping.md"),
        "the bundled threat taxonomy",
    ),
)

# Found anywhere in a text, so it also works inline in `git commit -m "..."`.
# The reason runs to the end of the line or a closing quote. Separator: hyphen,
# colon, en dash or em dash.
_OPT_OUT_RE = re.compile(
    r"Docs-Impact:\s*none\s*[-:\N{EN DASH}\N{EM DASH}]\s*(?P<reason>[^\"'\n]*)",
    re.IGNORECASE,
)
MIN_REASON = 10
NO_DOCS_LABELS = frozenset({"no-docs", "skip-changelog"})


@dataclass(frozen=True)
class Problem:
    message: str


def _is_code(path: str) -> bool:
    return path.startswith(CODE_PREFIXES) and not any(p.search(path) for p in CODE_EXEMPT)


def opt_out_reason(texts: Iterable[str]) -> str | None:
    """Return the Docs-Impact reason if any text carries a valid opt-out."""
    for text in texts:
        for match in _OPT_OUT_RE.finditer(text or ""):
            reason = match.group("reason").strip()
            if len(reason) >= MIN_REASON:
                return reason
    return None


def check(
    changed: Sequence[str], opt_out_texts: Iterable[str] = (), labels: Iterable[str] = ()
) -> list[Problem]:
    """Return the doc updates this change set is missing (empty when in sync)."""
    changed_set = {p.replace("\\", "/") for p in changed}
    code = sorted(p for p in changed_set if _is_code(p))
    if not code:
        return []
    if NO_DOCS_LABELS & {label.strip().lower() for label in labels}:
        return []
    if opt_out_reason(opt_out_texts):
        return []

    problems: list[Problem] = []
    if CHANGELOG not in changed_set:
        sample = ", ".join(code[:3]) + (" ..." if len(code) > 3 else "")
        problems.append(
            Problem(
                f"{CHANGELOG} has no entry for this change (code changed: {sample}). "
                "Add a line under ## [Unreleased]."
            )
        )
    for rule in DOC_RULES:
        touched = [p for p in code if p.startswith(rule.code)]
        if touched and not any(doc in changed_set for doc in rule.docs):
            problems.append(
                Problem(
                    f"{touched[0]} changed ({rule.why}) but {' or '.join(rule.docs)} did not. "
                    "Update the page, or explain why it is unaffected."
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
    ).stdout


def changed_files(base: str | None, staged: bool) -> list[str]:
    if staged:
        return _git("diff", "--cached", "--name-only").splitlines()
    # Everything since the branch left `base`: commits, uncommitted edits and
    # new untracked files. In CI the tree is clean, so this equals base...HEAD;
    # locally it means the check sees work before it is committed.
    fork = _git("merge-base", str(base), "HEAD").strip()
    tracked = _git("diff", "--name-only", fork).splitlines()
    untracked = _git("ls-files", "--others", "--exclude-standard").splitlines()
    return sorted(set(tracked) | set(untracked))


def commit_messages(base: str) -> list[str]:
    return [m for m in _git("log", "--format=%B%x00", f"{base}..HEAD").split("\x00") if m.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--base", help="compare HEAD with this ref (branch or PR)")
    source.add_argument(
        "--staged", action="store_true", help="check the staged changes (before a commit)"
    )
    parser.add_argument(
        "--message", action="append", default=[], help="extra text that may hold a Docs-Impact line"
    )
    parser.add_argument("--pr-body-env", help="environment variable holding the PR description")
    parser.add_argument(
        "--labels-env", help="environment variable holding comma-separated PR labels"
    )
    args = parser.parse_args(argv)

    texts: list[str] = list(args.message)
    if args.base:
        texts += commit_messages(args.base)
    if args.pr_body_env:
        texts.append(os.environ.get(args.pr_body_env, ""))
    labels = os.environ.get(args.labels_env, "").split(",") if args.labels_env else []

    problems = check(changed_files(args.base, args.staged), texts, labels)
    if not problems:
        reason = opt_out_reason(texts)
        print(f"docs in sync{f' (Docs-Impact: none - {reason})' if reason else ''}")
        return 0
    print("Docs are out of sync with the code:\n", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem.message}", file=sys.stderr)
    print(
        "\nUpdate the docs (Claude Code: run /document-release), or, if nothing user-facing changed, "
        "add a line to the commit message or PR description:\n"
        "  Docs-Impact: none - <why no docs are needed>",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
