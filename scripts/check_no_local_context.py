#!/usr/bin/env python
"""Fail if committed prose describes the maintainer's machine instead of the project.

Why this exists
---------------
This is a security tool, and its docs are written during working sessions. Twice
now, session narration has been committed to public files: an antivirus product
name, the fact that a live cloud API key was sitting in a shell, and a note that
the maintainer's TLS is intercepted. Read together those lines profile the one
person holding commit rights and the PyPI publishing credential. The first
occurrence had to be removed with a force-push after the fact.

A one-time scrub fixes the instance. This fixes the class: the next session that
writes "blocked on this machine" into TODOS.md gets stopped at commit time.

Scope
-----
Prose files only (``*.md``), because the phrases below are legitimate in code:
``control_shim.py`` and ``labels.py`` say "this session" about an MCP *scan*
session, which has nothing to do with a work session. Widening this to ``*.py``
produces false positives that train people to bypass the hook, which is worse
than not having it.

What is NOT flagged
-------------------
``maintainer`` as a ROLE is normal open-source language and stays:
``GOVERNANCE.md``'s "made by the maintainer", a "maintainer-run" recipe, the
README's honest "single maintainer". What is flagged is that person's *machine*,
*antivirus*, *credential*, and *session*.

Usage::

    python scripts/check_no_local_context.py            # all tracked *.md
    python scripts/check_no_local_context.py a.md b.md  # pre-commit passes paths
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

#: (compiled pattern, why it must not ship). Case-insensitive.
DENYLIST: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\bon (?:this|my) machine\b", re.I),
        "describes the author's computer; say what the step REQUIRES instead "
        '(e.g. "needs a provider key and working TLS egress")',
    ),
    (
        re.compile(r"\b(?:the )?maintainer'?s machine\b", re.I),
        "same as above: the requirement is environmental, not personal",
    ),
    (
        re.compile(r"\bspecific to this machine\b", re.I),
        "make the caveat about the environment class, not one computer",
    ),
    (
        re.compile(r"\b(?:in|as of) this session\b", re.I),
        "session narration is not durable documentation; state the status, not "
        "when you observed it",
    ),
    (
        re.compile(r"\b(?:Norton|McAfee|Kaspersky|Bitdefender|Avast|Sophos)\b"),
        "naming the endpoint-protection product on the maintainer's box is a "
        'targeting hint; say "endpoint-protection software" / "a local AV CA"',
    ),
    (
        re.compile(r"\bdeclined to spend\b", re.I),
        "records a decision made in one session rather than the project's state",
    ),
    (
        re.compile(r"\bAPI[_ ]KEY\b[^\n]{0,40}\bwas present\b", re.I),
        "never record that a live credential was present in an environment",
    ),
    (
        re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+", re.I),
        "absolute path leaking a local username",
    ),
    (
        # Placeholder names are how docs SHOULD write an example path, so they
        # are excluded by name rather than by weakening the pattern. `runner`
        # and `ubuntu` are CI home directories and equally impersonal.
        re.compile(
            r"/(?:home|Users)/"
            r"(?!(?:alice|bob|carol|dave|eve|user|username|youruser|you|me|someone|"
            r"example|runner|ubuntu)\b)"
            r"[a-z][a-z0-9._-]{2,}/",
            re.I,
        ),
        "absolute path leaking a local username; use a placeholder like /home/alice/",
    ),
]

#: Files whose whole point is to document this guard.
EXEMPT = {"scripts/check_no_local_context.py"}


def tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.md"], capture_output=True, text=True, check=True
    ).stdout
    return [Path(line) for line in out.splitlines() if line]


def scan(paths: list[Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        if path.as_posix() in EXEMPT or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern, why in DENYLIST:
                match = pattern.search(line)
                if match:
                    problems.append(f"{path.as_posix()}:{lineno}: {match.group(0)!r} - {why}")
    return problems


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]] if len(argv) > 1 else tracked_markdown()
    paths = [p for p in paths if p.suffix == ".md"]
    problems = scan(paths)
    if not problems:
        return 0
    print("Local-context leak in committed prose:\n", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(
        "\nThese describe the author's machine rather than the project. For a "
        "security tool they also profile the person holding commit and publishing\n"
        "rights. Rewrite in environment-neutral terms; see the module docstring "
        "of scripts/check_no_local_context.py for the convention.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
