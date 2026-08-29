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
Prose files only (``*.md``) **for source files**, because the phrases below are
legitimate in code: ``control_shim.py`` and ``labels.py`` say "this session"
about an MCP *scan* session, which has nothing to do with a work session.
Widening this to ``*.py`` produces false positives that train people to bypass
the hook, which is worse than not having it.

The one exception is **committed verification results**
(``verification/results/**/*.json``, ``*.jsonl``). Those are not source: they are
machine-generated evidence produced by running the harness on the maintainer's
own computer, against servers on localhost ports. Nothing in them is written by
hand, so there is no legitimate-in-context reading to protect, and the
false-positive argument above does not apply. They therefore get the prose rules
PLUS the stricter data rules in ``DATA_DENYLIST`` (local addresses and ports,
and JSON-escaped Windows paths). ``verification/_sanitise.py`` is what keeps
them clean at write time; this is the check that they actually are.

What is NOT flagged
-------------------
``maintainer`` as a ROLE is normal open-source language and stays:
``GOVERNANCE.md``'s "made by the maintainer", a "maintainer-run" recipe, the
README's honest "single maintainer". What is flagged is that person's *machine*,
*antivirus*, *credential*, and *session*.

Usage::

    python scripts/check_no_local_context.py            # tracked *.md + results data
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

#: Rules applied ONLY to committed verification results (see "Scope" above).
#: Deliberately not applied to prose: the project's own docs legitimately show a
#: ``http://localhost:8000`` MCP endpoint in a quickstart, and flagging those
#: would make the hook noise rather than signal.
DATA_DENYLIST: list[tuple[re.Pattern[str], str]] = [
    (
        # Loopback / unspecified / RFC1918, with or without a port. A committed
        # result must not record which port the harness happened to bind to on
        # the machine that ran it.
        re.compile(
            r"(?<![\w.:-])(?:localhost"
            r"|127(?:\.\d{1,3}){3}"
            r"|0\.0\.0\.0"
            r"|10(?:\.\d{1,3}){3}"
            r"|192\.168(?:\.\d{1,3}){2}"
            r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
            r"|\[::1\])"
            r"(?::\d{1,5})?(?![\w-])",
            re.I,
        ),
        "a local address/port from the machine that ran the campaign; the "
        "sanitiser collapses these to <host>:<port> (verification/_sanitise.py)",
    ),
    (
        # JSON escapes its backslashes, so the prose rule above (which expects a
        # single separator) never fires on a serialised Windows path.
        re.compile(r"[A-Za-z]:\\{1,2}[A-Za-z0-9._\-\\]*", re.I),
        "a Windows absolute path survived JSON encoding; scrub it to <path>",
    ),
]

#: Files whose whole point is to document this guard.
EXEMPT = {"scripts/check_no_local_context.py"}

#: Committed campaign evidence. Matched anywhere in the path (not anchored at the
#: repo root) so the same rules apply when a test writes a fixture tree under a
#: temporary directory.
RESULTS_DIR = "verification/results/"

#: Machine-readable evidence formats written into ``RESULTS_DIR``.
DATA_SUFFIXES = {".json", ".jsonl"}


def is_results_data(path: Path) -> bool:
    """True for a machine-readable file under ``verification/results/``."""
    return RESULTS_DIR in path.as_posix() and path.suffix in DATA_SUFFIXES


def rules_for(path: Path) -> list[tuple[re.Pattern[str], str]]:
    """The rule set that applies to ``path``: prose rules, plus data rules for results."""
    if is_results_data(path):
        return DENYLIST + DATA_DENYLIST
    return DENYLIST


def _git_ls(*patterns: str) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", *patterns], capture_output=True, text=True, check=True
    ).stdout
    return [Path(line) for line in out.splitlines() if line]


def tracked_markdown() -> list[Path]:
    return _git_ls("*.md")


def tracked_results_data() -> list[Path]:
    """Tracked JSON/JSONL under ``verification/results/``.

    ``git ls-files`` lists tracked files only, so a campaign directory that has
    been written but not yet staged is invisible here. That is deliberate: the
    guard's job is to stop a leak from being COMMITTED, and pre-commit passes
    staged paths as arguments, which takes the branch above.
    """
    return [p for p in _git_ls(RESULTS_DIR) if p.suffix in DATA_SUFFIXES]


def in_scope(path: Path) -> bool:
    """True if this guard has anything to say about ``path``."""
    return path.suffix == ".md" or is_results_data(path)


def scan(paths: list[Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        if path.as_posix() in EXEMPT or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rules = rules_for(path)
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern, why in rules:
                match = pattern.search(line)
                if match:
                    problems.append(f"{path.as_posix()}:{lineno}: {match.group(0)!r} - {why}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        paths = [Path(a) for a in argv[1:]]
    else:
        paths = tracked_markdown() + tracked_results_data()
    paths = [p for p in paths if in_scope(p)]
    problems = scan(paths)
    if not problems:
        return 0
    print("Local-context leak in committed prose or results:\n", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(
        "\nThese describe the author's machine rather than the project. For a "
        "security tool they also profile the person holding commit and publishing\n"
        "rights. Rewrite prose in environment-neutral terms; run generated results "
        "through verification/_sanitise.py. See the module docstring of\n"
        "scripts/check_no_local_context.py for the convention.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
