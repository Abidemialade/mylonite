#!/usr/bin/env python3
"""Prose check for Mylonite's docs, changelog, pull requests and commits.

Enforces the mechanical parts of ``docs/contributing/writing-style.md``:

* phrases that read as machine-written or as marketing copy ("delve",
  "leverage", "seamless", "it's worth noting", ...), in *changed* Markdown lines
  only, so existing prose never blocks an unrelated change;
* Conventional Commits pull-request titles;
* the required pull-request description sections.

It is deliberately conservative. A check that cries wolf gets bypassed, which is
worse than no check, so every rule targets a phrase with almost no legitimate
use in technical writing. Code blocks and inline code are never checked, and a
line can opt out with ``<!-- prose-lint: allow -->`` (for example, a quotation).

Usage::

    python scripts/check_prose.py --diff-base origin/main
    python scripts/check_prose.py --text-file commit-msg.txt
    python scripts/check_prose.py --pr-title-env PR_TITLE --pr-body-env PR_BODY

Exit status: 0 when clean (warnings allowed), 1 on any error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARKER = "prose-lint: allow"

# Files that quote the banned phrases on purpose, to teach them.
EXCLUDED_PATHS = (
    "docs/contributing/writing-style.md",
    ".claude/skills/mylonite-writing/",
)

# (pattern, message). Errors fail the check.
ERROR_RULES: tuple[tuple[str, str], ...] = (
    (r"\bdelv(e|es|ed|ing)\b", 'say "look at", "cover" or "explain"'),
    (r"\b(let's|lets) dive\b|\bdive into\b", 'say "look at" or "cover"'),
    (r"\bleverag(e|es|ed|ing)\b", 'say "use"'),
    (r"\butili[sz](e|es|ed|ing|ation)\b", 'say "use"'),
    (r"\bseamless(ly)?\b", "say what actually happens"),
    (r"\bcutting[- ]edge\b|\bstate[- ]of[- ]the[- ]art\b", "show the evidence instead"),
    (r"\bgame[- ]chang(er|ing)\b|\brevolutioni[sz](e|es|ed|ing)\b", "show the result instead"),
    (r"\bbest[- ]in[- ]class\b|\bworld[- ]class\b", "show the result instead"),
    (r"\bsupercharg(e|es|ed|ing)\b|\bempower(s|ed|ing)?\b", "say what the reader can now do"),
    (r"\bunlock(s|ed|ing)? the (power|potential)\b|\bharness(es|ed|ing)? the power\b", "cut it"),
    (r"\bit(?:'s| is) (worth noting|important to note)\b", "just state it"),
    (r"\b(furthermore|moreover)\b", 'start a new sentence, or use "also"'),
    (r"\bin today's\b|\bever[- ]evolving\b|\bfast[- ]paced world\b", "cut it"),
    (
        r"\b(may|could) potentially\b|\bmight possibly\b|\bcould possibly\b",
        'pick one: "may" or "can"',
    ),
    (r"\btapestry\b|\bplethora\b|\bmyriad of\b|\brealm of\b", "use a plain word"),
    (r"\ba testament to\b|\bnavigat(e|ing) the complexities\b", "cut it"),
    (r"\bi hope this helps\b|\bfeel free to\b|\brest assured\b", "cut it"),
    (r"\bas an ai\b|\bas a large language model\b", "cut it"),
    (r"\bin conclusion\b|\bin summary,", "end on the last real point"),
    (r"\bthis (pr|pull request|document|page) (aims|seeks) to\b", "start with what it does"),
)

# Words that shrink the work. Reported, never fatal: they have honest uses.
WARNING_RULES: tuple[tuple[str, str], ...] = (
    (r"\bunfortunately\b", "state the limit as scope, without apology"),
    (r"\bmerely\b|\bjust a (small|simple|quick)\b", "let the diff show the size"),
    (r"\bsimply\b", "cut it; if it were simple, the reader would not need the sentence"),
    (r"\b(robust|powerful|comprehensive)\b", "replace with the evidence or what it covers"),
)

CONVENTIONAL_TYPES = (
    "feat",
    "fix",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "build",
    "ci",
    "chore",
    "revert",
)
_TYPES = "|".join(CONVENTIONAL_TYPES)
TITLE_RE = re.compile(rf"^(?:{_TYPES})(?:\([a-z0-9._/,-]+\))?!?: \S.*$")
MAX_TITLE = 72

# Sections a pull-request description must fill in (heading text, lower case).
REQUIRED_PR_SECTIONS = ("summary", "how this was tested")

_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE_RE = re.compile(r"`[^`]*`")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


@dataclass(frozen=True)
class Finding:
    source: str
    line: int
    severity: str  # "error" | "warning"
    message: str

    def render(self) -> str:
        where = f"{self.source}:{self.line}" if self.line else self.source
        return f"{where}: {self.severity}: {self.message}"


def _compiled(rules: Iterable[tuple[str, str]]) -> list[tuple[re.Pattern[str], str]]:
    return [(re.compile(p, re.IGNORECASE), m) for p, m in rules]


_ERRORS = _compiled(ERROR_RULES)
_WARNINGS = _compiled(WARNING_RULES)


def _prose_lines(lines: Iterable[tuple[int, str]]) -> Iterator[tuple[int, str]]:
    """Yield (lineno, text) for prose lines: code fences and inline code removed."""
    in_fence = False
    for lineno, raw in lines:
        if _FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence or ALLOW_MARKER in raw:
            continue
        yield lineno, _INLINE_CODE_RE.sub("", raw)


def lint_lines(lines: Iterable[tuple[int, str]], source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, text in _prose_lines(lines):
        for pattern, advice in _ERRORS:
            match = pattern.search(text)
            if match:
                findings.append(Finding(source, lineno, "error", f'"{match.group(0)}": {advice}'))
        for pattern, advice in _WARNINGS:
            match = pattern.search(text)
            if match:
                findings.append(Finding(source, lineno, "warning", f'"{match.group(0)}": {advice}'))
    return findings


def lint_text(text: str, source: str) -> list[Finding]:
    """Lint a free-text block (commit message, PR body). HTML comments are skipped."""

    def _blank(match: re.Match[str]) -> str:
        # Drop the comment's words but keep its line breaks (so line numbers
        # stay true) and keep an allow marker, which lives inside a comment.
        keep = f" {ALLOW_MARKER} " if ALLOW_MARKER in match.group(0) else ""
        return keep + "\n" * match.group(0).count("\n")

    stripped = _HTML_COMMENT_RE.sub(_blank, text)
    return lint_lines(enumerate(stripped.splitlines(), start=1), source)


def check_pr_title(title: str) -> list[Finding]:
    title = title.strip()
    problems: list[str] = []
    if not TITLE_RE.match(title):
        problems.append(
            "title must follow Conventional Commits: type(scope): summary "
            f"(types: {', '.join(CONVENTIONAL_TYPES)})"
        )
    if len(title) > MAX_TITLE:
        problems.append(f"title is {len(title)} characters; keep it under {MAX_TITLE}")
    if title.endswith("."):
        problems.append("title should not end with a full stop")
    return [Finding("PR title", 0, "error", p) for p in problems] + lint_text(title, "PR title")


def _sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: str | None = None
    for line in body.splitlines():
        heading = re.match(r"^#{2,3}\s+(.*?)\s*$", line)
        if heading:
            current = heading.group(1).strip().lower()
            sections[current] = ""
        elif current is not None:
            sections[current] += line + "\n"
    return sections


def check_pr_body(body: str) -> list[Finding]:
    findings: list[Finding] = []
    visible = _HTML_COMMENT_RE.sub("", body or "")
    sections = _sections(visible)
    for required in REQUIRED_PR_SECTIONS:
        content = next((v for k, v in sections.items() if k.startswith(required)), None)
        if content is None:
            findings.append(
                Finding("PR body", 0, "error", f'missing the "## {required.capitalize()}" section')
            )
        elif not content.strip():
            findings.append(
                Finding("PR body", 0, "error", f'the "{required.capitalize()}" section is empty')
            )
    return findings + lint_text(body or "", "PR body")


def _is_excluded(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in EXCLUDED_PATHS)


def added_markdown_lines(base: str, cwd: Path | None = None) -> dict[str, list[tuple[int, str]]]:
    """Map each changed Markdown file to the lines added since the branch left ``base``.

    Covers commits, uncommitted edits and new untracked files, so a local run
    sees work before it is committed. In CI the tree is clean, so this equals
    ``base...HEAD``.
    """

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            cwd=cwd,
        ).stdout

    fork = git("merge-base", base, "HEAD").strip()
    added = parse_added_lines(git("diff", "--unified=0", "--no-color", fork, "--", "*.md"))
    root = Path(git("rev-parse", "--show-toplevel").strip())
    for path in git("ls-files", "--others", "--exclude-standard", "--", "*.md").splitlines():
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        added[path] = list(enumerate(text.splitlines(), start=1))
    return added


def parse_added_lines(diff: str) -> dict[str, list[tuple[int, str]]]:
    added: dict[str, list[tuple[int, str]]] = {}
    path: str | None = None
    lineno = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            path = None if target == "/dev/null" else target.removeprefix("b/")
        elif line.startswith("@@"):
            hunk = re.search(r"\+(\d+)", line)
            lineno = int(hunk.group(1)) if hunk else 0
        elif path and line.startswith("+") and not line.startswith("+++"):
            added.setdefault(path, []).append((lineno, line[1:]))
            lineno += 1
    return added


def lint_diff(added: dict[str, list[tuple[int, str]]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, lines in sorted(added.items()):
        if not _is_excluded(path):
            findings.extend(lint_lines(lines, path))
    return findings


def _read(value: str | None, env: str | None, file: str | None) -> str | None:
    if value is not None:
        return value
    if env:
        return os.environ.get(env, "")
    if file:
        return Path(file).read_text(encoding="utf-8")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--diff-base", help="lint Markdown lines added since this git ref")
    parser.add_argument("--files", nargs="*", default=[], help="lint these files in full")
    parser.add_argument("--text-file", help="lint a free-text file (commit message)")
    parser.add_argument("--pr-title")
    parser.add_argument("--pr-title-env", help="read the PR title from this environment variable")
    parser.add_argument("--pr-body-file")
    parser.add_argument(
        "--pr-body-env", help="read the PR description from this environment variable"
    )
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    if args.diff_base:
        findings += lint_diff(added_markdown_lines(args.diff_base))
    for file in args.files:
        if not _is_excluded(file.replace("\\", "/")):
            text = Path(file).read_text(encoding="utf-8")
            findings += lint_lines(enumerate(text.splitlines(), start=1), file)
    if args.text_file:
        findings += lint_text(Path(args.text_file).read_text(encoding="utf-8"), args.text_file)
    title = _read(args.pr_title, args.pr_title_env, None)
    if title is not None:
        findings += check_pr_title(title)
    body = _read(None, args.pr_body_env, args.pr_body_file)
    if body is not None:
        findings += check_pr_body(body)

    for finding in findings:
        print(finding.render())
    errors = [f for f in findings if f.severity == "error"]
    if errors:
        print(
            f"\n{len(errors)} writing problem(s). See docs/contributing/writing-style.md; "
            f'add "<!-- {ALLOW_MARKER} -->" to a line only when quoting on purpose.',
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
