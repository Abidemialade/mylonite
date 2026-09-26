#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block commits, pushes and PRs that fail the
writing and docs-sync checks.

Wired in ``.claude/settings.json``. It reads the pending tool call from stdin,
and when the command is a ``git commit``, ``git push`` or ``gh pr create/edit``
it runs ``scripts/check_docs_sync.py`` and ``scripts/check_prose.py``. On a
failure it exits 2, which blocks the call and hands the reason back to Claude.

It never blocks anything else, and it fails open (allows the call) if git or the
checks themselves cannot run: CI runs the same checks and is the backstop.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

# Match only where a command starts (line start, or after ; & | ( or $( ), so a
# command that merely *mentions* "git commit" inside a string is not treated as
# one. A quoted mention preceded by "&&" can still match; that errs toward
# checking, which is the safe side.
_START = r"(?:^|[;&|(\n]|\$\()\s*"
_GIT_OPTS = r"(?:\s+-{1,2}[\w-]+(?:[= ]\S+)?)*"
COMMIT_RE = re.compile(_START + r"git" + _GIT_OPTS + r"\s+commit\b")
PUSH_RE = re.compile(_START + r"git" + _GIT_OPTS + r"\s+push\b")
PR_RE = re.compile(_START + r"gh\s+pr\s+(create|edit)\b")
ADD_RE = re.compile(r"\bgit\s+add\b([^;&|\n]*)")


def _load(project: Path, name: str) -> ModuleType:
    path = project / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _git(project: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=project,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout


def _files_for_commit(project: Path, command: str) -> list[str]:
    """Files the command is about to commit: staged now, plus any `git add` in the same command."""
    files = set(_git(project, "diff", "--cached", "--name-only").splitlines())
    worktree = [
        line[3:].split(" -> ")[-1] for line in _git(project, "status", "--porcelain").splitlines()
    ]
    for match in ADD_RE.finditer(command):
        try:
            args = shlex.split(match.group(1))
        except ValueError:
            args = match.group(1).split()
        if any(a in {"-A", "--all", ".", "-u", "--update"} for a in args):
            files.update(worktree)
        else:
            paths = [a for a in args if not a.startswith("-")]
            files.update(
                w
                for w in worktree
                if any(w == p or w.startswith(p.rstrip("/") + "/") for p in paths)
            )
    if re.search(r"\bcommit\b[^;&|\n]*\s(-a|--all|-am)\b", command):
        files.update(_git(project, "diff", "--name-only").splitlines())
    return sorted(files)


def _pr_title(command: str) -> str | None:
    match = re.search(r"""(?:--title|-t)(?:=|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))""", command)
    if not match:
        return None
    return next(g for g in match.groups() if g is not None)


def _pr_body(project: Path, command: str) -> str | None:
    """The PR description, or None when its --body-file can't be read from here.

    A path built from shell-local variables ("$DIR/body.md"), stdin ("-") or a
    file that doesn't exist can't be resolved from the command text. Returning
    None leaves the body to CI, rather than reporting every section as missing.
    """
    match = re.search(r"""--body-file(?:=|\s+)(?:"([^"]+)"|'([^']+)'|(\S+))""", command)
    if match:
        raw = next(g for g in match.groups() if g is not None)
        path = Path(os.path.expandvars(raw)).expanduser()
        path = path if path.is_absolute() else project / path
        return path.read_text(encoding="utf-8") if path.is_file() else None
    return command  # inline --body or heredoc: the command text carries it


def run(payload: dict[str, Any]) -> list[str]:
    command = (payload.get("tool_input") or {}).get("command") or ""
    is_commit, is_push, pr = (
        COMMIT_RE.search(command),
        PUSH_RE.search(command),
        PR_RE.search(command),
    )
    if not (is_commit or is_push or pr):
        return []

    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or ".")
    docs = _load(project, "check_docs_sync")
    prose = _load(project, "check_prose")
    problems: list[str] = []

    if is_commit:
        changed = _files_for_commit(project, command)
        problems += [p.message for p in docs.check(changed, [command])]
        problems += [
            f.render() for f in prose.lint_text(command, "commit message") if f.severity == "error"
        ]

    if is_push or pr:
        base = "origin/main"
        changed = _git(project, "diff", "--name-only", f"{base}...HEAD").splitlines()
        texts = [*docs.commit_messages(base), command]
        if pr:
            body = _pr_body(project, command)
            if body is not None:
                texts.append(body)
            if pr.group(1) == "create":
                title = _pr_title(command)
                if title is not None:
                    problems += [
                        f.render() for f in prose.check_pr_title(title) if f.severity == "error"
                    ]
                if body is not None:
                    problems += [
                        f.render() for f in prose.check_pr_body(body) if f.severity == "error"
                    ]
        problems += [p.message for p in docs.check(changed, texts)]
        problems += [
            f.render() for f in prose.lint_diff(prose.added_markdown_lines(base, cwd=project))
        ]
        problems = [p for p in problems if ": warning:" not in p]

    return list(dict.fromkeys(problems))


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
        problems = run(payload)
    except Exception as exc:  # fail open: CI is the backstop
        print(f"enforce_writing hook skipped: {exc}", file=sys.stderr)
        return 0
    if not problems:
        return 0
    print(
        "Blocked by the Mylonite writing and docs checks (docs/contributing/writing-style.md):\n",
        file=sys.stderr,
    )
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "\nFix: update the docs and CHANGELOG (run /document-release), rewrite the flagged phrases "
        "using the mylonite-writing skill, then retry. If no docs are needed, add "
        "'Docs-Impact: none - <reason>' to the commit message or PR description.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
