#!/usr/bin/env python3
"""Check every fenced ``mylonite ...`` command in the docs against the
committed CLI golden (``tests/cli_golden/goldens/command_tree.json``).

This is deliberately NOT the live CLI: ``tests/test_docs_consistency.py``
already parses these same examples against the real, running ``Command``
tree (catching a renamed flag the moment ``cli.py`` changes, before any
golden is regenerated). This script instead reads the golden snapshot
docs-sync already keeps in sync with the CLI, so it stays import-light —
no ``typer``/``mylonite`` import, matching ``check_docs_sync.py``'s own
style — and can run as a quick, offline docs lint on its own.

Scope: fenced ` ```bash ` and ` ```console ` blocks in ``docs/*.md``,
``docs/journey/*.md`` and ``README.md``. A backslash line continuation is
joined before a logical line is checked, so a wrapped invocation is read
as one command. For each ``mylonite ...`` logical line:

* the subcommand (the first token after ``mylonite``, if it doesn't start
  with ``-``) must be a real, live command — or one of ``_RETIRED_COMMANDS``,
  a documented migration note rather than a live invocation;
* every ``--flag``-shaped token on the line must be one of that
  subcommand's real options (or a root-level option, if there is no
  subcommand).

Launch-set commands (``demo``, ``scan``, ``generate``, ``validate``,
``gate``, ``report`` — the six commands the journey's steps 1-6 run) get an
empty allowlist: every failure there must be fixed in the docs, never
carried. A non-launch command (``check``, ``ablate``, ``plugins``,
``version``) may carry a reasoned entry in
``tests/fixtures/fenced_commands_allowlist.json`` if one is ever needed.

Usage::

    python scripts/check_fenced_commands.py
    python scripts/check_fenced_commands.py --repo-root /path/to/checkout
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TREE_PATH = "tests/cli_golden/goldens/command_tree.json"
ALLOWLIST_PATH = "tests/fixtures/fenced_commands_allowlist.json"

#: The six commands the journey's steps 1-6 run (see docs/journey/). Their
#: allowlist must stay empty -- a failure here is always a doc to fix, never
#: a reasoned exception.
LAUNCH_SET = frozenset({"demo", "scan", "generate", "validate", "gate", "report"})

#: Commands named in a documented migration note ("X became Y") rather than
#: a live invocation -- mirrors tests/test_docs_consistency.py's own set.
_RETIRED_COMMANDS = frozenset({"init-target", "export", "doctor", "taxonomy"})

#: Fenced-block languages this check reads. Narrower than
#: tests/test_docs_consistency.py on purpose -- see the module docstring.
_SHELL_FENCES = ("bash", "console")

_FLAG_TOKEN_RE = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*(?![\w-])")
_SOURCE_GLOBS = ("README.md", "docs/*.md", "docs/journey/*.md")


@dataclass(frozen=True)
class Problem:
    message: str
    command: str


def _load_command_tree(repo_root: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((repo_root / COMMAND_TREE_PATH).read_text(encoding="utf-8"))
    return data


def _flag_set(params: list[dict[str, Any]]) -> set[str]:
    flags: set[str] = set()
    for param in params:
        flags.update(o for o in param.get("opts", []) if o.startswith("--"))
        flags.update(o for o in param.get("secondary_opts", []) if o.startswith("--"))
    return flags


def known_flags(tree: dict[str, Any]) -> tuple[set[str], dict[str, set[str]]]:
    """(root flags, {command: command's own flags}) -- NOT unioned with root;
    the caller unions per-line, matching how Typer resolves options."""
    root_flags = _flag_set(tree["root"]["params"])
    per_command = {name: _flag_set(cmd["params"]) for name, cmd in tree["commands"].items()}
    return root_flags, per_command


def _join_line_continuations(lines: list[str]) -> list[str]:
    """Join a trailing backslash line continuation into one logical line."""
    out: list[str] = []
    buf: str | None = None
    for raw in lines:
        line = raw.strip()
        continued = line.endswith("\\")
        if continued:
            line = line[:-1].rstrip()
        buf = f"{buf} {line}".strip() if buf is not None else line
        if continued:
            continue
        out.append(buf)
        buf = None
    if buf is not None:
        out.append(buf)
    return out


def extract_fenced_mylonite_commands(text: str) -> list[str]:
    """Every logical ``mylonite ...`` line inside a ```bash/```console fence."""
    found: list[str] = []
    in_shell = False
    fence_lines: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            if in_shell:
                for logical in _join_line_continuations(fence_lines):
                    if logical.startswith("mylonite "):
                        found.append(logical.split(" #", 1)[0].rstrip())
                fence_lines = []
                in_shell = False
            else:
                lang = stripped[3:].strip().lower()
                in_shell = lang in _SHELL_FENCES
            continue
        if in_shell:
            fence_lines.append(raw)
    return found


def _doc_sources(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in _SOURCE_GLOBS:
        paths.extend(repo_root.glob(pattern))
    # dedupe (docs/*.md and docs/journey/*.md never overlap, but keep this
    # robust if that changes) and skip local-only / point-in-time dirs.
    seen: set[Path] = set()
    out: list[Path] = []
    for path in sorted(paths):
        if path in seen or not path.is_file():
            continue
        if "superpowers" in path.parts or "reviews" in path.parts:
            continue
        seen.add(path)
        out.append(path)
    return out


def _load_allowlist_entries(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / ALLOWLIST_PATH
    if not path.exists():
        return []
    data: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _load_allowlist(repo_root: Path) -> set[str]:
    return {entry["command"] for entry in _load_allowlist_entries(repo_root)}


def check_allowlist_has_no_launch_set_entries(repo_root: Path) -> list[Problem]:
    """DOC-B rule: a launch-set command (the six §2 commands) may never
    carry an allowlist entry -- a failure there is always a doc to fix."""
    violations = sorted(LAUNCH_SET & _load_allowlist(repo_root))
    if not violations:
        return []
    return [
        Problem(
            f"{ALLOWLIST_PATH} allowlists launch-set command(s) {violations}, which must "
            "stay empty -- fix the doc instead of carrying the exception.",
            command="(launch-set)",
        )
    ]


def check(repo_root: Path) -> list[Problem]:
    tree = _load_command_tree(repo_root)
    root_flags, per_command = known_flags(tree)
    allowlisted = _load_allowlist(repo_root)

    problems: list[Problem] = list(check_allowlist_has_no_launch_set_entries(repo_root))
    for path in _doc_sources(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        for command_line in extract_fenced_mylonite_commands(path.read_text(encoding="utf-8")):
            tokens = command_line.split()
            location = f"{rel}: `{command_line}`"
            sub = tokens[1] if len(tokens) > 1 else None

            if sub is not None and sub.startswith("-"):
                sub = None  # a flag right after `mylonite`, no subcommand yet

            if sub is not None and sub not in per_command and sub not in _RETIRED_COMMANDS:
                if sub not in allowlisted:
                    problems.append(
                        Problem(f"{location} -- {sub!r} is not a known command", command=sub)
                    )
                continue
            if sub in _RETIRED_COMMANDS:
                continue  # a migration note, not a live invocation

            allowed = root_flags | (per_command.get(sub, set()) if sub else set())
            key = sub or "(root)"
            if key in allowlisted:
                continue
            for flag in _FLAG_TOKEN_RE.findall(command_line):
                if flag == "--help":
                    continue
                if flag not in allowed:
                    problems.append(
                        Problem(
                            f"{location} -- {flag!r} is not a known option of {key}", command=key
                        )
                    )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    problems = check(args.repo_root)
    if not problems:
        print("fenced mylonite commands match the CLI golden")
        return 0
    print("Fenced `mylonite ...` commands disagree with the CLI golden:\n", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
