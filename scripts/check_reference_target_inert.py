#!/usr/bin/env python3
"""Guard the deliberately-vulnerable reference target against a real backdoor.

WHY THIS EXISTS
---------------
``reference_targets/mcp_kitchen_sink`` ships an intentionally insecure MCP
server. CLAUDE.md's rule is that a weakness there is fine if it is catalogued in
``seeds/seeds.yaml`` and a real bug otherwise. That rule has no teeth on its own:
a contributor can add anything to ``server_vulnerable.py`` and label it
"intentional, see the seed catalogue", and no reviewer can cheaply falsify the
claim. It is the best place in this repository to hide malicious code, precisely
because insecure code there is expected.

What makes the file auditable is a property it has today: the package is INERT.
``web_fetch`` does not fetch and ``send_email`` does not send -- both are
simulated against an in-memory store. Every seeded weakness is a *behavioural*
flaw in how simulated tools are described and sequenced, not a real capability.

So a seeded weakness and a genuine backdoor are separable by construction: a
backdoor needs real I/O, and there is none here to hide among. This script pins
that. It does not judge whether a weakness is "intended" -- an unwinnable
argument -- it asserts the cheaper property that this code cannot reach the
outside world at all.

HOW IT AVOIDS BEING THEATRE
---------------------------
An earlier version of this script allowed a module prefix and stopped there. A
review showed that was worthless: 19 hostile payloads passed it, because
allowing ``asyncio`` also allows ``asyncio.create_subprocess_shell``, allowing
``mcp`` allows ``mcp.client.stdio.stdio_client``, and allowing
``mylonite.scan.llm_types`` allows ``mylonite.os.system`` -- Python binds the
ROOT package name, so any capability reachable by attribute traversal from it
comes along. Checking import statements while ignoring attribute access is
checking the doorway and not the wall.

Two rules replace that, and between them they close attribute traversal by
construction rather than by blocklist:

1. **Capable roots may only be imported ``from``, never bound as a name.**
   ``from urllib.parse import urlparse`` binds ``urlparse``; ``import
   urllib.parse`` binds ``urllib``, and from there ``urllib.request.urlopen`` is
   two attributes away. Same for ``mylonite`` and ``mcp``. If the module object
   is never bound, there is nothing to traverse.

2. **Transport imports are confined to one file.** ``asyncio`` and ``mcp``
   genuinely carry capability, and exactly one module needs them:
   ``_stdio_common.py``, which is the wire transport. Every other module --
   including both servers, where the seeded weaknesses live -- is held to the
   inert set. The blast radius of "this import is dangerous but necessary" is
   one 90-line file that does no tool work.

THE CHECKS
----------
1. INERTNESS  -- per-file import allowlist, plus the two rules above, plus a ban
                 on data-to-code builtins (checked wherever the NAME appears, so
                 ``_e = eval`` does not slip past a call-site-only check).
2. SURFACE    -- the tools ``_call_tool`` dispatches on must be exactly the tools
                 ``list_tools`` declares. This is what stops "add a hidden branch
                 and call it intentional": an undeclared branch is reachable,
                 because the stdio layer forwards any name straight through.
3. PARITY     -- the guarded twin covers every tool the vulnerable one exposes.
4. CATALOGUE  -- every seed's loci resolve to real symbols, and every exposed
                 tool is named by some seed.

WHAT THIS DOES NOT CLAIM
------------------------
Passing does not mean the reference target is secure. It is emphatically not,
and must not be -- see CLAUDE.md.

Scope is the shipped package (``src/mcp_kitchen_sink/``). It does NOT cover the
target's own ``tests/`` or its ``pyproject.toml`` build hooks, both of which
execute in CI. Those are covered by CODEOWNERS review on ``reference_targets/``,
not by this script; do not read a pass here as a statement about them.

Nor is this a sandbox. It reasons about source, so a sufficiently determined
author can still construct capability (``getattr`` chains over allowed objects,
say). It raises the cost from "add a plausible-looking import" to "write
something that visibly does not belong in a note-taking fixture", which is the
difference between a backdoor that survives review and one that does not.

Widening any allowlist here is a security decision, not a build fix.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_ROOT = REPO_ROOT / "reference_targets" / "mcp_kitchen_sink"
PKG_ROOT = TARGET_ROOT / "src" / "mcp_kitchen_sink"
SEEDS_PATH = TARGET_ROOT / "seeds" / "seeds.yaml"

#: Modules any file here may import, in any form. Every one is incapable of
#: I/O by itself: data structures, text handling, and arithmetic.
#:
#: `json` and friends are on this list deliberately. An earlier version omitted
#: them, so a contributor writing a legitimate seeded weakness hit a hard failure
#: on `import json` and was told to open an issue -- friction with no security
#: value whatsoever, since `json` cannot reach anything.
#:
#: Deliberately absent, and not an oversight: `base64` and `binascii`. Decoding a
#: payload from an opaque blob is the exact shape CONTRIBUTING.md bans, so if one
#: is ever genuinely needed that should be argued in an issue.
INERT_MODULES = frozenset(
    {
        "__future__",
        "abc",
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "functools",
        "itertools",
        "json",
        "math",
        "mcp_kitchen_sink",
        "re",
        "string",
        "sys",
        "textwrap",
        "typing",
        "uuid",
    }
)

#: Modules reachable ONLY via ``from X import name``, never ``import X``.
#:
#: Each is a submodule of a package that also contains capability. Binding the
#: root name would make that capability two attribute lookups away:
#: ``urllib`` -> ``urllib.request.urlopen``, ``mylonite`` -> ``mylonite.os``
#: (``mylonite/__init__.py`` imports ``os``). Importing the leaf names instead
#: binds only the functions and classes actually wanted.
FROM_IMPORT_ONLY = frozenset(
    {
        "urllib.parse",
        "mylonite.scan.llm_types",
    }
)

#: Files permitted to import the transport stack, and what each may import.
#:
#: ``asyncio`` and ``mcp`` are the two genuinely capable dependencies --
#: ``asyncio.create_subprocess_shell`` and ``mcp.client.stdio.stdio_client``
#: both spawn processes. They are needed to speak the wire protocol at all, so
#: they are confined to the module that does exactly that and nothing else.
TRANSPORT_IMPORTS: dict[str, frozenset[str]] = {
    "_stdio_common.py": frozenset({"asyncio", "mcp"}),
}

#: Names that turn data into code, or open a file. Checked wherever the NAME is
#: loaded, not only at a call site, so aliasing (``_e = eval``) is caught too.
#:
#: ``open`` is here because it needs no import: it is the one capability the
#: inert allowlist cannot deny by omission.
BANNED_NAMES = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
        "globals",
        "locals",
        "open",
        "vars",
    }
)


class Finding(NamedTuple):
    """One violation, rendered as an editor-clickable line."""

    path: Path
    line: int
    message: str

    def render(self) -> str:
        rel = self.path.relative_to(REPO_ROOT).as_posix()
        return f"{rel}:{self.line}: {self.message}"


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _python_files() -> list[Path]:
    return sorted(PKG_ROOT.rglob("*.py"))


def _root(module: str) -> str:
    return module.split(".", 1)[0]


def _allowed_roots(path: Path) -> frozenset[str]:
    """Module roots this specific file may bind, transport exception included."""
    return INERT_MODULES | TRANSPORT_IMPORTS.get(path.name, frozenset())


def check_inertness(trees: dict[Path, ast.Module]) -> list[Finding]:
    """No import and no name may give this package real-world reach."""
    findings: list[Finding] = []
    for path, tree in trees.items():
        allowed = _allowed_roots(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FROM_IMPORT_ONLY or _root(alias.name) in {
                        _root(m) for m in FROM_IMPORT_ONLY
                    }:
                        findings.append(
                            Finding(
                                path,
                                node.lineno,
                                f"`import {alias.name}` binds the root package "
                                f"{_root(alias.name)!r}, which also contains capability "
                                f"reachable by attribute access. Use `from "
                                f"{alias.name} import <name>` instead.",
                            )
                        )
                    elif _root(alias.name) not in allowed:
                        findings.append(
                            Finding(
                                path,
                                node.lineno,
                                f"imports {alias.name!r}, which is not inert and is not "
                                f"permitted in this file. See this script's docstring "
                                f"before widening any allowlist.",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                # A relative import never leaves the package; those files are
                # scanned on their own account.
                if node.level:
                    continue
                module = node.module or ""
                if module in FROM_IMPORT_ONLY:
                    continue
                if _root(module) not in allowed:
                    findings.append(
                        Finding(
                            path,
                            node.lineno,
                            f"imports from {module!r}, which is not inert and is not "
                            f"permitted in this file. See this script's docstring "
                            f"before widening any allowlist.",
                        )
                    )
            elif (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in BANNED_NAMES
            ):
                findings.append(
                    Finding(
                        path,
                        node.lineno,
                        f"uses {node.id!r}, which turns data into code or opens a file. "
                        f"The seeded weaknesses are behavioural; none needs it.",
                    )
                )
    return findings


def _declared_tools(tree: ast.Module) -> dict[str, int]:
    """Tool names declared as ``ToolDescription(name="...")``, mapped to line."""
    names: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if called != "ToolDescription":
            continue
        for kw in node.keywords:
            if (
                kw.arg == "name"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                names.setdefault(kw.value.value, kw.value.lineno)
    return names


def _dispatched_tools(tree: ast.Module) -> dict[str, int]:
    """Tool names a ``_call_tool`` body compares against, mapped to line.

    Matches ``name == "x"`` and ``name in ("x", "y")`` inside any function whose
    first argument is called ``name`` -- the dispatch shape both servers use.
    """
    names: dict[str, int] = {}
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        args = [a.arg for a in func.args.args]
        if "name" not in args:
            continue
        for node in ast.walk(func):
            if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name):
                continue
            if node.left.id != "name":
                continue
            for comparator in node.comparators:
                parts = (
                    comparator.elts
                    if isinstance(comparator, ast.Tuple | ast.List | ast.Set)
                    else [comparator]
                )
                for part in parts:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        names.setdefault(part.value, part.lineno)
    return names


def check_surface(trees: dict[Path, ast.Module]) -> list[Finding]:
    """Dispatched tools must equal declared tools, on both twins.

    This is the check that prices "add a hidden branch and call it intentional".
    ``_stdio_common.py`` forwards whatever tool name arrives straight to
    ``call_tool`` without consulting ``list_tools``, so a dispatch branch with no
    matching ``ToolDescription`` is fully reachable over the wire while being
    invisible to anything that reads only the declared surface -- including, in
    an earlier version, every other check in this file.

    Both directions are errors. An undeclared branch is the backdoor shape. A
    declared-but-undispatched tool is a weaker signal, but it means the
    advertised surface and the real one disagree, which is how the first kind
    gets to look normal.
    """
    findings: list[Finding] = []
    for filename in ("server_vulnerable.py", "server_guarded.py"):
        path = PKG_ROOT / filename
        if path not in trees:
            findings.append(Finding(PKG_ROOT, 0, f"expected {filename} to exist"))
            continue
        declared = _declared_tools(trees[path])
        dispatched = _dispatched_tools(trees[path])
        findings += [
            Finding(
                path,
                line,
                f"dispatches tool {name!r}, which no ToolDescription declares. The "
                f"stdio layer forwards any name to call_tool, so this branch is "
                f"reachable while staying off the advertised surface.",
            )
            for name, line in sorted(dispatched.items())
            if name not in declared
        ]
        findings += [
            Finding(
                path,
                line,
                f"declares tool {name!r} but never dispatches it; the advertised "
                f"surface and the real one disagree.",
            )
            for name, line in sorted(declared.items())
            if name not in dispatched
        ]
    return findings


def check_parity(trees: dict[Path, ast.Module]) -> list[Finding]:
    """Guarded must cover every tool vulnerable exposes.

    One-directional on purpose. The guarded twin legitimately adds tools the
    vulnerable one lacks (``confirm_send`` is W4's whole mitigation), but a tool
    only on the vulnerable side is capability with no defended counterpart --
    both the shape of an added backdoor and a hole in the differential oracle,
    since nothing on the guarded side can prove it blocked.
    """
    vuln_path = PKG_ROOT / "server_vulnerable.py"
    guard_path = PKG_ROOT / "server_guarded.py"
    if vuln_path not in trees or guard_path not in trees:
        return []

    guarded = set(_declared_tools(trees[guard_path]))
    return [
        Finding(
            vuln_path,
            line,
            f"tool {name!r} is exposed by the vulnerable server but has no "
            f"counterpart in server_guarded.py, so the differential oracle can "
            f"never show it being blocked.",
        )
        for name, line in sorted(_declared_tools(trees[vuln_path]).items())
        if name not in guarded
    ]


def _load_seeds() -> tuple[list[dict[str, object]], list[Finding]]:
    try:
        import yaml
    except ModuleNotFoundError:  # pragma: no cover - dev dependency
        return [], [Finding(SEEDS_PATH, 0, "PyYAML is required to check the seed catalogue")]
    try:
        loaded = yaml.safe_load(SEEDS_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [], [Finding(SEEDS_PATH, 0, f"could not read the seed catalogue: {exc}")]
    if not isinstance(loaded, list):
        return [], [Finding(SEEDS_PATH, 0, "the seed catalogue must be a list of seeds")]
    return [s for s in loaded if isinstance(s, dict)], []


def _defined_symbols(tree: ast.Module) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    }


def check_catalogue(trees: dict[Path, ast.Module], seeds: list[dict[str, object]]) -> list[Finding]:
    """Each locus must point at a symbol that exists, and ids must be unique.

    A locus reads ``server_vulnerable.call_tool (web_fetch branch)``. Only the
    ``module.symbol`` head is resolved; the parenthetical is prose for a human.
    Resolving the head catches the failure that matters -- an entry left pointing
    at renamed or deleted code, which silently becomes a seed nobody can check.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for seed in seeds:
        seed_id = seed.get("id")
        if not isinstance(seed_id, str):
            findings.append(Finding(SEEDS_PATH, 0, f"a seed has no string id: {seed!r}"))
            continue
        if seed_id in seen:
            findings.append(Finding(SEEDS_PATH, 0, f"duplicate seed id {seed_id!r}"))
        seen.add(seed_id)

        for field in ("vulnerable_locus", "guarded_locus"):
            raw = seed.get(field)
            if not isinstance(raw, str) or not raw.strip():
                findings.append(Finding(SEEDS_PATH, 0, f"{seed_id}: {field} is missing"))
                continue
            head = raw.split("(")[0].strip()
            module, _, symbol = head.partition(".")
            path = PKG_ROOT / f"{module}.py"
            if path not in trees:
                findings.append(
                    Finding(SEEDS_PATH, 0, f"{seed_id}: {field} names unknown module {module!r}")
                )
                continue
            if symbol and symbol not in _defined_symbols(trees[path]):
                findings.append(
                    Finding(
                        SEEDS_PATH,
                        0,
                        f"{seed_id}: {field} points at {head!r}, but {module}.py defines "
                        f"no such symbol. Renamed or deleted code leaves a seed nobody "
                        f"can verify.",
                    )
                )
    return findings


def check_coverage(trees: dict[Path, ast.Module], seeds: list[dict[str, object]]) -> list[Finding]:
    """Every vulnerable tool must be named by at least one seed.

    Matches on word boundaries, not substrings. A plain ``in`` test let a tool
    called ``send`` ride on a seed that happened to mention ``send_email``, and
    ``list``, ``read``, ``fetch``, ``note`` and ``call`` were all free for the
    same reason -- so the check could be defeated by choosing a name.
    """
    import re

    vuln_path = PKG_ROOT / "server_vulnerable.py"
    if vuln_path not in trees:
        return []
    catalogue_text = " ".join(
        str(value)
        for seed in seeds
        for key, value in seed.items()
        if key in {"name", "summary", "vulnerable_locus", "guarded_locus"}
    )
    return [
        Finding(
            vuln_path,
            line,
            f"tool {name!r} is not named anywhere in seeds/seeds.yaml. Every "
            f"capability on the vulnerable server needs a catalogue entry saying "
            f"what weakness it demonstrates.",
        )
        for name, line in sorted(_declared_tools(trees[vuln_path]).items())
        if not re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", catalogue_text)
    ]


def main() -> int:
    if not PKG_ROOT.is_dir():
        print(f"error: {PKG_ROOT} does not exist", file=sys.stderr)
        return 2

    trees: dict[Path, ast.Module] = {}
    for path in _python_files():
        try:
            trees[path] = _parse(path)
        except SyntaxError as exc:
            print(f"{path}:{exc.lineno}: could not parse: {exc.msg}", file=sys.stderr)
            return 2

    seeds, findings = _load_seeds()
    findings += check_inertness(trees)
    findings += check_surface(trees)
    findings += check_parity(trees)
    findings += check_catalogue(trees, seeds)
    findings += check_coverage(trees, seeds)

    if findings:
        print("Reference-target guard failed:\n", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.render()}", file=sys.stderr)
        print(
            "\nThe vulnerable reference target is allowed to be insecure, but only in "
            "\nways the seed catalogue names and the guarded twin can block. See "
            "\nscripts/check_reference_target_inert.py for what each check protects.",
            file=sys.stderr,
        )
        return 1

    print(
        f"reference target inert: {len(trees)} modules, {len(seeds)} catalogued seeds, "
        f"no capability imports, declared and dispatched surfaces agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
