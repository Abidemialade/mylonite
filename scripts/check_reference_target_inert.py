#!/usr/bin/env python3
"""Guard the deliberately-vulnerable reference target against a real backdoor.

WHY THIS EXISTS
---------------
``reference_targets/mcp_kitchen_sink`` ships an intentionally insecure MCP
server. CLAUDE.md's rule is that a weakness there is fine if it is catalogued in
``seeds/seeds.yaml`` and a real bug otherwise. That rule has no teeth: a
contributor can add anything to ``server_vulnerable.py`` and label it
"intentional, see the seed catalogue", and no reviewer can cheaply falsify the
claim. It is the single best place in this repository to hide malicious code,
precisely because insecure code there is expected.

What makes the file auditable is a property it happens to have today: the whole
package is INERT. It imports no network, no subprocess, no filesystem, no
deserialisation. ``web_fetch`` does not fetch and ``send_email`` does not send —
both are simulated against an in-memory store. Every seeded weakness is a
*behavioural* flaw in how the simulated tools are described and sequenced, not a
real capability.

So the seeded weaknesses and a genuine backdoor are separable by construction: a
backdoor needs real I/O, and there is currently none to hide among. This script
pins that. It does not try to judge whether a weakness is "intended" — an
unwinnable argument — it asserts the far cheaper property that no code here can
reach the outside world at all.

THE FOUR CHECKS
---------------
1. INERTNESS   — imports come from a fixed allowlist; no dynamic-execution or
                 deserialisation builtins are called.
2. PARITY      — the guarded twin exposes every tool the vulnerable one does. A
                 tool that exists only on the vulnerable side is an uncatalogued
                 capability, which is what an added backdoor tool looks like.
3. CATALOGUE   — every seed's ``vulnerable_locus`` / ``guarded_locus`` resolves
                 to a symbol that actually exists, so the catalogue cannot rot
                 into a rubber stamp that points at nothing.
4. COVERAGE    — every tool on the vulnerable server is named by some seed's
                 locus, so a tool cannot be added without a catalogue entry.

WHAT THIS DOES NOT CLAIM
------------------------
Passing does not mean the reference target is secure. It is emphatically not,
and must not be — see CLAUDE.md. It means the target cannot reach the network,
spawn a process, read the filesystem, or execute constructed code, so its
insecurity stays confined to the simulated tool surface the oracle measures.

Widening ``ALLOWED_IMPORT_PREFIXES`` is therefore a security decision, not a
build fix. If a change here genuinely needs real I/O, that is a design
discussion in an issue, not a one-line edit to the allowlist.
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

#: Dotted module prefixes the reference target may import. A module matches if
#: it equals an entry or is a submodule of one.
#:
#: Prefixes, not top-level roots, because two entries here are only safe at
#: submodule granularity:
#:
#: - ``urllib.parse`` is pure string parsing (``urlparse`` backs the guarded
#:   server's W3 hostname allowlist). Allowing bare ``urllib`` would admit
#:   ``urllib.request``, which fetches.
#: - ``mylonite.scan.llm_types`` is a declared dependency re-exporting the
#:   shared Pydantic models (see the target's pyproject.toml). Allowing bare
#:   ``mylonite`` would admit LiteLLM and with it real network reach -- the
#:   reference target would gain, transitively, the capability this file exists
#:   to deny it.
#:
#: Everything else is inert: data structures, text handling, or the MCP protocol
#: plumbing the server is *for*. Absent by design: subprocess, socket, http,
#: httpx, requests, os, pathlib, shutil, pickle, marshal, shelve, ctypes,
#: importlib, tempfile.
#:
#: ``asyncio`` and ``mcp`` are the two carrying real capability, and both are
#: confined to the stdio entrypoints -- the transport, not the tool bodies.
ALLOWED_IMPORT_PREFIXES = (
    "__future__",
    "asyncio",
    "dataclasses",
    "mcp",
    "mcp_kitchen_sink",
    "mylonite.scan.llm_types",
    "re",
    "sys",
    "typing",
    "urllib.parse",
)


def _import_allowed(module: str) -> bool:
    """True when ``module`` is an allowed prefix or a submodule of one."""
    return any(
        module == prefix or module.startswith(f"{prefix}.") for prefix in ALLOWED_IMPORT_PREFIXES
    )


#: Builtins that turn data into code, or bytes into objects. A backdoor that
#: could not import its way to a capability would reach for one of these.
BANNED_CALLS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})


class Finding(NamedTuple):
    """One violation, in a form that renders as an editor-clickable line."""

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


def check_inertness(trees: dict[Path, ast.Module]) -> list[Finding]:
    """No import and no call may give this package real-world reach."""
    findings: list[Finding] = []
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not _import_allowed(alias.name):
                        findings.append(
                            Finding(
                                path,
                                node.lineno,
                                f"imports {alias.name!r}, which is not on the inertness "
                                f"allowlist. The reference target must stay incapable of "
                                f"real I/O; see this script's docstring before widening it.",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                # A relative import (level > 0) never leaves the package.
                if node.level:
                    continue
                if not _import_allowed(node.module or ""):
                    findings.append(
                        Finding(
                            path,
                            node.lineno,
                            f"imports from {node.module!r}, which is not on the inertness "
                            f"allowlist. The reference target must stay incapable of "
                            f"real I/O; see this script's docstring before widening it.",
                        )
                    )
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in BANNED_CALLS
            ):
                findings.append(
                    Finding(
                        path,
                        node.lineno,
                        f"calls {node.func.id}(), which turns data into code. The "
                        f"seeded weaknesses are behavioural; none needs this.",
                    )
                )
    return findings


def _tool_names(tree: ast.Module) -> dict[str, int]:
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


def check_parity(trees: dict[Path, ast.Module]) -> list[Finding]:
    """Guarded must cover every tool vulnerable exposes.

    Deliberately one-directional. The guarded twin legitimately adds tools the
    vulnerable one lacks (``confirm_send`` is W4's whole mitigation), but a tool
    that exists ONLY on the vulnerable side is capability with no defended
    counterpart -- which is both the shape of an added backdoor and a hole in the
    differential oracle, since nothing on the guarded side can prove it blocked.
    """
    vuln_path = PKG_ROOT / "server_vulnerable.py"
    guard_path = PKG_ROOT / "server_guarded.py"
    if vuln_path not in trees or guard_path not in trees:
        return [Finding(PKG_ROOT, 0, "expected both server_vulnerable.py and server_guarded.py")]

    vulnerable = _tool_names(trees[vuln_path])
    guarded = set(_tool_names(trees[guard_path]))
    return [
        Finding(
            vuln_path,
            line,
            f"tool {name!r} is exposed by the vulnerable server but has no "
            f"counterpart in server_guarded.py, so the differential oracle can "
            f"never show it being blocked.",
        )
        for name, line in sorted(vulnerable.items())
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
    """Every function, method and class name defined in a module."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            out.add(node.name)
    return out


def check_catalogue(trees: dict[Path, ast.Module], seeds: list[dict[str, object]]) -> list[Finding]:
    """Each locus must point at a symbol that exists, and ids must be unique.

    A locus reads ``server_vulnerable.call_tool (web_fetch branch)``. Only the
    ``module.symbol`` head is resolved; the parenthetical is prose for a human.
    Resolving the head is enough to catch the failure that matters -- a catalogue
    entry left pointing at code that was renamed or deleted, which silently
    becomes a seed nobody can check.
    """
    findings: list[Finding] = []
    seen: dict[str, object] = {}

    for seed in seeds:
        seed_id = seed.get("id")
        if not isinstance(seed_id, str):
            findings.append(Finding(SEEDS_PATH, 0, f"a seed has no string id: {seed!r}"))
            continue
        if seed_id in seen:
            findings.append(Finding(SEEDS_PATH, 0, f"duplicate seed id {seed_id!r}"))
        seen[seed_id] = seed

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

    This is what stops "add a tool, call it intentional" from being free. The
    match is on the tool name appearing anywhere in a seed's loci or summary,
    which is loose on purpose: the goal is to force a contributor adding a tool
    to write down why, not to police catalogue prose.
    """
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
            f"tool {name!r} is not mentioned anywhere in seeds/seeds.yaml. Every "
            f"capability on the vulnerable server needs a catalogue entry saying "
            f"what weakness it is there to demonstrate.",
        )
        for name, line in sorted(_tool_names(trees[vuln_path]).items())
        if name not in catalogue_text
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
        f"no un-allowlisted imports, no unguarded tools"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
