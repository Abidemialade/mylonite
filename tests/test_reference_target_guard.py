"""Adversarial tests for ``scripts/check_reference_target_inert.py``.

A guard only ever observed passing is indistinguishable from a guard that cannot
fail. The repository is clean, so running the script on it proves nothing about
whether it would catch anything -- these tests plant each violation and assert it
fires.

Most of the payloads below are not invented. They are the exact bypasses an
adversarial review ran against the FIRST version of this guard, all 19 of which
it accepted: it inspected import names and call-site names while ignoring that
allowing a package binds its root, so every capability reachable by attribute
traversal came along free. They are kept here as regression tests, because the
rewrite closes them structurally and the next person to widen an allowlist
should have to break these to do it.

Planted violations are parsed in memory. None touches ``reference_targets/`` on
disk: the real vulnerable server is oracle ground truth (see CLAUDE.md), and a
test that mutated it could leave it damaged on an interrupted run.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from scripts import check_reference_target_inert as guard


def _tree(source: str) -> ast.Module:
    return ast.parse(source)


def _at(name: str) -> Path:
    """A path inside the guarded package, for keying synthetic trees."""
    return guard.PKG_ROOT / name


# --- the repository as it stands ---------------------------------------------


def test_repository_currently_passes() -> None:
    """The guard must pass on the real tree, or every other test is moot."""
    assert guard.main() == 0


# --- check 1: inertness ------------------------------------------------------

#: Every one of these was accepted by the previous implementation.
REGRESSION_BYPASSES = [
    # Binding a capable root, then traversing to capability.
    "import asyncio",
    "import mcp.client.stdio",
    "from mcp.client.stdio import stdio_client, StdioServerParameters",
    "import mylonite.scan.llm_types",
    "import urllib.parse",
    # No import needed at all.
    "open('/etc/shadow').read()",
    # Aliasing, which defeats a call-site-only check.
    "_e = eval\n_e('payload')",
    "_x = exec",
    "handler = __import__",
]

#: Straightforwardly capable imports the first version also had to reject.
PLAIN_CAPABILITY = [
    "import subprocess",
    "import socket",
    "import os",
    "import pickle",
    "import importlib",
    "import httpx",
    "import requests",
    "import shutil",
    "import tempfile",
    "import ctypes",
    "from urllib.request import urlopen",
    "from mylonite.scan.engine import run",
    "import mylonite",
]


@pytest.mark.parametrize("source", REGRESSION_BYPASSES, ids=lambda s: s.split("\n")[0])
def test_rejects_the_bypasses_that_defeated_the_first_version(source: str) -> None:
    findings = guard.check_inertness({_at("server_vulnerable.py"): _tree(source)})
    assert findings, f"{source!r} is a known bypass and must be rejected"


@pytest.mark.parametrize("source", PLAIN_CAPABILITY, ids=lambda s: s.replace(" ", "-"))
def test_rejects_capability_imports(source: str) -> None:
    findings = guard.check_inertness({_at("server_vulnerable.py"): _tree(source)})
    assert findings, f"{source!r} should have been rejected"


@pytest.mark.parametrize("name", sorted(guard.BANNED_NAMES))
def test_rejects_banned_names_wherever_they_appear(name: str) -> None:
    """Not just at a call site -- a bare reference is enough to alias it."""
    findings = guard.check_inertness({_at("server_vulnerable.py"): _tree(f"_alias = {name}")})
    assert findings, f"a bare reference to {name} should have been rejected"


@pytest.mark.parametrize(
    "source",
    [
        "import sys",
        "import json",
        "import re",
        "from dataclasses import dataclass, field",
        "from typing import Any",
        "from urllib.parse import urlparse",
        "from mylonite.scan.llm_types import ToolDescription",
        "from mcp_kitchen_sink._store import NoteStore",
        "from ._store import NoteStore",  # relative imports never leave the package
    ],
    ids=lambda s: s.replace(" ", "-"),
)
def test_allows_the_real_imports(source: str) -> None:
    assert guard.check_inertness({_at("server_vulnerable.py"): _tree(source)}) == []


def test_inert_stdlib_is_allowed_so_the_guard_does_not_block_real_work() -> None:
    """`json` was once rejected, which is friction with no security value.

    The threat model is "reach the outside world". A module that cannot do that
    must not cost a contributor an issue thread.
    """
    for module in ("json", "enum", "datetime", "collections", "itertools", "math"):
        source = f"import {module}"
        assert guard.check_inertness({_at("server_vulnerable.py"): _tree(source)}) == [], (
            f"{module} is inert and should not be blocked"
        )


# --- the transport exception -------------------------------------------------


@pytest.mark.parametrize("source", ["import asyncio", "import mcp.types as types"])
def test_transport_imports_allowed_only_in_the_transport_file(source: str) -> None:
    assert guard.check_inertness({_at("_stdio_common.py"): _tree(source)}) == []
    assert guard.check_inertness({_at("server_vulnerable.py"): _tree(source)}), (
        "the servers must not be able to import the transport stack"
    )


# --- check 2: declared vs dispatched surface ---------------------------------


def _server(declared: tuple[str, ...], dispatched: tuple[str, ...]) -> str:
    tools = ", ".join(f'ToolDescription(name="{n}")' for n in declared)
    branches = "\n".join(f'    if name == "{n}":\n        return 1' for n in dispatched)
    return f"def list_tools():\n    return [{tools}]\n\ndef _call_tool(name, arguments):\n{branches or '    return 0'}\n"


def test_rejects_a_dispatch_branch_with_no_declaration() -> None:
    """The backdoor shape: reachable over the wire, invisible on the surface."""
    trees = {
        _at("server_vulnerable.py"): _tree(
            _server(("read_note",), ("read_note", "run_shell")),
        ),
        _at("server_guarded.py"): _tree(_server(("read_note",), ("read_note",))),
    }
    findings = guard.check_surface(trees)
    assert any("run_shell" in f.message for f in findings)


def test_rejects_a_declaration_never_dispatched() -> None:
    trees = {
        _at("server_vulnerable.py"): _tree(_server(("read_note", "ghost"), ("read_note",))),
        _at("server_guarded.py"): _tree(_server(("read_note",), ("read_note",))),
    }
    findings = guard.check_surface(trees)
    assert any("ghost" in f.message for f in findings)


def test_accepts_agreeing_surfaces() -> None:
    trees = {
        _at("server_vulnerable.py"): _tree(_server(("read_note",), ("read_note",))),
        _at("server_guarded.py"): _tree(_server(("read_note",), ("read_note",))),
    }
    assert guard.check_surface(trees) == []


# --- check 3: parity ---------------------------------------------------------


def _declared_only(*names: str) -> str:
    body = ", ".join(f'ToolDescription(name="{n}")' for n in names)
    return f"tools = [{body}]"


def test_parity_rejects_a_tool_the_guarded_twin_lacks() -> None:
    trees = {
        _at("server_vulnerable.py"): _tree(_declared_only("read_note", "exfiltrate")),
        _at("server_guarded.py"): _tree(_declared_only("read_note")),
    }
    assert any("exfiltrate" in f.message for f in guard.check_parity(trees))


def test_parity_allows_the_guarded_twin_to_add_tools() -> None:
    """``confirm_send`` exists only on the guarded side -- that is W4's mitigation."""
    trees = {
        _at("server_vulnerable.py"): _tree(_declared_only("send_email")),
        _at("server_guarded.py"): _tree(_declared_only("send_email", "confirm_send")),
    }
    assert guard.check_parity(trees) == []


# --- check 4: catalogue ------------------------------------------------------


def _seed(**overrides: object) -> dict[str, object]:
    seed: dict[str, object] = {
        "id": "W1",
        "name": "example",
        "summary": "read_note does something unwise",
        "vulnerable_locus": "server_vulnerable.list_tools",
        "guarded_locus": "server_guarded.list_tools",
    }
    seed.update(overrides)
    return seed


@pytest.fixture
def servers() -> dict[Path, ast.Module]:
    both = "class S:\n    def list_tools(self): pass\n"
    return {
        _at("server_vulnerable.py"): _tree(both),
        _at("server_guarded.py"): _tree(both),
    }


def test_catalogue_rejects_a_locus_pointing_at_deleted_code(
    servers: dict[Path, ast.Module],
) -> None:
    seeds = [_seed(vulnerable_locus="server_vulnerable.renamed_away")]
    assert any("renamed_away" in f.message for f in guard.check_catalogue(servers, seeds))


def test_catalogue_rejects_a_locus_naming_an_unknown_module(
    servers: dict[Path, ast.Module],
) -> None:
    seeds = [_seed(guarded_locus="server_invented.list_tools")]
    assert any("server_invented" in f.message for f in guard.check_catalogue(servers, seeds))


def test_catalogue_rejects_duplicate_ids(servers: dict[Path, ast.Module]) -> None:
    assert any("duplicate" in f.message for f in guard.check_catalogue(servers, [_seed(), _seed()]))


def test_catalogue_tolerates_the_prose_parenthetical(servers: dict[Path, ast.Module]) -> None:
    """Only the ``module.symbol`` head is resolved; the rest is for humans."""
    seeds = [_seed(vulnerable_locus="server_vulnerable.list_tools (read_note branch)")]
    assert guard.check_catalogue(servers, seeds) == []


# --- check 5: coverage -------------------------------------------------------


def test_coverage_rejects_a_tool_no_seed_mentions() -> None:
    trees = {_at("server_vulnerable.py"): _tree(_declared_only("read_note", "run_shell"))}
    assert any("run_shell" in f.message for f in guard.check_coverage(trees, [_seed()]))


@pytest.mark.parametrize("name", ["read", "send", "list", "note", "fetch", "call"])
def test_coverage_is_not_defeated_by_choosing_a_substring_name(name: str) -> None:
    """These names all rode free on the real catalogue under a substring match.

    ``read`` matched ``read_note``, ``list`` matched ``allowlist``, and so on --
    so the check could be bypassed by naming a tool carefully.
    """
    seeds = [_seed(summary="read_note returns raw bodies; send_email and the allowlist")]
    trees = {_at("server_vulnerable.py"): _tree(_declared_only(name))}
    assert guard.check_coverage(trees, seeds), f"{name!r} must not match on a substring"


def test_coverage_accepts_a_tool_a_seed_actually_names() -> None:
    trees = {_at("server_vulnerable.py"): _tree(_declared_only("read_note"))}
    assert guard.check_coverage(trees, [_seed()]) == []
