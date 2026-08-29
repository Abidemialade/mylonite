"""Adversarial tests for ``scripts/check_reference_target_inert.py``.

A guard that has only ever been observed passing is indistinguishable from a
guard that cannot fail. The repository is currently clean, so running the script
on it proves nothing about whether it would catch anything — these tests plant
each violation it claims to detect and assert it fires.

The planted violations are written as source strings and parsed in memory. None
touches ``reference_targets/`` on disk: the real vulnerable server is oracle
ground truth (see CLAUDE.md), and a test that mutated it could leave it damaged
on an interrupted run.
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


# --- check 1: inertness -------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "import socket",
        "import os",
        "import pickle",
        "import urllib.request",  # sibling of the allowed urllib.parse
        "from urllib.request import urlopen",
        "import httpx",
        "from mylonite.scan.engine import run",  # sibling of the allowed llm_types
        "import mylonite",  # the bare root would drag in LiteLLM
    ],
    ids=lambda s: s.replace(" ", "-"),
)
def test_inertness_rejects_capability_imports(source: str) -> None:
    findings = guard.check_inertness({_at("server_vulnerable.py"): _tree(source)})
    assert findings, f"{source!r} should have been rejected"


@pytest.mark.parametrize(
    "source",
    [
        "import sys",
        "import asyncio",
        "from urllib.parse import urlparse",
        "from mylonite.scan.llm_types import ToolDescription",
        "import mcp.types as types",
        "from mcp.server.stdio import stdio_server",
        "from mcp_kitchen_sink._store import NoteStore",
        "from ._store import NoteStore",  # relative imports never leave the package
    ],
    ids=lambda s: s.replace(" ", "-"),
)
def test_inertness_allows_the_real_imports(source: str) -> None:
    assert guard.check_inertness({_at("server_vulnerable.py"): _tree(source)}) == []


@pytest.mark.parametrize("call", ["eval", "exec", "compile", "__import__"])
def test_inertness_rejects_dynamic_execution(call: str) -> None:
    findings = guard.check_inertness({_at("server_vulnerable.py"): _tree(f"{call}('x')")})
    assert findings, f"{call}() should have been rejected"


# --- check 2: tool-surface parity --------------------------------------------


def _server(*names: str) -> str:
    body = ", ".join(f'ToolDescription(name="{n}")' for n in names)
    return f"tools = [{body}]"


def test_parity_rejects_a_tool_the_guarded_twin_lacks() -> None:
    trees = {
        _at("server_vulnerable.py"): _tree(_server("read_note", "exfiltrate")),
        _at("server_guarded.py"): _tree(_server("read_note")),
    }
    findings = guard.check_parity(trees)
    assert any("exfiltrate" in f.message for f in findings)


def test_parity_allows_the_guarded_twin_to_add_tools() -> None:
    """``confirm_send`` exists only on the guarded side — that is W4's mitigation."""
    trees = {
        _at("server_vulnerable.py"): _tree(_server("send_email")),
        _at("server_guarded.py"): _tree(_server("send_email", "confirm_send")),
    }
    assert guard.check_parity(trees) == []


# --- check 3: catalogue integrity --------------------------------------------


def _seed(**overrides: object) -> dict[str, object]:
    seed = {
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
    findings = guard.check_catalogue(servers, seeds)
    assert any("renamed_away" in f.message for f in findings)


def test_catalogue_rejects_a_locus_naming_an_unknown_module(
    servers: dict[Path, ast.Module],
) -> None:
    seeds = [_seed(guarded_locus="server_invented.list_tools")]
    findings = guard.check_catalogue(servers, seeds)
    assert any("server_invented" in f.message for f in findings)


def test_catalogue_rejects_duplicate_ids(servers: dict[Path, ast.Module]) -> None:
    findings = guard.check_catalogue(servers, [_seed(), _seed()])
    assert any("duplicate" in f.message for f in findings)


def test_catalogue_tolerates_the_prose_parenthetical(servers: dict[Path, ast.Module]) -> None:
    """Only the ``module.symbol`` head is resolved; the rest is for humans."""
    seeds = [_seed(vulnerable_locus="server_vulnerable.list_tools (read_note branch)")]
    assert guard.check_catalogue(servers, seeds) == []


# --- check 4: coverage --------------------------------------------------------


def test_coverage_rejects_a_tool_no_seed_mentions() -> None:
    trees = {_at("server_vulnerable.py"): _tree(_server("read_note", "run_shell"))}
    findings = guard.check_coverage(trees, [_seed()])
    assert any("run_shell" in f.message for f in findings)


def test_coverage_accepts_a_tool_a_seed_names() -> None:
    trees = {_at("server_vulnerable.py"): _tree(_server("read_note"))}
    assert guard.check_coverage(trees, [_seed()]) == []
