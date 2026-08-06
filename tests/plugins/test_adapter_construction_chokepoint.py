"""T10 class-killer: nothing outside the factory module may instantiate an
MCP/HTTP target-adapter class directly.

Root cause this guards against: ``testkit`` used to construct ``MCPStdioAdapter``
directly (bypassing transport dispatch and the launch-triple threading), which
let its twin-construction drift from the real scan path (``cli.py`` -> the
transport-aware factory -> the concrete adapter). AST-walks every ``.py`` file
under ``src/mylonite/`` looking for a call to one of the three transport-
dispatched adapter classes (``MCPStdioAdapter`` / ``MCPRemoteAdapter`` /
``HTTPAgentAdapter``) and fails if the only allowed call site
(``src/mylonite/plugins/_mcp/factory.py``) isn't the one making it.

Deliberately narrow scope: the per-bundled-family 0-arg subclasses
(``FilesystemMCPAdapter``/``FetchMCPAdapter``/``GitHubMCPAdapter``, each a
``MCPStdioAdapter`` subclass) are NOT flagged here even though ``cli.py``
constructs them directly (``_build_adapter_for_mcp``) — that is a separate,
pre-existing, unrelated pattern (bundled targets are always stdio, with no
transport variation and no server-layer twin to drift on), not an instance of
the transport-dispatch bug this test guards.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "mylonite"
FACTORY_FILE = (SRC_ROOT / "plugins" / "_mcp" / "factory.py").resolve()

#: The transport-dispatched adapter classes. Instantiating one of these
#: directly is exactly the bug class T10 closes: it bypasses transport
#: dispatch AND the launch-triple threading that only ``build_adapter_for_spec``
#: (and, for the raw low-level entry point, ``build_mcp_adapter``) guarantees.
_GUARDED_CLASS_NAMES = frozenset({"MCPStdioAdapter", "MCPRemoteAdapter", "HTTPAgentAdapter"})


class _AdapterCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name in _GUARDED_CLASS_NAMES:
            self.calls.append((node.lineno, name))
        self.generic_visit(node)


def _iter_src_py_files() -> list[Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def test_adapter_construction_chokepoint() -> None:
    offenders: list[str] = []
    for path in _iter_src_py_files():
        resolved = path.resolve()
        if resolved == FACTORY_FILE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        visitor = _AdapterCallVisitor()
        visitor.visit(tree)
        for lineno, name in visitor.calls:
            offenders.append(f"{path.relative_to(SRC_ROOT.parent.parent)}:{lineno} ({name})")
    assert offenders == [], (
        "MCPStdioAdapter/MCPRemoteAdapter/HTTPAgentAdapter must only be "
        "instantiated inside plugins/_mcp/factory.py (build_mcp_adapter / "
        "build_adapter_for_spec) — found direct construction elsewhere, which "
        "can silently skip transport dispatch and/or the launch-triple "
        f"threading: {offenders}"
    )


def test_factory_file_itself_does_construct_every_guarded_class() -> None:
    """Sanity check on the visitor + allowlist: the factory module DOES
    contain calls to all three guarded class names (otherwise the chokepoint
    test above would trivially pass by the classes never being called at
    all — e.g. if someone renamed a class and the visitor's name set went
    stale)."""
    tree = ast.parse(FACTORY_FILE.read_text(encoding="utf-8"), filename=str(FACTORY_FILE))
    visitor = _AdapterCallVisitor()
    visitor.visit(tree)
    found = {name for _lineno, name in visitor.calls}
    assert found == _GUARDED_CLASS_NAMES, (
        f"expected factory.py to construct all of {sorted(_GUARDED_CLASS_NAMES)}, "
        f"found {sorted(found)} — either the factory or this test's allowlist is stale"
    )
