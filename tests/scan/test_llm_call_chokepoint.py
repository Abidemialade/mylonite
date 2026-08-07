"""T14 class-killer (mirrors T10's ``test_adapter_construction_chokepoint.py``):
nothing outside a small, explicit allowlist may call ``litellm.completion``/
``litellm.acompletion`` directly.

Root cause this guards against: before T14, ``LLMPlanner.run()`` called
``completion(**call_kwargs)`` directly (bypassing budget-counting AND every
``LLMPolicy`` kwarg — temperature/max_tokens/drop_params/seed/api_base/...),
and ``gate.mitigation._llm_suggestion`` hardcoded
``litellm.completion(model="claude-haiku-4-5-20251001", ...)`` with the same
gap. Both were fixed by routing through ``scan._llm``'s chokepoint functions
(``litellm_json_call``/``_async``, ``litellm_tool_call_async``,
``litellm_text_call``). This test is what makes a FUTURE regression of the
same shape fail the build instead of silently reintroducing the bug: an
AST-walk over every ``.py`` file under ``src/mylonite/`` looking for a call
to ``litellm.completion``/``litellm.acompletion``, failing if a call site
outside the allowlist below is found.

This does not claim to make a direct call structurally IMPOSSIBLE (there is
no import-time enforcement -- see ``scan/_llm.py``'s ``llm_scope`` docstring
for that caveat) -- it makes one CI-visible, matching T10's own scope.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "mylonite"

#: Every file allowed to call ``litellm.completion``/``litellm.acompletion``
#: directly, and WHY -- an allowlist entry with no comment is a bug.
_ALLOWED_FILES: dict[Path, str] = {
    (SRC_ROOT / "scan" / "_llm.py").resolve(): (
        "the chokepoint itself -- litellm_json_call[_async]/"
        "litellm_tool_call_async/litellm_text_call are WHERE the real call "
        "happens; everything else is supposed to go through one of them."
    ),
    (SRC_ROOT / "cli.py").resolve(): (
        "doctor()'s one-shot (max_tokens=1) connectivity ping. Deliberately "
        "bypasses budget-counting/LLMPolicy: it is not part of a scan's call "
        "budget and its whole job is probing a REAL provider round-trip "
        "before any policy/oracle concern applies."
    ),
    (SRC_ROOT / "demo" / "_replay.py").resolve(): (
        "the demo recorder's record-mode passthrough -- this IS the "
        "'real completion' a caller's completion_fn injection point "
        "(the seam every chokepoint function exposes) resolves to when "
        "MYLONITE_TEST_RECORD=1; it is downstream of the chokepoint, not a "
        "bypass of it, exactly the way a test's own completion_fn stub is."
    ),
}

_GUARDED_ATTRS = frozenset({"completion", "acompletion"})


class _LitellmCallVisitor(ast.NodeVisitor):
    """Finds every ``<name>.completion`` / ``<name>.acompletion`` ATTRIBUTE
    REFERENCE (not just an immediate call) where ``<name>`` was bound by
    ``import litellm`` -- so ``foo.completion()`` on an unrelated object is
    not a false positive, and (deliberately) so is a reference that's stored
    rather than called immediately.

    Attribute-reference, not just Call: ``scan/_llm.py``'s own style is
    ``fn = completion_fn or litellm.completion`` followed by a LATER
    ``fn(**call_kwargs)`` — the ``litellm.completion``/``litellm.acompletion``
    token itself never appears as an ``ast.Call``'s ``.func``, only as a bare
    ``ast.Attribute`` expression. Restricting this to ``ast.Call`` nodes would
    make the chokepoint file itself invisible to the allowlist sanity check
    below (and would miss an equivalent indirection bug elsewhere: assigning
    ``litellm.completion`` to a variable is just as much a direct-call
    bypass as calling it inline, once that variable is invoked).
    """

    def __init__(self) -> None:
        self.refs: list[tuple[int, str]] = []
        self._litellm_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "litellm":
                self._litellm_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            node.attr in _GUARDED_ATTRS
            and isinstance(node.value, ast.Name)
            and node.value.id in self._litellm_names
        ):
            self.refs.append((node.lineno, node.attr))
        self.generic_visit(node)


def _iter_src_py_files() -> list[Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def _visit(path: Path) -> _LitellmCallVisitor:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # A module-level `import litellm` binds the name for the WHOLE file (every
    # function body sees it), so a single visitor pass — Import nodes anywhere
    # in the tree feed the same `_litellm_names` set every Attribute node
    # checks against — correctly handles both a top-of-file import and a
    # local (inside-a-function) one, regardless of which comes first in the
    # walk order relative to any given attribute reference.
    visitor = _LitellmCallVisitor()
    visitor.visit(tree)
    return visitor


def test_litellm_completion_calls_are_confined_to_the_allowlist() -> None:
    offenders: list[str] = []
    for path in _iter_src_py_files():
        resolved = path.resolve()
        if resolved in _ALLOWED_FILES:
            continue
        visitor = _visit(path)
        for lineno, attr in visitor.refs:
            offenders.append(
                f"{path.relative_to(SRC_ROOT.parent.parent)}:{lineno} (litellm.{attr})"
            )
    assert offenders == [], (
        "litellm.completion/litellm.acompletion must only be called from the "
        "explicit allowlist in this test (scan/_llm.py's chokepoint, "
        "cli.py's doctor() ping, demo/_replay.py's recorder passthrough) — "
        "found a direct call elsewhere, which can silently skip both "
        f"budget-counting and every LLMPolicy kwarg: {offenders}"
    )


def test_allowlisted_files_do_still_call_litellm_directly() -> None:
    """Sanity check on the visitor + allowlist (mirrors T10's own factory
    sanity check): every allowlisted file DOES contain at least one direct
    call, otherwise the chokepoint test above would trivially pass because a
    file was removed/rewritten out from under a stale allowlist entry."""
    missing: list[str] = []
    for path, _reason in _ALLOWED_FILES.items():
        visitor = _visit(path)
        if not visitor.refs:
            missing.append(str(path))
    assert missing == [], (
        f"expected these allowlisted files to still call litellm.completion/"
        f"acompletion directly; found none — the allowlist entry (and this "
        f"test) is stale and should be removed: {missing}"
    )


def test_llm_module_itself_is_the_only_file_with_json_call_helpers() -> None:
    """Cheap defense-in-depth: litellm_json_call/_async, litellm_tool_call_async,
    and litellm_text_call (the chokepoint functions callers are SUPPOSED to
    use instead of calling litellm directly) are all actually defined in
    scan/_llm.py -- catches a future refactor that splits them out without
    updating this test's allowlist reasoning."""
    llm_py = (SRC_ROOT / "scan" / "_llm.py").resolve()
    tree = ast.parse(llm_py.read_text(encoding="utf-8"), filename=str(llm_py))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    expected = {
        "litellm_json_call",
        "litellm_json_call_async",
        "litellm_tool_call_async",
        "litellm_text_call",
    }
    assert expected <= defined, (
        f"expected {expected} defined in {llm_py}, found {defined & expected}"
    )
