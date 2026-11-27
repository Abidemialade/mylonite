"""No user-facing string in ``src/`` names one provider's key variable.

Mylonite has no default provider. A message that says ``ANTHROPIC_API_KEY``
reads as "this is the one you need" to someone on another provider, so the
variable names live in the provider registry and nowhere else. Messages use
``unreachable_hint`` (which names the key for the model's own provider) or
neutral wording such as "your provider's API key".
"""

from __future__ import annotations

import ast
from pathlib import Path

from mylonite.providers.registry import PROVIDERS

SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"
REGISTRY_DIR = SRC / "providers"

#: (path relative to src/mylonite, variable) -> why a literal is unavoidable.
ALLOWLIST: dict[tuple[str, str], str] = {
    (
        "scan/diagnostics.py",
        name,
    ): "lists several providers' keys side by side; none is implied as the default"
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")
} | {
    (
        "scan/llm_policy.py",
        name,
    ): "lists two providers' keys side by side as examples of a credential env var"
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
}


def _provider_key_vars() -> set[str]:
    names: set[str] = set()
    for info in PROVIDERS.values():
        names.update(info.key_env)
    return {n for n in names if n}


def _literals(path: Path) -> list[tuple[int, str]]:
    """String literals a person can be shown; docstrings and comments are not."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_user_facing_string_names_one_providers_key() -> None:
    names = _provider_key_vars()
    assert "ANTHROPIC_API_KEY" in names, "registry names changed; the scan would be vacuous"

    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if REGISTRY_DIR in path.parents:
            continue
        rel = path.relative_to(SRC).as_posix()
        for lineno, text in _literals(path):
            for name in sorted(names):
                if name in text and (rel, name) not in ALLOWLIST:
                    offenders.append(f"{rel}:{lineno} names {name}")

    assert not offenders, (
        "user-facing strings must not name one provider's key; use "
        "unreachable_hint or neutral wording:\n  " + "\n  ".join(offenders)
    )
