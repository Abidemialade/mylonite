"""The LLM transport seam is a single named type, and stays that way.

Guards issue #95: `completion_fn` was annotated as an anonymous
`Callable[..., Any]` in ~27 signatures across five subpackages. It now uses the
named `mylonite.scan.llm_types.CompletionFn` (or `AsyncCompletionFn`). These
tests fail if a `completion_fn` parameter reverts to a bare `Callable[...]`
annotation anywhere in `src/`.
"""

from __future__ import annotations

import re
from pathlib import Path

from mylonite.scan.llm_types import AsyncCompletionFn, CompletionFn

_SRC = Path(__file__).resolve().parents[2] / "src" / "mylonite"

# A `*completion_fn` parameter/attribute annotated as a bare Callable, e.g.
# `completion_fn: Callable[..., Any]` or `mitigation_completion_fn: Callable[...`.
_BARE_CALLABLE_SEAM = re.compile(r"completion_fn:\s*Callable\[")


def test_aliases_exist() -> None:
    assert CompletionFn is not None
    assert AsyncCompletionFn is not None


def test_no_completion_fn_uses_a_bare_callable_annotation() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _BARE_CALLABLE_SEAM.search(line):
                offenders.append(f"{path.relative_to(_SRC)}:{i}")
    assert not offenders, (
        "these completion_fn annotations are a bare Callable instead of the named "
        f"CompletionFn / AsyncCompletionFn from mylonite.scan.llm_types: {offenders}"
    )
