"""Enforce the LLM chokepoint: `src/` never calls `litellm.completion` /
`litellm.acompletion` directly outside the wrapper that owns budget counting and
the active LLMPolicy.

`docs/architecture.md` states "All LLM access flows through LiteLLM". The second
half of that -- through the *counting/policy-applying* wrapper, not a raw
`litellm.completion` -- was a convention, not structure: the `doctor` command
once called `litellm.completion(...)` directly, skipping the
`LiteLLMCallCounter` and `LLMPolicy` (`llm_policy.py`: "a call site that skips it
silently changes what the oracle is measuring"). This test removes that decision
by making the next such bypass a red build, mirroring
`test_cli_output_boundary.py`.

Uses AST (not a regex) so a `litellm.completion(...)` mention inside a docstring
or comment -- there are several, documenting the historical call -- is not a
false positive; only a real call node counts.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"

# The chokepoint itself resolves `completion_fn or litellm.completion` and calls
# it via `fn(...)`. `_replay.py` is the recorder, which calls `litellm.acompletion`
# *downstream* of the chokepoint (injected as a completion_fn), not as a bypass.
_ALLOWED = {"_llm.py", "_replay.py"}

_CHOKEPOINT_METHODS = {"completion", "acompletion"}


def _is_litellm_call(node: ast.AST) -> bool:
    """True if ``node`` is a ``litellm.completion(...)`` / ``.acompletion(...)`` call."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _CHOKEPOINT_METHODS
        and isinstance(func.value, ast.Name)
        and func.value.id == "litellm"
    )


def test_no_direct_litellm_completion_calls_outside_the_chokepoint() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name in _ALLOWED:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if _is_litellm_call(node):
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno}")
    assert not offenders, (
        "these call litellm.completion/acompletion directly, bypassing the "
        "budget counter + LLMPolicy — route through mylonite.scan.llm "
        "(litellm_json_call / _async / litellm_tool_call_async) instead:\n  "
        + "\n  ".join(offenders)
    )
