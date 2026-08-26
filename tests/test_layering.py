"""Enforce the package layering direction (issue #97).

`docs/architecture.md` and `scan/exec_context.py` state the intended direction:

    contracts  <-  scan / plugins  <-  gate / report  <-  cli

It was stated in prose and enforced nowhere. This test enforces it for
**module-level** imports (the import-time dependency edges the layering is
about): a lower tier must not import from a higher one.

Deliberately scoped to top-level imports, so it does not flag:
- `if TYPE_CHECKING:` imports (annotations only, no runtime edge), or
- function-local imports (the codebase's intentional escape valve for
  cost-containment / cycle-avoidance, e.g. building a `gate.recommend`
  `TargetContext` from a target-file spec).

If you need a genuinely new cross-layer dependency, move the shared code down to
a tier both sides can import (as the mitigation snippets were moved to
`mylonite.mitigations`), rather than importing upward.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "mylonite"

# Lower number = lower tier. A module may import its own tier or below, never above.
_TIER = {
    "contracts": 0,
    "scan": 1,
    "plugins": 1,
    "gate": 2,
    "report": 2,
    "cli": 3,
}


def _segment(rel: Path) -> str:
    """The tiered package segment for a file relative to ``mylonite/``.

    ``gate/mitigation.py`` -> ``gate``; ``cli.py`` -> ``cli``.
    """
    first = rel.parts[0]
    return first[:-3] if first.endswith(".py") else first


def _imported_segment(module: str) -> str | None:
    """The tiered segment a ``mylonite.<seg>...`` import targets, else None."""
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "mylonite":
        return parts[1]
    return None


def test_no_module_level_import_runs_against_the_layering() -> None:
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        src_seg = _segment(path.relative_to(_SRC))
        src_tier = _TIER.get(src_seg)
        if src_tier is None:
            continue  # utility leaves / testkit / etc. are not tiered
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:  # module-level only
            targets: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                targets.append(node.module)
            elif isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            for module in targets:
                tgt_seg = _imported_segment(module)
                if tgt_seg is None:
                    continue
                tgt_tier = _TIER.get(tgt_seg)
                if tgt_tier is not None and tgt_tier > src_tier:
                    offenders.append(
                        f"{path.relative_to(_SRC)}:{node.lineno} ({src_seg} -> {tgt_seg}: {module})"
                    )
    assert not offenders, (
        "these module-level imports run against the layering "
        "(contracts <- scan/plugins <- gate/report <- cli):\n  " + "\n  ".join(offenders)
    )
