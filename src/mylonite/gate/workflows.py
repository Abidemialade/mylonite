"""Write the gating workflow templates into a target repo's .github/workflows/."""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path

_TEMPLATES = ("mylonite-gate.yml", "mylonite-discovery.yml")


def write_workflows(repo_root: Path, *, runs_on: str = "ubuntu-latest") -> list[Path]:
    """Render both workflow templates into ``repo_root/.github/workflows/``.

    ``runs_on`` replaces the ``__RUNS_ON__`` token — pass a self-hosted label
    (e.g. ``"[self-hosted, linux]"``) for in-perimeter enterprise runners.
    Returns the written paths.
    """
    dest = repo_root / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    base = ir.files("mylonite.gate") / "templates"
    written: list[Path] = []
    for name in _TEMPLATES:
        text = (base / name).read_text(encoding="utf-8").replace("__RUNS_ON__", runs_on)
        out = dest / name
        out.write_text(text, encoding="utf-8")
        written.append(out)
    return written
