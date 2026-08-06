"""Write the gating workflow templates into a target repo's .github/workflows/."""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path

from mylonite.layout import DEFAULT_LAYOUT

_TEMPLATES = ("mylonite-gate.yml", "mylonite-discovery.yml")


def write_workflows(
    repo_root: Path,
    *,
    runs_on: str = "ubuntu-latest",
    gate_dir: Path = DEFAULT_LAYOUT.gate,
) -> list[Path]:
    """Render both workflow templates into ``repo_root/.github/workflows/``.

    A token MAP is substituted into each template (rather than a single
    string-replace) so the scaffolded workflows can reference the ACTUAL
    configured gate directory instead of a hardcoded default baked into the
    YAML:

    * ``__RUNS_ON__`` -> ``runs_on`` — a self-hosted label (e.g.
      ``"[self-hosted, linux]"``) for in-perimeter enterprise runners.
    * ``__GATE_DIR__`` -> ``gate_dir`` (posix-style) — the ``gate --out``
      directory the committed test / target.yaml actually live under;
      defaults to :data:`mylonite.layout.DEFAULT_LAYOUT`'s gate dir.

    Returns the written paths.
    """
    tokens = {"__RUNS_ON__": runs_on, "__GATE_DIR__": Path(gate_dir).as_posix()}
    dest = repo_root / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    base = ir.files("mylonite.gate") / "templates"
    written: list[Path] = []
    for name in _TEMPLATES:
        text = (base / name).read_text(encoding="utf-8")
        for token, value in tokens.items():
            text = text.replace(token, value)
        out = dest / name
        out.write_text(text, encoding="utf-8")
        written.append(out)
    return written
