"""Single source of truth for the package version.

Genuinely single: ``pyproject.toml`` declares ``dynamic = ["version"]`` and points
``[tool.hatch.version].path`` at this file, so the built distribution's metadata
and ``mylonite.__version__`` cannot disagree. Bump it here and nowhere else --
``scripts/prepare_release.py`` does exactly that.
"""

from __future__ import annotations

__version__ = "0.8.1"
