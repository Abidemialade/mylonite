"""Pytest plugin that registers the markers mylonite-emitted tests carry.

Auto-loaded for any pytest invocation in an environment where ``mylonite`` is
installed, via the ``pytest11`` entry point declared in ``pyproject.toml``. Its
sole job is to register — warning-free — the bounded set of markers the
reference pytest generator emits:

* ``mylonite_security`` — flags a Mylonite-generated security regression test.
* ``owasp_llm01`` .. ``owasp_llm10`` — OWASP LLM Top 10 (2025) category.
* ``owasp_asi01`` .. ``owasp_asi10`` — OWASP Agentic Security Initiative (2026).

Without this registration an emitted test would raise ``PytestUnknownMarkWarning``,
which the project's ``filterwarnings = ["error", ...]`` config promotes to a
failure. ATLAS / NIST IDs are deliberately NOT markers (their identifier space
is unbounded); they ride in the emitted test's docstring instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register the mylonite-emitted markers so they collect warning-free."""
    config.addinivalue_line(
        "markers",
        "mylonite_security: a Mylonite-generated security regression test",
    )
    for n in range(1, 11):
        config.addinivalue_line(
            "markers",
            f"owasp_llm{n:02d}: OWASP LLM Top 10 (2025) category LLM{n:02d}",
        )
        config.addinivalue_line(
            "markers",
            f"owasp_asi{n:02d}: OWASP Agentic Security Initiative (2026) category ASI{n:02d}",
        )
