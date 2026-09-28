"""Shared environment pinning for the CLI golden tests.

Rich sizes its console output from the ``COLUMNS`` env var (falling back to
terminal detection, which differs between a CI runner and a local shell).
Pinning ``COLUMNS`` plus disabling colour keeps the captured text identical
on ubuntu and Windows CI. ``TERM=dumb`` additionally discourages any
terminal-capability probing.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _pinned_terminal(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("NO_COLOR", "1")
    yield
