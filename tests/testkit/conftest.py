"""Shared fixtures for the testkit tests."""

from __future__ import annotations

import pytest

from mylonite import testkit


@pytest.fixture(autouse=True)
def _no_redrive_attempts_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests pin the default number of live re-drive attempts, so a value left
    in the developer's or CI runner's environment must not change it."""
    monkeypatch.delenv(testkit.REDRIVE_ATTEMPTS_ENV, raising=False)
