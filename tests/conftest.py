"""Root fixtures shared across the whole test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _check_and_ablate_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """`check` and `ablate` are hidden, experimental CLI commands gated on
    `MYLONITE_EXPERIMENTAL=1` (see `mylonite._experimental`). Most of the
    suite -- tests/test_cli.py, tests/test_cli_keyless.py,
    tests/scan/test_ablate_cli.py, tests/integration/
    test_scaffold_credential_vars.py and others -- predates the gate and
    invokes the two commands directly to exercise their real behaviour, not
    the gate itself, so the variable is ON by default for every test.

    `tests/test_experimental.py` tests the gate itself and overrides this
    per call (`CliRunner.invoke(..., env={"MYLONITE_EXPERIMENTAL": None})`)
    -- a per-call `env` mapping always wins over this ambient default for
    the duration of that one invocation (`click.testing`'s isolation saves
    and restores whatever was set before applying the override).
    """
    monkeypatch.setenv("MYLONITE_EXPERIMENTAL", "1")


@pytest.fixture(autouse=True)
def _no_request_ceiling(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The LLM request ceiling is process-wide state: one test's count or trip
    must never leak into the next. Start every test with no ceiling and a zero
    count, and clear whatever the test left behind."""
    from mylonite.scan._llm import REQUEST_CEILING_ENV, reset_request_ceiling

    monkeypatch.delenv(REQUEST_CEILING_ENV, raising=False)
    reset_request_ceiling()
    yield
    reset_request_ceiling()
