"""Shared environment pinning for the CLI golden tests.

Rich sizes its console output from the ``COLUMNS`` env var (falling back to
terminal detection, which differs between a CI runner and a local shell).
Pinning ``COLUMNS`` plus disabling colour keeps the captured text identical
on ubuntu and Windows CI. ``TERM=dumb`` additionally discourages any
terminal-capability probing.

The dry-run goldens also embed the resolved ``provider=`` / ``model=``
(``scan``'s report line) and the LLM-call cap, both of which
``_resolve_model_ref``/``_env_run_config_or_exit`` resolve from — in
descending precedence — an explicit CLI flag (none here), a ``mylonite.yaml``
auto-discovered from the working directory, then ``MYLONITE_*`` env vars
(``MYLONITE_MODEL``, ``MYLONITE_PROVIDER``, ...), then the command's hardcoded
default. Provider API-key and ``LITELLM_*`` vars can also change what a
command reports (e.g. a warning line). None of that is under this test
suite's control on a developer's machine or a CI runner that happens to
export one of them — a real regression here shipped as a golden failure only
when ``MYLONITE_MODEL`` was set in the environment. Strip every var in those
families and run from an empty temp directory so the goldens depend only on
the code under test.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _pinned_terminal(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("NO_COLOR", "1")
    yield


@pytest.fixture(autouse=True)
def _isolated_llm_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Strip every env var that could change a command's resolved
    provider/model/cap, and run from an empty directory so no
    auto-discovered ``./mylonite.yaml`` or ``.env`` can either.

    Covers ``MYLONITE_*`` (every flat env var the settings model reads:
    ``MYLONITE_MODEL``, ``MYLONITE_PROVIDER``, ``MYLONITE_ROOT``, ...),
    ``LITELLM_*``, and anything :func:`mylonite.scan.providers.
    looks_like_provider_env_var` recognises as a provider credential/config
    var (``*_API_KEY``, the ``AZURE_*`` family, Bedrock's AWS credential
    pair, ...) — the same recognition ``--env-file`` uses, reused here so
    this list can't drift from what the CLI itself treats as
    provider-shaped. The demo fixture lookup uses ``importlib.resources``
    (package-relative, not cwd-relative) and the reference targets are
    in-process, so neither depends on the working directory this chdirs
    into.
    """
    from mylonite.scan.providers import looks_like_provider_env_var

    for key in list(os.environ):
        if (
            key.startswith("MYLONITE_")
            or key.startswith("LITELLM_")
            or looks_like_provider_env_var(key)
        ):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    yield
