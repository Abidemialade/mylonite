"""Offline demo support for ``mylonite demo`` (v0.3.0, PR A).

``mylonite.demo._replay`` holds the LiteLLM record/replay core promoted from
``tests/integration/_recorder.py`` so recorded real-LLM fixtures can ship
inside the wheel. The demo runner, rendering, and CLI wiring land in later
tasks of PR A.

Recorded fixtures live under ``mylonite/demo/fixtures/<variant>/`` —
namespaced per target variant because the replay cache key is the
``(model, messages)`` pair only (see ``_replay`` module docstring).
"""

from __future__ import annotations

from mylonite.demo._replay import (
    DEMO_RERECORD_HINT,
    CorruptFixtureError,
    FixtureConflictError,
    FixtureError,
    LiteLLMRecorder,
    MissingFixtureError,
    packaged_fixture_dir,
)

__all__ = [
    "DEMO_RERECORD_HINT",
    "CorruptFixtureError",
    "FixtureConflictError",
    "FixtureError",
    "LiteLLMRecorder",
    "MissingFixtureError",
    "packaged_fixture_dir",
]
