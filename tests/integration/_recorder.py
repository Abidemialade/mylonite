"""Back-compat shim — the LiteLLM record/replay core now lives in
``mylonite._replay`` (promoted in v0.3.0, PR A, so recorded fixtures can ship
inside the wheel).

This module keeps the test-side pieces (``ScriptedLLM``, ``make_recorder``,
``fixture_dir``) and re-exports the promoted core, including the private
helpers existing tests import directly (``_stable_key``,
``_response_from_dict``).

Mode is controlled by ``MYLONITE_TEST_RECORD``. The default is replay-only,
which deliberately raises ``MissingFixtureError`` on a cache miss — the test
fails loudly rather than silently making an unexpected network call.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mylonite._replay import (
    CorruptFixtureError,
    FixtureConflictError,
    LiteLLMRecorder,
    MissingFixtureError,
    _dictify_response,
    _response_from_dict,
    _stable_key,
)

#: Test-side re-record hint — the demo default names
#: ``scripts/record_demo_fixtures.py`` instead.
TEST_RECORD_HINT = (
    "Re-run with MYLONITE_TEST_RECORD=1 to capture, or add the fixture file manually."
)


# --- ScriptedLLM -------------------------------------------------------------


@dataclass
class ScriptedLLM:
    """Sequential-response stub for integration tests.

    Tests pre-build a list of completion responses (or callables that produce
    one) and pass an instance as ``completion_fn``. Each call consumes the
    next item; running out is a loud test failure.

    Used by ``test_scan_vulnerable.py`` / ``test_scan_guarded.py`` because no
    real LLM fixtures are committed in v0.2 (the recorder is ready for them
    in v0.2.1+).
    """

    responses: list[Any] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self.responses:
            raise RuntimeError(
                f"ScriptedLLM out of responses on call {len(self.calls)}; kwargs={kwargs}"
            )
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(**kwargs)
        return item


# --- Recorder fixture helper for pytest ------------------------------------


def make_recorder(fixtures_dir: Path) -> LiteLLMRecorder:
    """Construct a recorder honouring ``MYLONITE_TEST_RECORD``."""
    mode: Literal["record", "replay"] = (
        "record" if os.environ.get("MYLONITE_TEST_RECORD") == "1" else "replay"
    )
    return LiteLLMRecorder(
        fixtures_dir=fixtures_dir,
        mode=mode,
        missing_fixture_hint=TEST_RECORD_HINT,
    )


def fixture_dir() -> Path:
    """Default fixtures directory: ``tests/integration/fixtures/litellm``."""
    return Path(__file__).parent / "fixtures" / "litellm"


__all__ = [
    "CorruptFixtureError",
    "FixtureConflictError",
    "LiteLLMRecorder",
    "MissingFixtureError",
    "ScriptedLLM",
    "_dictify_response",
    "_response_from_dict",
    "_stable_key",
    "fixture_dir",
    "make_recorder",
]
