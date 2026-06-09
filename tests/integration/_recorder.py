"""LiteLLMRecorder — record once against a real provider, replay forever.

The recorder hashes the (model, messages) pair, persists the LiteLLM response
under ``tests/integration/fixtures/litellm/<sha>.json``, and on subsequent
runs returns the cached response without making a network call. The Phase 1
integration tests opt into this so CI doesn't need a live API key while still
exercising the engine end-to-end against realistic completions.

Mode is controlled by ``MYLONITE_TEST_RECORD``. The default is replay-only,
which deliberately raises ``MissingFixtureError`` on a cache miss — the test
fails loudly rather than silently making an unexpected network call.

This module is part of the Phase 1 deliverable per the design spec and the
eng review's G4 finding. Phase 1's integration tests rely on the
``ScriptedLLM`` stub instead (also in this module) since they predate any
recorded fixtures; the recorder is the path forward in Phase 1.5+.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal


class MissingFixtureError(RuntimeError):
    """Raised in replay mode when no fixture matches the (model, messages) pair."""


def _stable_key(model: str, messages: Sequence[Any]) -> str:
    payload = json.dumps(
        {"model": model, "messages": list(messages)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _response_from_dict(data: dict[str, Any]) -> SimpleNamespace:
    """Rebuild a minimal LiteLLM-shaped response object from JSON."""
    choices = []
    for choice in data.get("choices", []):
        message = choice.get("message", {})
        tool_calls_raw = message.get("tool_calls")
        tool_calls: list[Any] | None = None
        if tool_calls_raw:
            tool_calls = [
                SimpleNamespace(
                    id=tc.get("id", "call_0"),
                    function=SimpleNamespace(
                        name=tc["function"]["name"],
                        arguments=tc["function"]["arguments"],
                    ),
                )
                for tc in tool_calls_raw
            ]
        choices.append(
            SimpleNamespace(
                message=SimpleNamespace(
                    content=message.get("content", ""),
                    tool_calls=tool_calls,
                )
            )
        )
    return SimpleNamespace(choices=choices)


@dataclass
class LiteLLMRecorder:
    """JSON-backed record/replay helper for ``litellm.acompletion``."""

    fixtures_dir: Path
    mode: Literal["record", "replay"] = "replay"
    cache_hits: int = 0
    cache_misses: int = 0

    def __post_init__(self) -> None:
        self.fixtures_dir = Path(self.fixtures_dir)
        if self.mode == "record":
            self.fixtures_dir.mkdir(parents=True, exist_ok=True)

    async def __call__(self, *, model: str, messages: Sequence[Any], **_: Any) -> SimpleNamespace:
        key = _stable_key(model, list(messages))
        path = self.fixtures_dir / f"{key}.json"
        if self.mode == "replay":
            if not path.exists():
                self.cache_misses += 1
                raise MissingFixtureError(
                    f"No fixture for sha256={key} (model={model!r}). "
                    f"Re-run with MYLONITE_TEST_RECORD=1 to capture, or add a "
                    f"fixture file at {path}."
                )
            self.cache_hits += 1
            return _response_from_dict(json.loads(path.read_text(encoding="utf-8")))
        # record mode — defer to litellm.acompletion for the real call.
        import litellm

        real = await litellm.acompletion(model=model, messages=list(messages))
        path.write_text(
            json.dumps(_dictify_response(real), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return real


def _dictify_response(response: Any) -> dict[str, Any]:
    """Best-effort JSON shape for an OpenAI-compatible LiteLLM completion."""
    choices = []
    for choice in getattr(response, "choices", []):
        msg = getattr(choice, "message", None)
        choices.append(
            {
                "message": {
                    "content": getattr(msg, "content", "") or "",
                    "tool_calls": [
                        {
                            "id": getattr(tc, "id", "call_0"),
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in (getattr(msg, "tool_calls", None) or [])
                    ],
                }
            }
        )
    return {"choices": choices}


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
    return LiteLLMRecorder(fixtures_dir=fixtures_dir, mode=mode)


def fixture_dir() -> Path:
    """Default fixtures directory: ``tests/integration/fixtures/litellm``."""
    return Path(__file__).parent / "fixtures" / "litellm"


__all__ = [
    "LiteLLMRecorder",
    "MissingFixtureError",
    "ScriptedLLM",
    "fixture_dir",
    "make_recorder",
]


# Keep dependency on Callable visible for re-exports / type-stub generators.
_REEXPORT_HINT: tuple[type, ...] = (Callable,)  # type: ignore[type-arg]
