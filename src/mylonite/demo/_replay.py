"""LiteLLM record/replay core for the offline ``mylonite demo``.

Promoted from ``tests/integration/_recorder.py`` (v0.2.x) so recorded
real-LLM fixtures can ship inside the wheel. Hashing behaviour is unchanged:
the cache key is the canonicalised ``(model, messages)`` pair ONLY — extra
call kwargs such as ``tools`` are deliberately excluded from the key (they
ARE forwarded to the underlying call in record mode). Because the tool
schema is exactly what differs between the vulnerable and guarded reference
variants, fixtures MUST be namespaced per variant
(``fixtures/vulnerable/``, ``fixtures/guarded/``) — identical
first-iteration messages would otherwise collide on the same key.

Replay mode accepts any ``importlib.resources`` Traversable for
``fixtures_dir``, so fixtures can be read straight out of an installed
wheel or zip. Record mode requires a real ``pathlib.Path`` — it has to
``mkdir`` and write, which the Traversable protocol does not offer.

Error-surfacing contract: the scan engine's ``_llm.py`` fallback chain and
the adapter's skip-conversion swallow exceptions raised by
``completion_fn``, so a demo runner must inspect recorder state after the
run (``cache_misses``, ``last_error``) rather than rely on exception
propagation.

This module must not import from ``mylonite.scan`` (keeps the demo package
cycle-free).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

DEMO_RERECORD_HINT = (
    "Re-record the demo fixtures with scripts/record_demo_fixtures.py "
    "(requires a live provider key)."
)


class FixtureError(RuntimeError):
    """Common base for all fixture record/replay errors."""


class MissingFixtureError(FixtureError):
    """Raised in replay mode when no fixture matches the (model, messages) pair."""


class CorruptFixtureError(FixtureError):
    """Raised in replay mode when a fixture file exists but is not valid JSON."""


class FixtureConflictError(FixtureError):
    """Raised in record mode when a key already exists with different content."""


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


@dataclass
class LiteLLMRecorder:
    """JSON-backed record/replay helper for ``litellm.acompletion``.

    ``fixtures_dir`` may be any ``importlib.resources`` Traversable in replay
    mode (e.g. ``packaged_fixture_dir() / "vulnerable"``); record mode
    requires a real ``pathlib.Path`` because it must ``mkdir`` and write.

    ``missing_fixture_hint`` is appended to the cache-miss error message so
    each construction site can name its own re-record procedure (the demo
    names ``scripts/record_demo_fixtures.py``; the test shim names
    ``MYLONITE_TEST_RECORD=1``).

    ``cache_hits`` / ``cache_misses`` / ``last_error`` are runner-inspectable
    state: callers in the scan engine swallow ``completion_fn`` exceptions,
    so a post-run state check is the reliable way to detect replay problems.
    Note the counter asymmetry: a corrupt fixture increments neither
    ``cache_hits`` nor ``cache_misses`` (only ``last_error`` is set), so
    callers reconciling ``hits + misses == calls`` must also check
    ``last_error``.

    Instance state is cumulative across calls — construct one recorder per
    run or call :meth:`reset` between runs (the multi-run flakiness
    filter is the motivating case). The recorder is not thread-safe, and
    ``last_error`` reflects only the most recent failure — under concurrent
    calls use the counters as the aggregate signal; the demo runner drives
    this with ``max_concurrent=1``.
    """

    fixtures_dir: Path | Traversable
    mode: Literal["record", "replay"] = "replay"
    missing_fixture_hint: str = DEMO_RERECORD_HINT
    cache_hits: int = 0
    cache_misses: int = 0
    last_error: Exception | None = None

    def __post_init__(self) -> None:
        if isinstance(self.fixtures_dir, str):
            self.fixtures_dir = Path(self.fixtures_dir)
        if self.mode == "record":
            if not isinstance(self.fixtures_dir, Path):
                raise TypeError(
                    "record mode requires a real pathlib.Path fixtures_dir "
                    f"(mkdir/write are Path-only); got {type(self.fixtures_dir).__name__}"
                )
            self.fixtures_dir.mkdir(parents=True, exist_ok=True)

    def reset(self) -> None:
        """Clear cumulative state (``cache_hits``, ``cache_misses``, ``last_error``)."""
        self.cache_hits = 0
        self.cache_misses = 0
        self.last_error = None

    async def __call__(self, *, model: str, messages: Sequence[Any], **kwargs: Any) -> Any:
        key = _stable_key(model, list(messages))
        path = self.fixtures_dir / f"{key}.json"
        if self.mode == "replay":
            return self._load_fixture(key=key, model=model, path=path)
        return await self._record(model=model, messages=messages, path=path, kwargs=kwargs)

    def _load_fixture(self, *, key: str, model: str, path: Path | Traversable) -> SimpleNamespace:
        if not path.is_file():
            self.cache_misses += 1
            missing = MissingFixtureError(
                f"No fixture for sha256={key} (model={model!r}) at {path}. "
                f"{self.missing_fixture_hint}"
            )
            self.last_error = missing
            raise missing
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            corrupt = CorruptFixtureError(
                f"fixture corrupt — reinstall mylonite or re-record: {path} is not "
                f"valid JSON ({exc}). {self.missing_fixture_hint}"
            )
            self.last_error = corrupt
            raise corrupt from exc
        self.cache_hits += 1
        return _response_from_dict(data)

    async def _record(
        self,
        *,
        model: str,
        messages: Sequence[Any],
        path: Path | Traversable,
        kwargs: dict[str, Any],
    ) -> Any:
        # Record mode — defer to litellm.acompletion for the real call. The
        # import stays lazy so replay mode never needs litellm at call time.
        # Extra kwargs (notably ``tools=`` from LLMPlanner) are forwarded to
        # the provider but deliberately excluded from the cache key.
        import litellm

        real = await litellm.acompletion(model=model, messages=list(messages), **kwargs)
        serialised = json.dumps(_dictify_response(real), indent=2, sort_keys=True) + "\n"
        assert isinstance(path, Path)  # __post_init__ enforces Path in record mode  # noqa: S101  # removed in P9
        if path.is_file():
            existing = path.read_text(encoding="utf-8")
            if existing != serialised:
                conflict = FixtureConflictError(
                    f"Refusing to overwrite existing fixture {path} with different "
                    "content — the (model, messages) key collided. Namespace "
                    "fixtures per variant (fixtures/vulnerable/, fixtures/guarded/) "
                    "or delete the stale file and re-record."
                )
                self.last_error = conflict
                raise conflict
        path.write_text(serialised, encoding="utf-8")
        return real


def packaged_fixture_dir() -> Traversable:
    """Root of the fixtures shipped inside the wheel (``mylonite/demo/fixtures``).

    Per-variant namespaces live underneath: ``<root>/vulnerable``,
    ``<root>/guarded``. Returns a Traversable so replay works from a
    zip/wheel install as well as a source checkout.
    """
    return files("mylonite.demo") / "fixtures"


__all__ = [
    "DEMO_RERECORD_HINT",
    "CorruptFixtureError",
    "FixtureConflictError",
    "FixtureError",
    "LiteLLMRecorder",
    "MissingFixtureError",
    "packaged_fixture_dir",
]
