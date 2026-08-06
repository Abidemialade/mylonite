"""LiteLLM record/replay core for the offline ``mylonite demo``.

Promoted from ``tests/integration/_recorder.py`` (v0.2.x) so recorded
real-LLM fixtures can ship inside the wheel.

Cache-key format versions
--------------------------
Two cache-key algorithms exist, selected PER ``fixtures_dir`` (see
:func:`_resolve_key_version`):

* **v1** (:func:`_stable_key_v1`, the original ``_stable_key``) hashes the
  canonicalised ``(model, messages)`` pair ONLY — ``tools``,
  ``tool_choice``, ``response_format``, and ``api_base`` are excluded from
  the key (though still forwarded to the underlying call in record mode).
  This is a real gap: two calls with the same ``(model, messages)`` but a
  DIFFERENT tool schema or response-format mode collide on the same fixture
  file, and replay silently returns whichever response was recorded first.
  Because the tool schema is exactly what used to differ between the
  vulnerable and guarded reference variants, fixtures had to be namespaced
  per variant (``fixtures/vulnerable/``, ``fixtures/guarded/``) to avoid
  this collision — v1 is kept, byte-for-byte, ONLY so the already-shipped
  fixture directories (``src/mylonite/demo/fixtures/*``) keep replaying;
  nothing should record NEW fixtures with it.
* **v2** (:func:`_stable_key_v2`) additionally folds ``tools``,
  ``tool_choice``, ``response_format``, and ``api_base`` into the key —
  everything that changes what response comes back for the same
  conversation — while still excluding ``api_key`` (a secret, and rotating
  it must never cause a cache miss) and other non-identity call plumbing
  (e.g. ``timeout``).

A ``fixtures_dir`` declares its version via a ``_meta.json`` sidecar
(``{"format_version": 2, ...}``). No sidecar means: v1 on REPLAY (the
shipped dirs predate the sidecar entirely and must keep working), v2 on
RECORD (a fresh recording should always use the best available algorithm).
See :func:`_resolve_key_version` for the full dispatch rule.

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


def _stable_key_v1(model: str, messages: Sequence[Any]) -> str:
    """Original cache-key algorithm: ``(model, messages)`` ONLY.

    Kept byte-for-byte unchanged — the already-shipped v1 fixture
    directories (``src/mylonite/demo/fixtures/*``) were recorded with this
    exact function, and :func:`_resolve_key_version` routes replay against
    them straight back here. Do not extend this function; add to
    :func:`_stable_key_v2` instead.
    """
    payload = json.dumps(
        {"model": model, "messages": list(messages)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


#: Back-compat alias — existing importers (tests, ``tests/integration/_recorder.py``)
#: use the un-suffixed name for the v1 algorithm.
_stable_key = _stable_key_v1


#: The extra call kwargs that are identity-relevant to a v2 cache key — i.e.
#: they change what response comes back for the same ``(model, messages)``
#: conversation. Deliberately an ALLOWLIST rather than "everything except a
#: denylist": an open-ended kwargs dict can carry litellm-internal objects
#: (callbacks, logging hooks, client/session objects) whose ``repr()``/``str()``
#: is not stable across calls, which would silently defeat caching if blindly
#: included. The complement of this allowlist — notably ``api_key`` (a secret;
#: rotating it must never cause a cache miss) and ``timeout`` (a client-side
#: call bound, not a request parameter) — is exactly what a denylist would
#: have named, just expressed the safer way round.
_KEY_V2_IDENTITY_KWARGS: tuple[str, ...] = ("tools", "tool_choice", "response_format", "api_base")


def _stable_key_v2(model: str, messages: Sequence[Any], **kwargs: Any) -> str:
    """v2 cache-key algorithm: ``(model, messages)`` plus identity-relevant kwargs.

    Folds in ``tools``/``tool_choice``/``response_format``/``api_base`` (when
    present and not ``None``) so two calls that differ only in tool schema or
    response-format mode no longer collide on the same fixture. ``dict``
    values (e.g. individual tool schemas) are canonicalised the same way as
    ``messages`` already was — ``json.dumps(..., sort_keys=True)`` sorts keys
    recursively through nested dicts (including those inside lists), so key
    ordering never affects the hash. A non-JSON-native value (e.g. a Pydantic
    ``response_format`` class) falls back to ``str()``, which is stable for
    the same object/class across calls.
    """
    payload: dict[str, Any] = {"model": model, "messages": list(messages)}
    for name in _KEY_V2_IDENTITY_KWARGS:
        value = kwargs.get(name)
        if value is not None:
            payload[name] = value
    body = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _read_meta_format_version(fixtures_dir: Path | Traversable) -> int | None:
    """Read the ``format_version`` int out of ``fixtures_dir/_meta.json``, or ``None``.

    ``None`` covers every "no usable signal" case uniformly — no sidecar, an
    unreadable file, invalid JSON, a non-object payload, or a missing/non-int
    ``format_version`` field — so :func:`_resolve_key_version` can apply one
    consistent default rather than each caller re-deriving intent from a
    different failure mode.
    """
    try:
        meta_path = fixtures_dir / "_meta.json"
        if not meta_path.is_file():
            return None
        raw = meta_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    version = data.get("format_version")
    return version if isinstance(version, int) else None


def _resolve_key_version(fixtures_dir: Path | Traversable, mode: Literal["record", "replay"]) -> int:
    """Pick which cache-key algorithm (1 or 2) a recorder over ``fixtures_dir`` uses.

    A directory that declares its own ``_meta.json`` ``format_version`` wins
    outright, in EITHER mode — an explicit sidecar speaks for itself. Absent a
    sidecar the two modes deliberately default differently:

    * REPLAY defaults to **v1**. The already-shipped fixture directories
      (``src/mylonite/demo/fixtures/vulnerable``, ``.../guarded``) predate
      this sidecar entirely, so "no sidecar" must mean "the original
      algorithm" or every one of them would immediately stop replaying
      (every real lookup would miss).
    * RECORD defaults to **v2**. An empty/fresh ``fixtures_dir`` has no
      legacy fixtures to protect, so a brand-new recording should always use
      the most complete algorithm. Callers that stamp ``_meta.json`` after
      recording into a fresh directory (``reference_validator.py``,
      ``scripts/record_reference_example.py``, ``scripts/record_demo_fixtures.py``)
      already write ``format_version: 2``, matching what got recorded.
    """
    declared = _read_meta_format_version(fixtures_dir)
    if declared is not None:
        return declared
    return 2 if mode == "record" else 1


def _response_from_dict(data: dict[str, Any]) -> SimpleNamespace:
    """Rebuild a minimal LiteLLM-shaped response object from JSON.

    ``finish_reason`` (per-choice) and ``usage`` (response-level) are
    reconstructed when present in the fixture JSON, ``None`` otherwise — v1
    fixtures never recorded either field, so this stays backward compatible:
    a v1-shaped fixture simply yields ``finish_reason=None`` / ``usage=None``.
    ``finish_reason == "length"`` is the signal a response was truncated
    (hit ``max_tokens``), which is exactly what a missing ``max_tokens``
    setting elsewhere would produce — capturing it lets a fixture-based test
    assert truncation was detected.
    """
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
                ),
                finish_reason=choice.get("finish_reason"),
            )
        )
    usage_data = data.get("usage")
    usage = SimpleNamespace(**usage_data) if isinstance(usage_data, dict) else None
    return SimpleNamespace(choices=choices, usage=usage)


def _usage_to_dict(usage: Any) -> dict[str, Any] | None:
    """Best-effort plain-dict shape for a LiteLLM/OpenAI ``usage`` object.

    Tries, in order: already a ``dict``; a Pydantic-style ``model_dump()``;
    falling back to the three well-known token-count attributes. Returns
    ``None`` when nothing usable is found rather than writing an empty/
    misleading ``usage`` key into the fixture.
    """
    if isinstance(usage, dict):
        return dict(usage)
    model_dump = getattr(usage, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump()
        except Exception:  # pragma: no cover - defensive, provider-object dependent
            dumped = None
        if isinstance(dumped, dict):
            return dumped
    result: dict[str, Any] = {}
    for attr in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(usage, attr, None)
        if isinstance(value, int):
            result[attr] = value
    return result or None


def _dictify_response(response: Any) -> dict[str, Any]:
    """Best-effort JSON shape for an OpenAI-compatible LiteLLM completion.

    Captures ``finish_reason`` per choice and response-level ``usage`` when
    present — see :func:`_response_from_dict` for why. Both are omitted from
    the JSON entirely when unavailable (e.g. a test double that doesn't set
    them), so old and new fixtures stay structurally compatible.
    """
    choices = []
    for choice in getattr(response, "choices", []):
        msg = getattr(choice, "message", None)
        entry: dict[str, Any] = {
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
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason is not None:
            entry["finish_reason"] = finish_reason
        choices.append(entry)
    result: dict[str, Any] = {"choices": choices}
    usage_dict = _usage_to_dict(getattr(response, "usage", None))
    if usage_dict is not None:
        result["usage"] = usage_dict
    return result


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
        # Resolved once at construction time (not re-checked per call): which
        # cache-key algorithm this instance uses, per the dispatch rule in
        # _resolve_key_version's docstring. A recorder is constructed fresh
        # per fixtures_dir/run, so a `_meta.json` written mid-run (e.g. by a
        # sibling recorder) is not expected to change an already-live instance.
        self._key_version: int = _resolve_key_version(self.fixtures_dir, self.mode)

    def reset(self) -> None:
        """Clear cumulative state (``cache_hits``, ``cache_misses``, ``last_error``)."""
        self.cache_hits = 0
        self.cache_misses = 0
        self.last_error = None

    async def __call__(self, *, model: str, messages: Sequence[Any], **kwargs: Any) -> Any:
        msgs = list(messages)
        key = (
            _stable_key_v2(model, msgs, **kwargs)
            if self._key_version >= 2
            else _stable_key_v1(model, msgs)
        )
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
        # Extra kwargs (notably ``tools=`` from LLMPlanner) are always
        # forwarded to the provider; whether they ALSO enter the cache key
        # depends on this instance's resolved format version (v1: no; v2:
        # yes for the identity-relevant subset — see ``_stable_key_v2``).
        import litellm

        real = await litellm.acompletion(model=model, messages=list(messages), **kwargs)
        serialised = json.dumps(_dictify_response(real), indent=2, sort_keys=True) + "\n"
        if not isinstance(path, Path):
            # __post_init__ enforces a real Path in record mode (mkdir/write are
            # Path-only), so this should be unreachable — but never trust that an
            # invariant established elsewhere still holds at a write call site.
            raise TypeError(f"record mode requires a real pathlib.Path, got {type(path).__name__}")
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
