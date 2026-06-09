"""LiteLLMRecorder smoke tests — closes G4 (eng review)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.integration._recorder import (
    LiteLLMRecorder,
    MissingFixtureError,
    ScriptedLLM,
    _stable_key,
)


def test_stable_key_is_deterministic() -> None:
    msgs = [{"role": "user", "content": "hi"}]
    assert _stable_key("m", msgs) == _stable_key("m", msgs)


def test_stable_key_differs_on_different_messages() -> None:
    a = _stable_key("m", [{"role": "user", "content": "hi"}])
    b = _stable_key("m", [{"role": "user", "content": "bye"}])
    assert a != b


@pytest.mark.asyncio
async def test_replay_raises_on_cache_miss(tmp_path: Path) -> None:
    """G4: replay mode with no fixture must raise MissingFixtureError."""
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")
    with pytest.raises(MissingFixtureError):
        await recorder(model="claude-x", messages=[{"role": "user", "content": "hi"}])
    assert recorder.cache_misses == 1


@pytest.mark.asyncio
async def test_replay_returns_fixture(tmp_path: Path) -> None:
    msgs = [{"role": "user", "content": "hi"}]
    key = _stable_key("claude-x", msgs)
    (tmp_path / f"{key}.json").write_text(
        json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": "hello",
                            "tool_calls": [],
                        }
                    }
                ]
            }
        )
    )
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")
    response = await recorder(model="claude-x", messages=msgs)
    assert response.choices[0].message.content == "hello"
    assert recorder.cache_hits == 1


@pytest.mark.asyncio
async def test_scripted_llm_returns_responses_in_order() -> None:
    stub = ScriptedLLM(responses=["a", "b", "c"])
    assert await stub() == "a"
    assert await stub() == "b"
    assert await stub() == "c"


@pytest.mark.asyncio
async def test_scripted_llm_runs_out_of_responses_loudly() -> None:
    stub = ScriptedLLM(responses=[])
    with pytest.raises(RuntimeError, match="out of responses"):
        await stub()


@pytest.mark.asyncio
async def test_scripted_llm_raises_when_response_is_exception() -> None:
    stub = ScriptedLLM(responses=[RuntimeError("simulated")])
    with pytest.raises(RuntimeError, match="simulated"):
        await stub()
