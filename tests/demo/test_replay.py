"""Tests for the promoted LiteLLM record/replay core (PR A, Task A1).

The core moved from ``tests/integration/_recorder.py`` to
``mylonite.demo._replay`` so recorded real-LLM fixtures can ship inside the
wheel. Hashing behaviour must stay identical; these tests cover the new
behaviours added during promotion:

* parameterised ``MissingFixtureError`` hint (demo default names the
  re-record script),
* corrupt-fixture JSON wrapped in ``CorruptFixtureError`` (never a bare
  ``JSONDecodeError``),
* record mode forwards extra kwargs (``tools=``) to ``litellm.acompletion``,
* ``fixtures_dir`` accepts an ``importlib.resources`` Traversable in replay
  mode (record mode requires a real ``Path``),
* record mode refuses to silently overwrite an existing key with different
  content,
* ``last_error`` exposes the most recent failure for runner-side inspection.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.demo._replay import (
    CorruptFixtureError,
    FixtureConflictError,
    LiteLLMRecorder,
    MissingFixtureError,
    _stable_key,
    packaged_fixture_dir,
)

_MSGS = [{"role": "user", "content": "hi"}]


def _fixture_payload(content: str = "hello") -> str:
    return json.dumps({"choices": [{"message": {"content": content, "tool_calls": []}}]})


def _write_fixture(
    directory: Path,
    model: str,
    msgs: list[Any],
    content: str = "hello",
) -> Path:
    key = _stable_key(model, msgs)
    path = directory / f"{key}.json"
    path.write_text(_fixture_payload(content), encoding="utf-8")
    return path


def _fake_response(content: str = "ok") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=None))]
    )


# --- (1) replay hit ----------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_hit_returns_fixture_shaped_response(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "claude-x", _MSGS)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path)
    response = await recorder(model="claude-x", messages=_MSGS)
    assert response.choices[0].message.content == "hello"
    assert response.choices[0].message.tool_calls is None
    assert recorder.cache_hits == 1
    assert recorder.cache_misses == 0
    assert recorder.last_error is None


# --- (2) replay miss names the demo re-record script ---------------------------


@pytest.mark.asyncio
async def test_replay_miss_raises_missing_fixture_error_naming_rerecord_script(
    tmp_path: Path,
) -> None:
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path)
    with pytest.raises(MissingFixtureError) as excinfo:
        await recorder(model="claude-x", messages=_MSGS)
    assert "scripts/record_demo_fixtures.py" in str(excinfo.value)
    assert recorder.cache_misses == 1
    assert recorder.last_error is excinfo.value


@pytest.mark.asyncio
async def test_missing_fixture_hint_is_parameterised_per_construction_site(
    tmp_path: Path,
) -> None:
    recorder = LiteLLMRecorder(
        fixtures_dir=tmp_path,
        missing_fixture_hint="Re-run with MYLONITE_TEST_RECORD=1 to capture.",
    )
    with pytest.raises(MissingFixtureError, match="MYLONITE_TEST_RECORD=1"):
        await recorder(model="claude-x", messages=_MSGS)


# --- (3) corrupt fixture is wrapped, never a bare JSONDecodeError --------------


@pytest.mark.asyncio
async def test_corrupt_fixture_raises_wrapped_error_not_jsondecodeerror(
    tmp_path: Path,
) -> None:
    key = _stable_key("claude-x", _MSGS)
    (tmp_path / f"{key}.json").write_text("{not valid json", encoding="utf-8")
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path)
    with pytest.raises(CorruptFixtureError) as excinfo:
        await recorder(model="claude-x", messages=_MSGS)
    assert "fixture corrupt — reinstall mylonite or re-record" in str(excinfo.value)
    assert not isinstance(excinfo.value, json.JSONDecodeError)
    assert isinstance(excinfo.value.__cause__, json.JSONDecodeError)
    assert recorder.last_error is excinfo.value
    assert recorder.cache_hits == 0


# --- (4) record mode forwards tools= to the underlying call --------------------


@pytest.mark.asyncio
async def test_record_mode_forwards_tools_kwarg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_acompletion(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return _fake_response("ok")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    tools = [{"type": "function", "function": {"name": "read_note", "parameters": {}}}]
    response = await recorder(model="claude-x", messages=_MSGS, tools=tools)
    assert captured["tools"] == tools
    assert captured["model"] == "claude-x"
    assert response.choices[0].message.content == "ok"
    key = _stable_key("claude-x", _MSGS)
    written = json.loads((tmp_path / f"{key}.json").read_text(encoding="utf-8"))
    assert written["choices"][0]["message"]["content"] == "ok"


# --- record mode never silently overwrites -------------------------------------


@pytest.mark.asyncio
async def test_record_mode_refuses_to_overwrite_conflicting_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path, "claude-x", _MSGS, content="previous")

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("different")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    with pytest.raises(FixtureConflictError) as excinfo:
        await recorder(model="claude-x", messages=_MSGS)
    assert recorder.last_error is excinfo.value
    # The original fixture must be untouched.
    key = _stable_key("claude-x", _MSGS)
    existing = json.loads((tmp_path / f"{key}.json").read_text(encoding="utf-8"))
    assert existing["choices"][0]["message"]["content"] == "previous"


@pytest.mark.asyncio
async def test_record_mode_is_idempotent_for_identical_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("same")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    await recorder(model="claude-x", messages=_MSGS)
    # Re-recording the same key with byte-identical content must not raise.
    await recorder(model="claude-x", messages=_MSGS)


# --- (5) Traversable fixtures_dir ----------------------------------------------


@pytest.mark.asyncio
async def test_fixtures_dir_accepts_importlib_resources_traversable(tmp_path: Path) -> None:
    key = _stable_key("claude-x", _MSGS)
    archive = tmp_path / "fixtures.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(f"fixtures/{key}.json", _fixture_payload())
    root = zipfile.Path(archive) / "fixtures"  # a Traversable, not a pathlib.Path
    recorder = LiteLLMRecorder(fixtures_dir=root)
    response = await recorder(model="claude-x", messages=_MSGS)
    assert response.choices[0].message.content == "hello"
    assert recorder.cache_hits == 1


def test_record_mode_rejects_traversable_fixtures_dir(tmp_path: Path) -> None:
    archive = tmp_path / "fixtures.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("fixtures/.keep", "")
    root = zipfile.Path(archive) / "fixtures"
    with pytest.raises(TypeError, match="record mode requires a real"):
        LiteLLMRecorder(fixtures_dir=root, mode="record")


def test_packaged_fixture_dir_points_at_demo_package() -> None:
    root = packaged_fixture_dir()
    assert root.name == "fixtures"
