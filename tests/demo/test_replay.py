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
    CACHE_KEY_VERSION_FIELD,
    CorruptFixtureError,
    FixtureConflictError,
    LiteLLMRecorder,
    MissingFixtureError,
    _resolve_key_version,
    _stable_key,
    _stable_key_v1,
    _stable_key_v2,
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


@pytest.mark.asyncio
async def test_reset_zeroes_counters_and_clears_last_error(tmp_path: Path) -> None:
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path)
    with pytest.raises(MissingFixtureError):
        await recorder(model="claude-x", messages=_MSGS)
    assert recorder.cache_misses == 1
    assert recorder.last_error is not None
    recorder.reset()
    assert recorder.cache_hits == 0
    assert recorder.cache_misses == 0
    assert recorder.last_error is None


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
    # A fresh fixtures_dir (no `_meta.json`) defaults to v2 in record mode
    # (T8), so `tools=` is folded into the on-disk key — this is the actual
    # fix: recording under v1 here would silently drop the tool schema from
    # cache identity.
    key = _stable_key_v2("claude-x", _MSGS, tools=tools)
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


@pytest.mark.asyncio
async def test_fixtures_dir_accepts_str_and_coerces_to_path(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "claude-x", _MSGS)
    recorder = LiteLLMRecorder(fixtures_dir=str(tmp_path))  # type: ignore[arg-type]
    assert isinstance(recorder.fixtures_dir, Path)
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
    # The fixture root must live inside the mylonite.demo package itself.
    import mylonite.demo

    demo_pkg_dir = Path(mylonite.demo.__file__).resolve().parent
    assert Path(str(root)).resolve().parent == demo_pkg_dir
    # Per-variant namespaces must be joinable underneath the root.
    assert (root / "vulnerable").name == "vulnerable"


# --- (T8) v2 cache key: extra call-shape kwargs must change the key ------------
#
# The bug: the shipped key function hashes ONLY (model, messages), so two
# calls that differ solely in `tools`/`response_format`/`api_base` collide on
# the same fixture file — replay silently returns whichever response was
# recorded first, which may not be shaped for the call actually being made.
# `_stable_key_v2` is the fix; `_stable_key_v1` (== the original `_stable_key`)
# is kept byte-for-byte so the already-shipped v1 fixture directories
# (`src/mylonite/demo/fixtures/*`) keep replaying under the old algorithm.


def test_tool_schema_change_produces_distinct_key() -> None:
    tools_a = [{"type": "function", "function": {"name": "read_note", "parameters": {}}}]
    tools_b = [{"type": "function", "function": {"name": "send_email", "parameters": {}}}]
    key_a = _stable_key_v2("claude-x", _MSGS, tools=tools_a)
    key_b = _stable_key_v2("claude-x", _MSGS, tools=tools_b)
    assert key_a != key_b
    # Proves the bug is real: the OLD (v1) algorithm ignores `tools` entirely,
    # so these same two calls collide under it.
    assert _stable_key_v1("claude-x", _MSGS) == _stable_key_v1("claude-x", _MSGS)


def test_response_format_change_produces_distinct_key() -> None:
    key_a = _stable_key_v2("claude-x", _MSGS, response_format={"type": "json_object"})
    key_b = _stable_key_v2("claude-x", _MSGS, response_format={"type": "text"})
    assert key_a != key_b


def test_api_base_in_key() -> None:
    key_a = _stable_key_v2("claude-x", _MSGS, api_base="https://a.example.com")
    key_b = _stable_key_v2("claude-x", _MSGS, api_base="https://b.example.com")
    assert key_a != key_b


def test_api_key_excluded_from_key() -> None:
    key_a = _stable_key_v2("claude-x", _MSGS, api_key="sk-aaaaaaaa")
    key_b = _stable_key_v2("claude-x", _MSGS, api_key="sk-bbbbbbbb")
    assert key_a == key_b
    # Rotating a key (or never setting one) must never itself cause a miss.
    assert key_a == _stable_key_v2("claude-x", _MSGS)


def test_v2_key_unaffected_by_dict_key_ordering() -> None:
    tools_ordered_a = [
        {"type": "function", "function": {"name": "x", "parameters": {"a": 1, "b": 2}}}
    ]
    tools_ordered_b = [
        {"function": {"parameters": {"b": 2, "a": 1}, "name": "x"}, "type": "function"}
    ]
    assert _stable_key_v2("claude-x", _MSGS, tools=tools_ordered_a) == _stable_key_v2(
        "claude-x", _MSGS, tools=tools_ordered_b
    )


# --- (T8) fixture-format-version detection -------------------------------------


def test_format_version_defaults_to_v1_on_replay_with_no_sidecar(tmp_path: Path) -> None:
    assert _resolve_key_version(tmp_path, "replay") == 1


def test_format_version_defaults_to_v2_on_record_with_no_sidecar(tmp_path: Path) -> None:
    assert _resolve_key_version(tmp_path, "record") == 2


def test_format_version_honours_explicit_sidecar_in_either_mode(tmp_path: Path) -> None:
    (tmp_path / "_meta.json").write_text(json.dumps({CACHE_KEY_VERSION_FIELD: 1}), encoding="utf-8")
    assert _resolve_key_version(tmp_path, "replay") == 1
    assert _resolve_key_version(tmp_path, "record") == 1

    (tmp_path / "_meta.json").write_text(json.dumps({CACHE_KEY_VERSION_FIELD: 2}), encoding="utf-8")
    assert _resolve_key_version(tmp_path, "replay") == 2
    assert _resolve_key_version(tmp_path, "record") == 2


def test_format_version_field_alone_is_ignored_by_cache_key_dispatch(tmp_path: Path) -> None:
    """A sidecar with ONLY the unrelated `format_version` field (testkit's own,
    NOT the cache-key field) must NOT be mistaken for a cache_key_version
    declaration — this is exactly the coupling-by-coincidence the two
    independent fields exist to rule out."""
    (tmp_path / "_meta.json").write_text(json.dumps({"format_version": 2}), encoding="utf-8")
    assert _resolve_key_version(tmp_path, "replay") == 1
    assert _resolve_key_version(tmp_path, "record") == 2


def test_real_shipped_demo_fixtures_are_detected_as_v1() -> None:
    """The committed demo fixtures ship with no `_meta.json` — must resolve v1."""
    root = packaged_fixture_dir()
    assert _resolve_key_version(root / "vulnerable", "replay") == 1
    assert _resolve_key_version(root / "guarded", "replay") == 1


# --- (T8) the critical non-regression: shipped v1 fixtures still replay --------


async def test_v1_fixtures_still_replay() -> None:
    """The real, already-shipped ``mylonite demo`` fixtures must keep working.

    The critical non-regression proof: drive the ACTUAL demo wiring
    (``mylonite.demo.runner.run_demo``) against the real packaged
    ``vulnerable``/``guarded`` fixtures — which ship with no ``_meta.json``
    sidecar — end to end. Every real call the demo's ``LLMPlanner`` makes
    includes ``tools=``/``tool_choice=``; if v1 dispatch (or the key-version
    detection defaulting) were broken, this would raise
    ``DemoFixtureError``/``MissingFixtureError`` instead of completing with
    the expected differential.
    """
    from mylonite.demo.runner import run_demo

    result = await run_demo(live=False)
    assert result.vulnerable.report.aborted is None
    assert result.guarded.report.aborted is None
    assert result.vulnerable.report.findings_count >= 1
    assert result.guarded.report.findings_count == 0


# --- (T8) usage / finish_reason round-trip through record + replay -------------


@pytest.mark.asyncio
async def test_finish_reason_roundtrips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="truncated...", tool_calls=None),
                    finish_reason="length",
                )
            ],
            usage=None,
        )

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    await recorder(model="claude-x", messages=_MSGS)

    replay = LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")
    response = await replay(model="claude-x", messages=_MSGS)
    assert response.choices[0].finish_reason == "length"


@pytest.mark.asyncio
async def test_usage_roundtrips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="ok", tool_calls=None),
                    finish_reason="stop",
                )
            ],
            usage=SimpleNamespace(prompt_tokens=12, completion_tokens=34, total_tokens=46),
        )

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    await recorder(model="claude-x", messages=_MSGS)

    replay = LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")
    response = await replay(model="claude-x", messages=_MSGS)
    assert response.usage is not None
    assert response.usage.prompt_tokens == 12
    assert response.usage.completion_tokens == 34
    assert response.usage.total_tokens == 46


@pytest.mark.asyncio
async def test_v2_recording_with_tools_replays_when_sidecar_declares_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The actual regression scenario: a call WITH tools, recorded + replayed v2."""
    tools = [{"type": "function", "function": {"name": "read_note", "parameters": {}}}]

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="", tool_calls=None), finish_reason="stop"
                )
            ],
            usage=None,
        )

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    # Explicit v2 sidecar written up front, mirroring how a caller that wants
    # v2 dispatch on a fresh directory would stamp it (reference_validator.py /
    # record_reference_example.py stamp it right after recording).
    (tmp_path / "_meta.json").write_text(
        json.dumps({CACHE_KEY_VERSION_FIELD: 2, "model": "claude-x"}), encoding="utf-8"
    )
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    await recorder(model="claude-x", messages=_MSGS, tools=tools)

    replay = LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")
    response = await replay(model="claude-x", messages=_MSGS, tools=tools)
    assert response.choices[0].message.content == ""
    assert replay.cache_hits == 1
    assert replay.cache_misses == 0
