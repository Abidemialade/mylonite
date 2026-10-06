"""Tests for the promoted LiteLLM record/replay core (PR A, Task A1).

The core moved from ``tests/integration/_recorder.py`` to
``mylonite._replay`` (originally ``mylonite.demo._replay``, relocated when
the ``demo`` on-ramp was removed) so recorded real-LLM fixtures can ship
inside the wheel. Hashing behaviour must stay identical; these tests cover
the new behaviours added during promotion:

* parameterised ``MissingFixtureError`` hint (each construction site names
  its own re-record procedure),
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

from mylonite._replay import (
    CACHE_KEY_VERSION,
    CACHE_KEY_VERSION_FIELD,
    FIXTURE_NAME_LENGTH,
    CorruptFixtureError,
    FixtureConflictError,
    FixtureVersionError,
    LiteLLMRecorder,
    MissingFixtureError,
    _resolve_key_version,
    _stable_key,
    _stable_key_v1,
    _stable_key_v2,
    _stable_key_v3,
)

_MSGS = [{"role": "user", "content": "hi"}]


def _fixture_payload(content: str = "hello") -> str:
    return json.dumps({"choices": [{"message": {"content": content, "tool_calls": []}}]})


def _stamped(directory: Path, version: int = CACHE_KEY_VERSION) -> Path:
    """Write the ``_meta.json`` sidecar a recorder needs once ``directory``
    holds recordings (unless one is already there); return ``directory``."""
    meta = directory / "_meta.json"
    if not meta.is_file():
        meta.write_text(json.dumps({CACHE_KEY_VERSION_FIELD: version}), encoding="utf-8")
    return directory


def _write_fixture(
    directory: Path,
    model: str,
    msgs: list[Any],
    content: str = "hello",
) -> Path:
    _stamped(directory)
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
    recorder = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path))
    response = await recorder(model="claude-x", messages=_MSGS)
    assert response.choices[0].message.content == "hello"
    assert response.choices[0].message.tool_calls is None
    assert recorder.cache_hits == 1
    assert recorder.cache_misses == 0
    assert recorder.last_error is None


# --- (2) replay miss names the construction site's re-record hint --------------


@pytest.mark.asyncio
async def test_replay_miss_raises_missing_fixture_error_naming_rerecord_hint(
    tmp_path: Path,
) -> None:
    recorder = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path))
    with pytest.raises(MissingFixtureError) as excinfo:
        await recorder(model="claude-x", messages=_MSGS)
    assert "Re-record this fixture set" in str(excinfo.value)
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
    recorder = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path))
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
    _stamped(tmp_path)
    (tmp_path / f"{key}.json").write_text("{not valid json", encoding="utf-8")
    recorder = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path))
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
    written = json.loads(
        (tmp_path / f"{key[:FIXTURE_NAME_LENGTH]}.json").read_text(encoding="utf-8")
    )
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
        zf.writestr("fixtures/_meta.json", json.dumps({CACHE_KEY_VERSION_FIELD: CACHE_KEY_VERSION}))
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


# --- (T8) v2 cache key: extra call-shape kwargs must change the key ------------
#
# The bug: the shipped key function hashes ONLY (model, messages), so two
# calls that differ solely in `tools`/`response_format`/`api_base` collide on
# the same fixture file — replay silently returns whichever response was
# recorded first, which may not be shaped for the call actually being made.
# `_stable_key_v2` is the fix; `_stable_key_v1` (== the original `_stable_key`)
# is kept byte-for-byte so any fixture directory recorded under it keeps
# replaying under the old algorithm.


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
#
# (close-the-loop) The old fallback was mode-dependent: a sidecar-less
# directory silently defaulted to v1 on REPLAY, v2 on RECORD. That asymmetry
# existed only to keep pre-sidecar fixture directories recorded under v1
# replaying; a directory that still needs v1 now declares
# `cache_key_version: 1` EXPLICITLY (see
# `test_format_version_honours_explicit_sidecar_in_either_mode` below), so the
# no-sidecar default is unified to `CACHE_KEY_VERSION` in EITHER mode — see
# `test_no_sidecar_defaults_to_cache_key_version_in_either_mode`.


def test_no_sidecar_defaults_to_cache_key_version_in_either_mode(tmp_path: Path) -> None:
    """The retired fallback: no more implicit "assume legacy v1" on replay.

    A sidecar-less directory now resolves the SAME default — the best
    available algorithm — whichever mode asks. Only a directory that
    explicitly declares an older version (see
    ``test_format_version_honours_explicit_sidecar_in_either_mode`` below)
    still resolves to it.
    """
    assert _resolve_key_version(tmp_path, "replay") == CACHE_KEY_VERSION == 3
    assert _resolve_key_version(tmp_path, "record") == CACHE_KEY_VERSION


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
    independent fields exist to rule out. With no cache_key_version signal,
    both modes fall through to the same unified no-sidecar default."""
    (tmp_path / "_meta.json").write_text(json.dumps({"format_version": 2}), encoding="utf-8")
    assert _resolve_key_version(tmp_path, "replay") == CACHE_KEY_VERSION
    assert _resolve_key_version(tmp_path, "record") == CACHE_KEY_VERSION


# --- (close-the-loop) proof the implicit v1 fallback is actually gone ---------


@pytest.mark.parametrize("mode", ["record", "replay"])
def test_a_sidecar_less_dir_holding_recordings_is_refused(tmp_path: Path, mode: str) -> None:
    """No sidecar, but recordings present: Mylonite cannot tell how they were
    keyed, so it refuses rather than guess (an old guess was v1, then the
    current default; either can return a stale reply or miss silently)."""
    v1_key = _stable_key_v1("claude-x", _MSGS)
    (tmp_path / f"{v1_key}.json").write_text(
        _fixture_payload("stale-v1-response"), encoding="utf-8"
    )
    with pytest.raises(FixtureVersionError, match="declares no cache_key_version"):
        LiteLLMRecorder(fixtures_dir=tmp_path, mode=mode)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("sidecar", "match"),
    [
        ("{not json", "not valid JSON"),
        ("[3]", "not a JSON object"),
        ('{"cache_key_version": "3"}', "not an integer"),
        ('{"cache_key_version": true}', "not an integer"),
    ],
)
def test_a_damaged_sidecar_is_refused(tmp_path: Path, sidecar: str, match: str) -> None:
    (tmp_path / "_meta.json").write_text(sidecar, encoding="utf-8")
    with pytest.raises(FixtureVersionError, match=match):
        LiteLLMRecorder(fixtures_dir=tmp_path, mode="replay")


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

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
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

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    response = await replay(model="claude-x", messages=_MSGS)
    assert response.usage is not None
    assert response.usage.prompt_tokens == 12
    assert response.usage.completion_tokens == 34
    assert response.usage.total_tokens == 46


@pytest.mark.asyncio
async def test_v2_recording_with_tools_replays_when_sidecar_declares_v2(tmp_path: Path) -> None:
    """A directory recorded under v2 (before redaction) still replays with v2,
    tools included. Record mode no longer writes v2 (see the refusal test)."""
    tools = [{"type": "function", "function": {"name": "read_note", "parameters": {}}}]
    (tmp_path / "_meta.json").write_text(
        json.dumps({CACHE_KEY_VERSION_FIELD: 2, "model": "claude-x"}), encoding="utf-8"
    )
    key = _stable_key_v2("claude-x", _MSGS, tools=tools)
    (tmp_path / f"{key}.json").write_text(_fixture_payload(""), encoding="utf-8")

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    assert replay.key_version == 2
    response = await replay(model="claude-x", messages=_MSGS, tools=tools)
    assert response.choices[0].message.content == ""
    assert replay.cache_hits == 1
    assert replay.cache_misses == 0


# --- short fixture file names ------------------------------------------------
#
# A recorded fixture is named after the first FIXTURE_NAME_LENGTH hex digits of
# its key, not all 64, so a committed gate directory fits under Windows' path
# limit from a deeper checkout. Directories recorded before keep their full
# names and still replay.


@pytest.mark.asyncio
async def test_record_mode_writes_the_short_fixture_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("ok")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    await recorder(model="claude-x", messages=_MSGS)

    key = _stable_key_v2("claude-x", _MSGS)
    assert [p.name for p in tmp_path.glob("*.json")] == [f"{key[:FIXTURE_NAME_LENGTH]}.json"]
    assert FIXTURE_NAME_LENGTH == 12


@pytest.mark.asyncio
async def test_replay_reads_a_short_fixture_name(tmp_path: Path) -> None:
    key = _stable_key_v2("claude-x", _MSGS)
    (tmp_path / f"{key[:FIXTURE_NAME_LENGTH]}.json").write_text(
        _fixture_payload("short"), encoding="utf-8"
    )
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    response = await replay(model="claude-x", messages=_MSGS)
    assert response.choices[0].message.content == "short"
    assert replay.cache_hits == 1


@pytest.mark.asyncio
async def test_replay_still_reads_a_full_length_fixture_name(tmp_path: Path) -> None:
    _write_fixture(tmp_path, "claude-x", _MSGS, content="legacy")
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    response = await replay(model="claude-x", messages=_MSGS)
    assert response.choices[0].message.content == "legacy"
    assert replay.cache_hits == 1


@pytest.mark.asyncio
async def test_record_into_a_full_length_directory_keeps_the_full_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("same")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    await LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")(model="claude-x", messages=_MSGS)
    # Turn the recording into one made before short names existed.
    # Those were named by the full key and carried no `_key` field.
    key = _stable_key_v2("claude-x", _MSGS)
    short = tmp_path / f"{key[:FIXTURE_NAME_LENGTH]}.json"
    data = json.loads(short.read_text(encoding="utf-8"))
    assert data.pop("_key") == key
    (tmp_path / f"{key}.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    short.unlink()

    await LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="record")(
        model="claude-x", messages=_MSGS
    )
    assert [p.name for p in tmp_path.glob("*.json") if p.name != "_meta.json"] == [f"{key}.json"]


@pytest.mark.asyncio
async def test_missing_fixture_error_names_the_short_path(tmp_path: Path) -> None:
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    with pytest.raises(MissingFixtureError) as excinfo:
        await replay(model="claude-x", messages=_MSGS)
    key = _stable_key_v2("claude-x", _MSGS)
    assert f"{key[:FIXTURE_NAME_LENGTH]}.json" in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_short_name_holding_another_keys_recording_is_a_miss(tmp_path: Path) -> None:
    # Two keys can share the first 12 hex digits. A short-named recording
    # stores its full key, so replay never answers with another call's reply.
    key = _stable_key_v2("claude-x", _MSGS)
    other = json.loads(_fixture_payload("someone else's answer"))
    other["_key"] = key[:FIXTURE_NAME_LENGTH] + "f" * (64 - FIXTURE_NAME_LENGTH)
    (tmp_path / f"{key[:FIXTURE_NAME_LENGTH]}.json").write_text(json.dumps(other), encoding="utf-8")
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    with pytest.raises(MissingFixtureError):
        await replay(model="claude-x", messages=_MSGS)
    assert replay.cache_hits == 0


# --- recorded fixtures are redacted (#273) ------------------------------------
#
# A gate commits its fixtures to the user's repository, and a target can echo a
# live secret into a model reply. Record mode writes the redacted reply; the v3
# key hashes the redacted conversation, so the redacted recording still replays.

# Built at runtime so no secret-shaped literal sits in the source.
_SECRET = "sk-" + "live" + "A1b2C3d4E5f6G7h8I9j0K1L2"  # pragma: allowlist secret


def _tool_call_response(arguments: str, content: str = "") -> SimpleNamespace:
    call = SimpleNamespace(
        id="call_1", function=SimpleNamespace(name="send_email", arguments=arguments)
    )
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content, tool_calls=[call]),
                finish_reason="tool_calls",
            )
        ],
        usage={"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
    )


def _conversation(reply_args: str, tool_result: str) -> list[dict[str, Any]]:
    """Turn two of an agent loop: the user turn, the tool call as the agent
    copies it back, and the target's tool result."""
    return [
        {"role": "user", "content": "summarise my inbox"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "send_email", "arguments": reply_args},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": tool_result},
    ]


@pytest.mark.asyncio
async def test_record_writes_a_secret_in_the_reply_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_args = json.dumps({"to": "x@example.com", "body": f"key is {_SECRET}"})
    live = _tool_call_response(raw_args, content=f"Authorization: Bearer {_SECRET}")

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return live

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    returned = await recorder(model="claude-x", messages=_MSGS)

    # The record-time caller still sees the live reply.
    assert returned is live
    files = [p for p in tmp_path.glob("*.json") if p.name != "_meta.json"]
    assert len(files) == 1
    text = files[0].read_text(encoding="utf-8")
    assert _SECRET not in text
    data = json.loads(text)
    message = data["choices"][0]["message"]
    assert "***REDACTED***" in message["content"]
    assert "***REDACTED***" in message["tool_calls"][0]["function"]["arguments"]
    # Arguments stay valid JSON; other fields and the token counts survive.
    assert json.loads(message["tool_calls"][0]["function"]["arguments"])["to"] == "x@example.com"
    assert data["usage"]["total_tokens"] == 10
    assert data["_key"] == _stable_key_v3("claude-x", _MSGS)


@pytest.mark.asyncio
async def test_a_redacted_multi_turn_recording_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Turn two carries turn one's reply back into the request. At record time
    that reply holds the raw secret; at replay time it holds the redacted one.
    Both must reach the same recording."""
    raw_args = json.dumps({"body": f"key is {_SECRET}"})
    replies = iter([_tool_call_response(raw_args), _fake_response("done")])

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return next(replies)

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    first = await recorder(model="claude-x", messages=_MSGS)
    live_args = first.choices[0].message.tool_calls[0].function.arguments
    # The target echoes what it was sent (here: the raw secret).
    await recorder(model="claude-x", messages=_conversation(live_args, f"sent: {live_args}"))
    for path in tmp_path.glob("*.json"):
        assert _SECRET not in path.read_text(encoding="utf-8")

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    replayed = await replay(model="claude-x", messages=_MSGS)
    replayed_args = replayed.choices[0].message.tool_calls[0].function.arguments
    assert _SECRET not in replayed_args
    # The same agent, offline: it copies the redacted call back, and the target
    # echoes the redacted value it was sent.
    second = await replay(
        model="claude-x", messages=_conversation(replayed_args, f"sent: {replayed_args}")
    )
    assert second.choices[0].message.content == "done"
    assert replay.cache_hits == 2
    assert replay.cache_misses == 0


def test_v3_key_matches_v2_when_nothing_is_secret_shaped() -> None:
    tools = [{"type": "function", "function": {"name": "read_note", "parameters": {}}}]
    assert _stable_key_v3("claude-x", _MSGS, tools=tools) == _stable_key_v2(
        "claude-x", _MSGS, tools=tools
    )
    secret_msgs = [{"role": "user", "content": f"use {_SECRET}"}]
    assert _stable_key_v3("claude-x", secret_msgs) != _stable_key_v2("claude-x", secret_msgs)


@pytest.mark.parametrize("old", [1, 2])
def test_record_refuses_a_directory_of_an_older_cache_key_version(tmp_path: Path, old: int) -> None:
    (tmp_path / "_meta.json").write_text(
        json.dumps({CACHE_KEY_VERSION_FIELD: old}), encoding="utf-8"
    )
    with pytest.raises(FixtureVersionError, match=f"cache_key_version={old}"):
        LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")


@pytest.mark.parametrize("mode", ["record", "replay"])
def test_an_unknown_cache_key_version_fails_clearly(tmp_path: Path, mode: str) -> None:
    (tmp_path / "_meta.json").write_text(
        json.dumps({CACHE_KEY_VERSION_FIELD: CACHE_KEY_VERSION + 1}), encoding="utf-8"
    )
    with pytest.raises(FixtureVersionError, match="does not support"):
        LiteLLMRecorder(fixtures_dir=tmp_path, mode=mode)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_miss_in_an_older_directory_names_its_version(tmp_path: Path) -> None:
    (tmp_path / "_meta.json").write_text(json.dumps({CACHE_KEY_VERSION_FIELD: 2}), encoding="utf-8")
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    with pytest.raises(MissingFixtureError, match="cache_key_version=2"):
        await replay(model="claude-x", messages=_MSGS)


# --- the v3 key never merges recordings whose real content differs ------------
#
# A guard whose job is to mask a credential in tool output, and the same tool
# with the guard removed, must not share a recording: a shared key would replay
# the guarded reply for the unguarded run and pass a test that should fail.

# Built at runtime so no secret-shaped literal sits in the source.
_OTHER_SECRET = "sk-" + "live" + "Z9y8X7w6V5u4T3s2R1q0P9o8"  # pragma: allowlist secret


def _tool_turn(tool_output: str) -> list[dict[str, Any]]:
    return [
        {"role": "user", "content": "read my config"},
        {"role": "tool", "tool_call_id": "call_1", "content": tool_output},
    ]


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (f"api_key: {_SECRET}", f"api_key: {_OTHER_SECRET}"),
        ("api_key: ***REDACTED***", f"api_key: {_SECRET}"),
        ("password=xxxxxxxxxxxxxxxx", "password=CorrectHorse1234"),  # pragma: allowlist secret
        ("Bearer " + "0" * 24, "Bearer " + "a1" * 12),
        (f"token: {_SECRET}", "token: sk-" + "X" * 30),
    ],
)
def test_tool_outputs_that_differ_inside_a_secret_span_key_differently(
    first: str, second: str
) -> None:
    assert _stable_key_v3("claude-x", _tool_turn(first)) != _stable_key_v3(
        "claude-x", _tool_turn(second)
    )


@pytest.mark.asyncio
async def test_a_recording_never_answers_for_a_different_secret_in_tool_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("guarded reply")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    guarded = _tool_turn("api_key: ***REDACTED***")
    leaked = _tool_turn(f"api_key: {_SECRET}")
    await LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")(model="claude-x", messages=guarded)

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    assert (await replay(model="claude-x", messages=guarded)).choices[0].message.content == (
        "guarded reply"
    )
    with pytest.raises(MissingFixtureError):
        await replay(model="claude-x", messages=leaked)


@pytest.mark.asyncio
async def test_a_target_secret_in_tool_output_replays_and_is_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same secret in the same tool output (the target is deterministic)
    replays, and neither the file name, the stored key nor the body is a fast
    hash of it or holds it."""

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return _fake_response("ok")

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    messages = _tool_turn(f"api_key: {_SECRET}")
    await LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")(model="claude-x", messages=messages)
    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    assert (await replay(model="claude-x", messages=messages)).choices[0].message.content == "ok"

    import hashlib

    fast = hashlib.sha256(_SECRET.encode()).hexdigest()
    for path in tmp_path.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert _SECRET not in text
        assert fast[:FIXTURE_NAME_LENGTH] not in path.name + text


def test_a_secret_span_enters_the_key_only_through_scrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brute-forcing a span from the stored key costs one scrypt per guess."""
    import hashlib

    from mylonite import _replay

    calls: list[dict[str, Any]] = []
    real = hashlib.scrypt

    def spy(password: bytes, **kwargs: Any) -> bytes:
        calls.append(kwargs)
        return real(password, **kwargs)

    monkeypatch.setattr(_replay.hashlib, "scrypt", spy)
    _replay._span_digest.cache_clear()
    _stable_key_v3("claude-x", _tool_turn(f"api_key: {_OTHER_SECRET}"))
    assert calls
    assert calls[0]["n"] >= 2**15
    assert calls[0]["r"] >= 8
    _stable_key_v3("claude-x", _MSGS)  # nothing secret-shaped: no scrypt at all
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_key_name_only_secret_echoed_back_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool-call argument masked only because of its key name (``password``)
    and echoed by the target without that key still replays: the echo of a
    reply span is keyed as the redacted echo."""
    password = "Correct" + "Horse" + "Battery9"  # pragma: allowlist secret
    raw_args = json.dumps({"password": password})
    replies = iter([_tool_call_response(raw_args), _fake_response("done")])

    async def fake_acompletion(**_: Any) -> SimpleNamespace:
        return next(replies)

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    recorder = LiteLLMRecorder(fixtures_dir=tmp_path, mode="record")
    first = await recorder(model="claude-x", messages=_MSGS)
    live_args = first.choices[0].message.tool_calls[0].function.arguments
    sent = json.loads(live_args)["password"]
    await recorder(model="claude-x", messages=_conversation(live_args, f"logged in as {sent}"))
    for path in tmp_path.glob("*.json"):
        assert password not in path.read_text(encoding="utf-8")

    replay = LiteLLMRecorder(fixtures_dir=_stamped(tmp_path), mode="replay")
    replayed = await replay(model="claude-x", messages=_MSGS)
    replayed_args = replayed.choices[0].message.tool_calls[0].function.arguments
    sent = json.loads(replayed_args)["password"]
    second = await replay(
        model="claude-x", messages=_conversation(replayed_args, f"logged in as {sent}")
    )
    assert second.choices[0].message.content == "done"
    assert replay.cache_misses == 0
