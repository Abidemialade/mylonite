"""Removal confirmation: a W4 delete reaches effect-confirmed only on proof.

A fake name-keyed store stands in for a third-party server (a Redis-style key
store or a knowledge graph). The W4 payload is the real ``action_task`` text,
so the record Mylonite plants is the one that text already names. Every case
but the happy path must leave ``removal_confirmed`` short of ``"true"``, and
nothing here may ever read as resisted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool
from pydantic import ValidationError

from mylonite.contracts import Payload, ToolSpec
from mylonite.plugins._mcp import calibration, removal_probe, stdio_adapter, target_registry
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
from mylonite.plugins._mcp.target_registry import (
    ControlConfig,
    EffectProbeSpec,
    RemovalProbeSpec,
)
from mylonite.scan.effect_verdict import EffectEvidence, decide
from mylonite.scan.probe_task import action_task

FAMILY = "removal-app"
RECORD = "quarterly summary"

_STR = {"type": "string"}
_SCHEMAS: dict[str, dict[str, Any]] = {
    "create_record": {
        "type": "object",
        "properties": {"name": _STR, "content": _STR},
        "required": ["name", "content"],
    },
    "delete_records": {
        "type": "object",
        "properties": {"names": {"type": "array", "items": _STR}},
        "required": ["names"],
    },
    "delete_item": {"type": "object", "properties": {"key": _STR}, "required": ["key"]},
    "delete_by_id": {
        "type": "object",
        "properties": {"id": {"type": "integer"}},
        "required": ["id"],
    },
    "rename_record": {
        "type": "object",
        "properties": {"old": _STR, "new": _STR},
        "required": ["old", "new"],
    },
    "get_record": {"type": "object", "properties": {"key": _STR}, "required": ["key"]},
}


def _text(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


class _Store:
    """A name-keyed store that outlives one launch."""

    def __init__(self, records: dict[str, str] | None = None) -> None:
        self.records: dict[str, str] = dict(records or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []
        #: Reads of a key, by phase: once ``after_delete`` is set, reads of
        #: these keys answer with this mode ("error", "empty").
        self.after_delete_read: dict[str, str] = {}
        self.deleted = False
        self.plant_error = False
        self.drop_plants = False
        self.delete_reply = "deleted"
        self.delete_is_error = False
        self.wipe_on_delete = False
        #: How a missing key reads: "echo" ("Key <k> does not exist") or "json".
        self.not_found = "echo"
        #: A flapping backend: once a delete was called, a read of the named
        #: record or of any missing key answers with soft-error text that
        #: echoes the key, without ``isError``.
        self.flap_after_delete = False
        #: The delete replies but removes nothing.
        self.delete_noop = False
        #: Once a delete was called, the fixed probe's own key flaps to
        #: soft-error text without ``isError``.
        self.flap_probe_key = False


class _Session:
    def __init__(self, store: _Store) -> None:
        self.store = store

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[
                MCPTool(name=name, description=name, inputSchema=schema)
                for name, schema in _SCHEMAS.items()
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        store = self.store
        store.calls.append((name, dict(arguments)))
        if name == "create_record":
            if store.plant_error:
                return _text("store is read-only", is_error=True)
            if not store.drop_plants:
                store.records[str(arguments["name"])] = str(arguments["content"])
            return _text("stored")
        if name == "get_record":
            key = str(arguments.get("key", ""))
            mode = store.after_delete_read.get(key) if store.deleted else None
            if mode == "error":
                return _text("backend unavailable", is_error=True)
            if mode == "empty":
                return CallToolResult(content=[], isError=False)
            if (
                store.flap_after_delete
                and store.deleted
                # The fixed probe's own key is left alone, so only the
                # removal check's reads flap.
                and (key == RECORD or (key not in store.records and key.startswith("myl-")))
            ):
                return _text(f"Error retrieving value from key {key}")
            if store.flap_probe_key and store.deleted and key == "mylonite-tpv-seed":
                return _text(f"Error retrieving value from key {key}")
            if key in store.records:
                return _text(f"{key}: {store.records[key]}")
            if store.not_found == "json":
                return _text(json.dumps({"entities": [], "relations": []}))
            return _text(f"Key {key} does not exist")
        if name in ("delete_records", "delete_item"):
            keys = arguments.get("names") or [arguments.get("key")]
            store.deleted = True
            if store.delete_noop:
                pass
            elif store.wipe_on_delete:
                store.records.clear()
            else:
                for key in keys:
                    store.records.pop(str(key), None)
            return _text(store.delete_reply, is_error=store.delete_is_error)
        if name == "rename_record":
            old, new = str(arguments["old"]), str(arguments["new"])
            if old in store.records:
                store.records[new] = store.records.pop(old)
            return _text("renamed")
        return _text(f"{name} ok")


def _launcher(store: _Store) -> Any:
    def _open(*args: Any, **kwargs: Any) -> Any:
        @asynccontextmanager
        async def _ctx() -> Any:
            yield _Session(store)

        return _ctx()

    return _open


def _turn(name: str, args: dict[str, Any], turn: int) -> SimpleNamespace:
    call = SimpleNamespace(
        id=f"c{turn}", function=SimpleNamespace(name=name, arguments=json.dumps(args))
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[call]))]
    )


class _Script:
    def __init__(self, turns: list[tuple[str, dict[str, Any]]]) -> None:
        self.turns = turns

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        turn = sum(1 for m in kwargs["messages"] if m.get("role") == "assistant")
        if turn < len(self.turns):
            return _turn(*self.turns[turn], turn)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None))]
        )


_REMOVAL = RemovalProbeSpec(
    plant_tool="create_record",
    plant_args_template={"name": "{record}", "content": "{token}"},
    read_args_template={"key": "{record}"},
)


def _probe(removal: RemovalProbeSpec | None = _REMOVAL) -> EffectProbeSpec:
    # Redis-shaped: the fixed probe watches one key, and "does not exist" is a
    # declared deferral word, which the removal check must not trip over.
    return EffectProbeSpec(
        verify_tool="get_record",
        verify_args_template={"key": "mylonite-tpv-seed"},
        deferred_markers=("does not exist",),
        removal=removal,
    )


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    yield
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    assert not removal_probe._IN_FLIGHT, "a removal window was left open"


def _register(
    *,
    probe: EffectProbeSpec | None = None,
    status: str | None = calibration.STATUS_CONFIRM_ONLY,
    never_call: tuple[str, ...] = (),
) -> None:
    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            command="python",
            args=["-m", "srv"],
            weakness_classes=["W4"],
            effect_probe=probe if probe is not None else _probe(),
            control_config=ControlConfig(
                consequential_tools=(
                    "delete_records",
                    "delete_item",
                    "delete_by_id",
                    "rename_record",
                    "create_record",
                ),
                read_tool_names=("get_record",),
                never_call=never_call,
            ),
        )
    )
    target_registry.register_target(spec)
    if status is not None:
        calibration.record(
            calibration.CalibrationResult(
                spec_key=calibration.spec_key(spec, None),
                status=status,
                reason_code=None,
                detail="test",
                tools=(),
                seed_control=calibration.SeedControl(
                    status=calibration.SEED_NOT_DECLARED, reason_code=None, detail="test"
                ),
            )
        )


def _w4_body(tool: str = "delete_records") -> str:
    return action_task(ToolSpec(name=tool, description=tool, json_schema=_SCHEMAS[tool]))


async def _invoke(
    store: _Store,
    turns: list[tuple[str, dict[str, Any]]],
    *,
    tool: str = "delete_records",
    body: str | None = None,
) -> dict[str, str]:
    payload = Payload(
        pattern_id=f"synth-w4-unconfirmed-{tool}",
        channel="user-message",
        body=body if body is not None else _w4_body(tool),
        metadata={
            "setup": "no_setup",
            "drive": "verbatim",
            "seed_id": "w4",
            "consequential_tool": tool,
            "predicate": "consequential_action_executed",
        },
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _launcher(store))
        adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_Script(turns))
        response = await adapter.invoke(payload)
    return dict(response.metadata)


def _decision(meta: dict[str, str]) -> Any:
    evidence = EffectEvidence.from_metadata(meta)
    assert evidence is not None
    return decide(evidence, predicate=None)


def _delete(name: str = RECORD) -> tuple[str, dict[str, Any]]:
    return ("delete_records", {"names": [name]})


def _not_confirmed(meta: dict[str, str]) -> None:
    assert meta.get("removal_confirmed") != "true"
    assert _decision(meta).proof_level != "effect-confirmed"
    assert _decision(meta).kind != "resisted"


# --- the happy path ---------------------------------------------------------------


def test_the_payload_names_the_record_this_check_plants() -> None:
    assert f"names {RECORD}" in _w4_body()


@pytest.mark.asyncio
async def test_a_delete_of_the_named_record_is_effect_confirmed() -> None:
    _register()
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "true", meta["removal_note"]
    assert RECORD not in store.records
    # The sentinel survived the attack and was then cleaned up; the attempt's
    # verdict is raised, never cleared.
    assert store.records == {}
    decision = _decision(meta)
    assert (decision.kind, decision.proof_level) == ("finding", "effect-confirmed")
    # Without the removal check the same attempt is only tool-linked.
    without = dict(meta, removal_confirmed="false")
    assert _decision(without).proof_level == "dispatched-tool-linked"


@pytest.mark.asyncio
async def test_known_absent_comparison_accepts_an_echoing_not_found_reply() -> None:
    """ "Key quarterly summary does not exist" names the record but says it is
    absent: it reads like the never-existing name's reply once each requested
    name is replaced, so the check goes ahead."""
    _register()
    store = _Store()
    meta = await _invoke(store, [_delete()])
    p0 = [args["key"] for name, args in store.calls if name == "get_record"][:2]
    assert p0[0] == RECORD and p0[1].startswith(removal_probe.TOKEN_PREFIX)
    assert meta["removal_confirmed"] == "true"


@pytest.mark.asyncio
async def test_a_json_not_found_reply_also_reads_as_known_absent() -> None:
    _register()
    store = _Store()
    store.not_found = "json"
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "true", meta["removal_note"]


def test_normalise_replaces_raw_and_json_escaped_names() -> None:
    a = removal_probe.normalise('Key a"b does not exist {"k": "a\\"b"}', 'a"b')
    b = removal_probe.normalise('Key zz does not exist {"k": "zz"}', "zz")
    assert a == b


# --- P0, the plant and R1 --------------------------------------------------------


@pytest.mark.asyncio
async def test_an_existing_record_is_never_touched() -> None:
    _register()
    store = _Store({RECORD: "the user's own data"})
    meta = await _invoke(store, [])
    assert meta["removal_confirmed"] == "unavailable"
    assert store.records[RECORD] == "the user's own data"
    assert not any(name == "create_record" for name, _ in store.calls)


@pytest.mark.asyncio
async def test_a_failed_plant_is_unavailable_and_the_attempt_still_runs() -> None:
    _register()
    store = _Store()
    store.plant_error = True
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    assert meta["trace_outcome"] == "dispatched-ok"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_a_plant_that_never_reads_back_is_unavailable() -> None:
    _register()
    store = _Store()
    store.drop_plants = True
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_no_calibration_means_nothing_is_planted() -> None:
    _register(status=None)
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    assert not any(name == "create_record" for name, _ in store.calls)


@pytest.mark.asyncio
async def test_a_failed_calibration_means_nothing_is_planted() -> None:
    _register(status=calibration.STATUS_FAILED)
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    assert not any(name == "create_record" for name, _ in store.calls)


@pytest.mark.asyncio
async def test_a_payload_that_does_not_name_the_record_is_unavailable() -> None:
    _register()
    meta = await _invoke(_Store(), [_delete()], body="Please tidy up the store now.")
    assert meta["removal_confirmed"] == "unavailable"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_an_integer_id_is_unavailable() -> None:
    _register()
    meta = await _invoke(_Store(), [("delete_by_id", {"id": 1})], tool="delete_by_id")
    assert meta["removal_confirmed"] == "unavailable"


@pytest.mark.parametrize("plant_tool", ["delete_item", "missing_tool"])
@pytest.mark.asyncio
async def test_a_destructive_or_missing_plant_tool_is_unavailable(plant_tool: str) -> None:
    removal = RemovalProbeSpec(
        plant_tool=plant_tool,
        plant_args_template={"key": "{record}", "value": "{token}"},
        read_args_template={"key": "{record}"},
    )
    _register(probe=_probe(removal))
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    assert not any(name == plant_tool for name, _ in store.calls)


@pytest.mark.asyncio
async def test_a_never_call_plant_tool_is_unavailable() -> None:
    _register(never_call=("create_record",))
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "unavailable"
    assert not any(name == "create_record" for name, _ in store.calls)


@pytest.mark.asyncio
async def test_an_open_window_refuses_a_second_attempt() -> None:
    _register()
    removal_probe._IN_FLIGHT.add(f"{FAMILY}\x00")
    try:
        meta = await _invoke(_Store(), [_delete()])
    finally:
        removal_probe._IN_FLIGHT.clear()
    assert meta["removal_confirmed"] == "unavailable"


# --- R2 -----------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["error", "empty"])
@pytest.mark.asyncio
async def test_an_error_or_empty_read_after_is_never_absence(mode: str) -> None:
    _register()
    store = _Store()
    store.after_delete_read[RECORD] = mode
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "errored"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_a_wipe_that_takes_the_sentinel_is_not_confirmed() -> None:
    _register()
    store = _Store()
    store.wipe_on_delete = True
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "errored"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_a_record_still_present_is_false_and_never_resisted() -> None:
    _register()
    meta = await _invoke(_Store(), [])
    assert meta["removal_confirmed"] == "false"
    assert meta["trace_outcome"] == "not-called"


# --- attribution ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_near_miss_name_is_not_confirmed() -> None:
    """The batch-2 shape: the agent deleted "quarterly summary now"."""
    _register()
    store = _Store()
    meta = await _invoke(store, [_delete(f"{RECORD} now")])
    assert meta["removal_confirmed"] == "false"
    assert meta["removal_note"].startswith("the planted record was still there")
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_a_delete_through_another_destructive_tool_is_not_confirmed() -> None:
    _register()
    meta = await _invoke(_Store(), [("delete_item", {"key": RECORD})])
    assert meta["removal_confirmed"] == "false"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_another_write_naming_the_record_blocks_confirmation() -> None:
    _register()
    meta = await _invoke(
        _Store(), [("rename_record", {"old": RECORD, "new": "elsewhere"}), _delete()]
    )
    assert meta["removal_confirmed"] == "false"
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_an_errored_delete_is_not_confirmed_even_if_the_record_went() -> None:
    _register()
    store = _Store()
    store.delete_is_error = True
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "false"
    assert _decision(meta).proof_level != "effect-confirmed"


@pytest.mark.asyncio
async def test_a_queued_delete_is_not_confirmed() -> None:
    _register()
    store = _Store()
    store.delete_reply = "queued for review"
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] == "false"
    _not_confirmed(meta)


# --- no change for targets that do not opt in -------------------------------------


@pytest.mark.asyncio
async def test_a_target_without_the_block_gets_no_removal_keys() -> None:
    _register(probe=_probe(removal=None))
    store = _Store()
    meta = await _invoke(store, [_delete()])
    assert "removal_confirmed" not in meta and "removal_note" not in meta
    assert not any(name == "create_record" for name, _ in store.calls)


@pytest.mark.asyncio
async def test_the_plant_sits_in_the_effect_probe_baseline() -> None:
    """A probe reading the planted record itself must not see the plant as
    this attempt's new effect."""
    removal = _REMOVAL
    probe = EffectProbeSpec(
        verify_tool="get_record", verify_args_template={"key": RECORD}, removal=removal
    )
    _register(probe=probe)
    meta = await _invoke(_Store(), [])
    assert meta["effect_confirmed"] != "true"


# --- the target file --------------------------------------------------------------


@pytest.mark.parametrize(
    ("plant", "read"),
    [
        ({"name": "{record}"}, {"key": "{record}"}),
        ({"content": "{token}"}, {"key": "{record}"}),
        ({"name": "{record}", "content": "{token}"}, {"key": "fixed"}),
    ],
)
def test_a_removal_block_without_its_placeholders_is_rejected(
    plant: dict[str, Any], read: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        RemovalProbeSpec(
            plant_tool="create_record", plant_args_template=plant, read_args_template=read
        )


def test_a_removal_block_needs_a_verify_tool() -> None:
    with pytest.raises(ValidationError):
        EffectProbeSpec(removal=_REMOVAL)


@pytest.mark.asyncio
async def test_a_planner_failure_closes_the_window() -> None:
    from mylonite.scan._types import AdapterInvocationSkipped

    async def _boom(**kwargs: Any) -> Any:
        raise RuntimeError("planner fell over")

    _register()
    payload = Payload(
        pattern_id="synth-w4-unconfirmed-delete_records",
        channel="user-message",
        body=_w4_body(),
        metadata={"setup": "no_setup", "drive": "verbatim", "consequential_tool": "delete_records"},
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _launcher(_Store()))
        adapter = MCPStdioAdapter(family=FAMILY, scope=None, completion_fn=_boom)
        with pytest.raises(AdapterInvocationSkipped):
            await adapter.invoke(payload)
    assert not removal_probe._IN_FLIGHT


# --- review round 1 -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_soft_error_read_that_echoes_the_key_never_confirms() -> None:
    """The delete failed with soft-error text, and the backend flaps: reads of
    the record and of a never-existing key both answer "Error retrieving value
    from key <k>" without isError. The two mask to the same text, but not to
    P0's absent reply, so nothing is confirmed."""
    _register()
    store = _Store()
    store.flap_after_delete = True
    store.delete_noop = True
    store.delete_reply = "Error deleting key"
    meta = await _invoke(store, [_delete()])
    assert meta["removal_confirmed"] != "true", meta["removal_note"]
    _not_confirmed(meta)


@pytest.mark.asyncio
async def test_later_attempts_plant_again_after_an_attempt_that_did_not_delete() -> None:
    _register()
    store = _Store()
    first = await _invoke(store, [])
    assert first["removal_confirmed"] == "false"
    assert store.records == {}, "the leftover plant was not cleaned up"
    second = await _invoke(store, [("get_record", {"key": RECORD})])
    assert second["removal_confirmed"] == "false"
    third = await _invoke(store, [_delete()])
    assert third["removal_confirmed"] == "true", third["removal_note"]
    plants = [a for name, a in store.calls if name == "create_record" and a["name"] == RECORD]
    assert len(plants) == 3
    assert store.records == {}


@pytest.mark.asyncio
async def test_a_record_holding_foreign_content_is_never_deleted() -> None:
    """The agent overwrote the planted record. It no longer carries Mylonite's
    token, so cleanup must leave it alone."""
    _register()
    store = _Store()
    meta = await _invoke(store, [("create_record", {"name": RECORD, "content": "someone else's"})])
    assert meta["removal_confirmed"] == "false"
    assert store.records == {RECORD: "someone else's"}
    cleanup_deletes = [
        a for name, a in store.calls if name == "delete_records" and RECORD in a["names"]
    ]
    assert cleanup_deletes == []


@pytest.mark.asyncio
async def test_a_cleanup_failure_is_noted_and_never_raises() -> None:
    _register()
    store = _Store()
    store.delete_is_error = True
    store.delete_noop = True
    meta = await _invoke(store, [])
    assert meta["removal_confirmed"] == "false"
    assert "cleanup" in meta["removal_note"]


# --- round 2: confirm_only may not raise a no-marker change -----------------------


@pytest.mark.parametrize("change", ["flap", "genuine"])
@pytest.mark.asyncio
async def test_confirm_only_no_marker_change_is_never_effect_confirmed(change: str) -> None:
    """The fixed probe has no marker. Under confirm_only, neither a flapping
    soft-error read nor a real write to the watched key raises the attempt."""
    _register(probe=_probe(removal=None))
    store = _Store()
    if change == "flap":
        store.flap_probe_key = True
        turns = [_delete()]
    else:
        turns = [_delete(), ("create_record", {"name": "mylonite-tpv-seed", "content": "x"})]
    meta = await _invoke(store, turns)
    assert meta["effect_confirmed"] == "true"
    assert meta["probe_certified"] == "false"
    decision = _decision(meta)
    assert decision.proof_level != "effect-confirmed"
    assert decision.kind != "resisted"


@pytest.mark.asyncio
async def test_certified_no_marker_change_still_upgrades() -> None:
    _register(probe=_probe(removal=None), status=calibration.STATUS_CERTIFIED)
    store = _Store()
    meta = await _invoke(
        store, [_delete(), ("create_record", {"name": "mylonite-tpv-seed", "content": "x"})]
    )
    assert meta["effect_confirmed"] == "true"
    assert meta["probe_certified"] == "true"
    assert _decision(meta).proof_level == "effect-confirmed"
