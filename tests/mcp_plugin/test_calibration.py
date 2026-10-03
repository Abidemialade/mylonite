"""Calibration: an effect probe's "no change" counts only after it is proven.

``plugins/_mcp/calibration.py`` runs model-free controls against a custom
target before its effect probe is trusted:

* a schema check: the verify arguments and each control write must satisfy the
  tool's ``inputSchema`` (``MYL-INC-005``);
* a negative control: two reads with nothing written between them must not read
  as a change (``MYL-INC-004``);
* a positive control: a write carrying a ``myl-cal-<hex>`` token must read as a
  change (``MYL-INC-003``);
* the W2 seed control: plant a token through the ``seed_arm`` and recall it
  (``MYL-INC-006`` when that fails, ``MYL-INC-007`` when no recall tool exists).

Each fake session is one launch over a shared store, like the fakes in
``test_effect_attribution.py``. No model is involved anywhere.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool
from tests.mcp_plugin.fakes.neutral_servers import memory_tools

from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp import calibration, stdio_adapter, target_registry
from mylonite.plugins._mcp.factory import build_adapter_for_spec
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
from mylonite.plugins._mcp.target_registry import (
    CalibrationSettings,
    ControlConfig,
    EffectProbeSpec,
    SeedArmSpec,
)

FAMILY = "cal-app"
MARKER = "attacker@example.com"

_OBJ_EMPTY: dict[str, Any] = {"type": "object", "properties": {}}


def _schema(**props: str) -> dict[str, Any]:
    """An object schema whose listed string params are all required."""
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in props.items()},
        "required": list(props),
    }


_DEFAULT_TOOLS: dict[str, dict[str, Any]] = {
    "send_email": _schema(to="string", body="string"),
    "list_outbox": _OBJ_EMPTY,
    "remember": _schema(content="string"),
    "recall": _OBJ_EMPTY,
    "delete_email": _schema(to="string"),
}


class _Store:
    """State that outlives one session."""

    def __init__(self) -> None:
        self.outbox: list[str] = []
        self.notes: list[str] = []
        self.reads = 0
        #: The verify read returns a fresh counter each time (a timestamped view).
        self.noisy_verify = False
        #: The send replies "sent" but stores nothing.
        self.drop_sends = False
        #: The recall tool never shows what was planted.
        self.blind_recall = False
        #: The plant call errors.
        self.plant_errors = False
        #: The send replies with a deferral word and stores nothing.
        self.defer_sends = False
        #: Seconds the verify read sleeps (a hung server).
        self.verify_delay = 0.0
        #: #324: the recall tool echoes the planted note ONLY through
        #: ``structuredContent`` (a go-memory-shaped response) -- ``content``
        #: stays a fixed, unrelated human-readable string, same as a real
        #: Go-SDK MCP server's "Nodes searched successfully" reply.
        self.structured_only_recall = False
        #: #324 review I2: the recall tool echoes its own ``query`` argument
        #: back and never actually stores or retrieves anything.
        self.echo_recall_query = False
        #: #324 re-review: the recall tool's FIRST call (the baseline, read
        #: before anything is planted) raises; every later call (the
        #: post-plant read) echoes its own ``query`` argument back instead.
        self.recall_baseline_raises_once = False
        self.recall_calls = 0


def _text(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


def _structured(text: str, structured: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)], structuredContent=structured
    )


class _Session:
    """A fake ``mcp.ClientSession`` over a shared ``_Store``."""

    def __init__(self, store: _Store, tools: dict[str, dict[str, Any]]) -> None:
        self.store = store
        self.tools = tools
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[
                MCPTool(name=name, description=name, inputSchema=schema)
                for name, schema in self.tools.items()
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, dict(arguments)))
        store = self.store
        if name in ("list_outbox", "read_file"):
            if store.verify_delay:
                await asyncio.sleep(store.verify_delay)
            store.reads += 1
            if store.noisy_verify:
                return _text(f"outbox as of read {store.reads}: " + "\n".join(store.outbox))
            return _text("\n".join(store.outbox) or "outbox empty")
        if name == "send_email":
            if store.defer_sends:
                return _text("queued for approval")
            if not store.drop_sends:
                store.outbox.append(
                    f"to={arguments.get('to', '')} body={arguments.get('body', '')}"
                )
            return _text("sent")
        if name == "remember":
            if store.plant_errors:
                return _text("store full", is_error=True)
            store.notes.append(str(arguments.get("content", "")))
            return _text("stored")
        if name == "recall":
            if store.blind_recall:
                return _text("no notes")
            if store.recall_baseline_raises_once:
                store.recall_calls += 1
                if store.recall_calls == 1:
                    raise RuntimeError("recall baseline read failed")
                # The post-plant call: echoes its own query argument back,
                # the exact I2 echo shape -- it must still never pass once
                # its baseline is excluded (#324 re-review).
                query = str(arguments.get("query", ""))
                return _structured(f"searched for {query}", {"query": query, "results": []})
            if store.echo_recall_query:
                # #324 review I2: echoes its own ``query`` argument back and
                # never actually stores or retrieves anything -- every
                # required arg of a recall call is filled with the token
                # itself, so an echo alone must never read as "recalled".
                query = str(arguments.get("query", ""))
                return _structured(f"searched for {query}", {"query": query, "results": []})
            if store.structured_only_recall:
                # The fixed, unrelated reply a Go-SDK MCP server sends in
                # `content` on every call, whatever was actually recalled --
                # the real data rides only in `structuredContent`.
                return _structured("Nodes searched successfully", {"notes": list(store.notes)})
            return _text("\n".join(store.notes) or "no notes")
        if name == "delete_email":
            return _text("deleted")
        return _text(f"{name} ok")


class _Launcher:
    """Patches ``_open_mcp_session``: every open is a fresh launch over one store."""

    def __init__(self, store: _Store, tools: dict[str, dict[str, Any]] | None = None) -> None:
        self.store = store
        self.tools = dict(_DEFAULT_TOOLS if tools is None else tools)
        self.sessions: list[_Session] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        session = _Session(self.store, self.tools)
        self.sessions.append(session)

        @asynccontextmanager
        async def _ctx() -> Any:
            yield session

        return _ctx()

    @property
    def calls(self) -> list[tuple[str, dict[str, Any]]]:
        return [c for s in self.sessions for c in s.calls]

    def called(self, tool: str) -> list[dict[str, Any]]:
        return [args for name, args in self.calls if name == tool]


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    yield
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()


_PROBE = EffectProbeSpec(verify_tool="list_outbox", expect_marker=MARKER)
_SEED_ARM = SeedArmSpec(tool="remember", args_template={"content": "{payload}"})


def _register(
    probe: EffectProbeSpec | None = _PROBE,
    *,
    seed_arm: SeedArmSpec | None = _SEED_ARM,
    control_config: ControlConfig | None = None,
    timeout_s: float | None = None,
    calibration_controls: str | None = None,
) -> target_registry.TargetSpec:
    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            command="python",
            args=["-m", "srv"],
            weakness_classes=["W2", "W4"],
            seed_arm=seed_arm,
            effect_probe=probe,
            control_config=control_config,
            timeout_s=timeout_s,
            calibration=(
                CalibrationSettings(controls=calibration_controls)  # type: ignore[arg-type]
                if calibration_controls is not None
                else None
            ),
        )
    )
    target_registry.register_target(spec)
    return spec


async def _calibrate(
    launcher: _Launcher, *, allow_writes: bool = True, adapter: Any = None
) -> calibration.CalibrationResult:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", launcher)
        adapter = adapter or MCPStdioAdapter(family=FAMILY, scope=None)
        return await calibration.calibrate(adapter, allow_writes=allow_writes)


# --- validate_args -------------------------------------------------------------


def test_validate_args_names_the_missing_required_argument() -> None:
    errors = calibration.validate_args(_schema(path="string"), {})
    assert errors
    assert "path" in errors[0]


def test_validate_args_accepts_valid_arguments() -> None:
    assert calibration.validate_args(_schema(path="string"), {"path": "/tmp/x"}) == []


def test_validate_args_reports_a_wrong_type() -> None:
    errors = calibration.validate_args(_schema(n="integer"), {"n": "seven"})
    assert errors


def test_validate_args_skips_an_invalid_schema() -> None:
    """A server's broken schema is not the operator's argument error."""
    assert calibration.validate_args({"type": 12}, {}) == []


# --- a certified run --------------------------------------------------------------


@pytest.mark.asyncio
async def test_certified_run_proves_both_controls_and_the_seed_control() -> None:
    _register()
    store = _Store()
    launcher = _Launcher(store)

    result = await _calibrate(launcher)

    assert result.calibrated is True
    assert result.status == calibration.STATUS_CERTIFIED
    assert result.reason_code is None
    assert result.certified_tools == ("send_email",)
    # The control write carried a myl-cal token, and the verify read saw it.
    sends = launcher.called("send_email")
    assert len(sends) == 1
    assert any("myl-cal-" in v for v in sends[0].values())
    assert any("myl-cal-" in e for e in store.outbox)
    # The W2 seed control planted a token and recalled it.
    assert result.seed_control.status == calibration.SEED_PASSED
    assert result.seed_control.reason_code is None
    assert any("myl-cal-" in n for n in store.notes)
    assert launcher.called("recall")
    # One session for the whole run.
    assert len(launcher.sessions) == 1


@pytest.mark.asyncio
async def test_each_run_mints_a_fresh_token() -> None:
    _register()
    store = _Store()
    launcher = _Launcher(store)
    await _calibrate(launcher)
    await _calibrate(launcher)
    tokens = {
        m
        for args in launcher.called("send_email")
        for m in re.findall(r"myl-cal-[0-9a-f]+", str(args))
    }
    assert len(launcher.called("send_email")) == 2
    assert len(tokens) == 2


@pytest.mark.asyncio
async def test_destructive_tools_are_never_written() -> None:
    """Only create-kind effects are calibrated in this release."""
    _register()
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher)
    assert launcher.called("delete_email") == []
    assert "delete_email" not in [t.tool for t in result.tools]


@pytest.mark.asyncio
async def test_candidate_tools_are_capped_at_five() -> None:
    tools = dict(_DEFAULT_TOOLS)
    for i in range(8):
        tools[f"send_note_{i}"] = _schema(body="string")
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert len(result.tools) <= calibration.MAX_CANDIDATE_TOOLS == 5


@pytest.mark.asyncio
async def test_declared_consequential_tools_are_used() -> None:
    tools = dict(_DEFAULT_TOOLS)
    tools["dispatch_memo"] = _schema(text="string")
    _register(control_config=ControlConfig(consequential_tools=("dispatch_memo",)))
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert "dispatch_memo" in [t.tool for t in result.tools]


# --- INC-003: the positive control fails -------------------------------------------


@pytest.mark.asyncio
async def test_probe_blind_to_a_known_write_is_inc_003() -> None:
    _register()
    store = _Store()
    store.drop_sends = True
    result = await _calibrate(_Launcher(store))
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"
    assert result.tools[0].reason_code == "MYL-INC-003"


@pytest.mark.asyncio
async def test_a_deferred_control_write_is_inc_003() -> None:
    _register(EffectProbeSpec(verify_tool="list_outbox", expect_marker=MARKER))
    store = _Store()
    store.defer_sends = True
    result = await _calibrate(_Launcher(store))
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"


@pytest.mark.asyncio
async def test_verify_tool_missing_from_the_server_is_inc_003() -> None:
    _register(EffectProbeSpec(verify_tool="no_such_tool", expect_marker=MARKER))
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher)
    assert result.reason_code == "MYL-INC-003"
    assert "no_such_tool" in result.detail
    assert launcher.called("send_email") == []


@pytest.mark.asyncio
async def test_no_writable_candidate_is_inc_003() -> None:
    tools = {"list_outbox": _OBJ_EMPTY, "remember": _schema(content="string"), "recall": _OBJ_EMPTY}
    _register()
    result = await _calibrate(_Launcher(_Store(), tools))
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"


# --- INC-004: the negative control fails -------------------------------------------


@pytest.mark.asyncio
async def test_probe_that_reads_change_when_nothing_happened_is_inc_004() -> None:
    """With no marker, "new" means the output changed; a timestamped view always does."""
    _register(EffectProbeSpec(verify_tool="list_outbox"))
    store = _Store()
    store.noisy_verify = True
    result = await _calibrate(_Launcher(store))
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-004"


# --- INC-005: arguments fail the schema --------------------------------------------


@pytest.mark.asyncio
async def test_empty_verify_args_against_a_required_arg_is_inc_005() -> None:
    """The scaffold's ``verify_args_template: {}`` against server-filesystem's read_file."""
    tools = dict(_DEFAULT_TOOLS)
    tools["read_file"] = _schema(path="string")
    _register(EffectProbeSpec(verify_tool="read_file", verify_args_template={}))
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-005"
    assert "path" in result.detail
    # A schema failure stops the POSITIVE CONTROL before any write.
    # (``read_file`` is also an INFERRED W2 recall candidate here -- a
    # separate check the seed control runs on its own, independent of the
    # effect probe's own schema failure, and #324 review I2's echo-guard
    # baseline now reads every recall candidate once before planting.)
    assert launcher.called("send_email") == []


@pytest.mark.asyncio
async def test_control_write_that_fails_the_schema_is_inc_005() -> None:
    """A required param with no generic schema-valid literal (an array of
    objects: #324's backfill deliberately does not guess a shape for one)
    still fails the schema check, and the invalid call is never sent."""
    tools = dict(_DEFAULT_TOOLS)
    tools["send_email"] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "attachments": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["to", "body", "attachments"],
    }
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-005"
    assert launcher.called("send_email") == []


@pytest.mark.asyncio
async def test_control_write_fills_a_required_integer_sibling_instead_of_failing() -> None:
    """#324: a required integer/number/boolean sibling used to be left
    missing (an unconditional schema failure, ``MYL-INC-005``) even though a
    neutral literal would have made the call valid. It now gets one, so the
    control still certifies through a tool that merely has one more required
    argument than the content slot."""
    tools = dict(_DEFAULT_TOOLS)
    tools["send_email"] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "priority": {"type": "integer"},
        },
        "required": ["to", "body", "priority"],
    }
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is True
    assert result.status == calibration.STATUS_CERTIFIED
    sends = launcher.called("send_email")
    assert sends and sends[0]["priority"] == 0


@pytest.mark.asyncio
async def test_control_write_skips_an_id_shaped_integer_sibling_instead_of_filling_it() -> None:
    """#324 review I3: a required integer/boolean sibling whose NAME is
    id-shaped (``chat_id``) must never be auto-filled with ``0`` -- unlike
    the per-run token a string fill uses, a bare ``0`` can BE a real (often
    root/default) resource. The tool is skipped entirely, and the invalid
    call is never sent."""
    tools = dict(_DEFAULT_TOOLS)
    tools["send_email"] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "chat_id": {"type": "integer"},
        },
        "required": ["to", "body", "chat_id"],
    }
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-005"
    assert "no schema-valid value" in result.detail
    assert launcher.called("send_email") == []


@pytest.mark.asyncio
async def test_control_write_whose_filled_integer_violates_a_minimum_is_inc_005() -> None:
    """A NON-id-shaped required integer sibling with a ``minimum`` constraint:
    the backfill's neutral ``0`` is schema-valid to fill in, but still fails
    the tool's own ``inputSchema`` -- pinning the ``validate_args`` branch of
    ``_control_one_tool`` (not the ``write_args is None`` early return the
    array-of-objects case above takes), and the invalid call is never sent."""
    tools = dict(_DEFAULT_TOOLS)
    tools["send_email"] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "priority": {"type": "integer", "minimum": 1},
        },
        "required": ["to", "body", "priority"],
    }
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-005"
    assert "minimum" in result.detail
    assert launcher.called("send_email") == []


# --- INC-006 / INC-007: the W2 seed control ----------------------------------------


@pytest.mark.asyncio
async def test_seed_that_cannot_be_recalled_is_inc_006() -> None:
    _register()
    store = _Store()
    store.blind_recall = True
    result = await _calibrate(_Launcher(store))
    assert result.seed_control.status == calibration.SEED_FAILED
    assert result.seed_control.reason_code == "MYL-INC-006"
    # The effect probe still certified; the seed control is reported separately.
    assert result.calibrated is True


@pytest.mark.asyncio
async def test_plant_call_error_is_inc_006() -> None:
    _register()
    store = _Store()
    store.plant_errors = True
    result = await _calibrate(_Launcher(store))
    assert result.seed_control.status == calibration.SEED_FAILED
    assert result.seed_control.reason_code == "MYL-INC-006"
    assert "plant" in result.seed_control.detail


@pytest.mark.asyncio
async def test_no_recall_tool_is_inc_007() -> None:
    tools = {
        "remember": _schema(content="string"),
        "send_email": _schema(to="string", body="string"),
    }
    _register(probe=None)
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.seed_control.status == calibration.SEED_NOT_RUN
    assert result.seed_control.reason_code == "MYL-INC-007"
    # Nothing is planted when it could never be recalled.
    assert launcher.called("remember") == []


@pytest.mark.asyncio
async def test_no_seed_arm_means_no_seed_control() -> None:
    _register(seed_arm=None)
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher)
    assert result.seed_control.status == calibration.SEED_NOT_DECLARED
    assert result.seed_control.reason_code is None
    assert launcher.called("remember") == []


@pytest.mark.asyncio
async def test_no_effect_probe_still_runs_the_seed_control() -> None:
    _register(probe=None)
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher)
    assert result.status == calibration.STATUS_NO_PROBE
    assert result.calibrated is False
    assert result.reason_code is None
    assert launcher.called("send_email") == []
    assert result.seed_control.status == calibration.SEED_PASSED


# --- no writes allowed: no calls at all --------------------------------------------


@pytest.mark.asyncio
async def test_no_calls_at_all_when_writes_are_not_allowed() -> None:
    _register()
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher, allow_writes=False)
    assert launcher.sessions == []
    assert result.calibrated is False
    assert result.status == calibration.STATUS_NOT_AUTHORIZED
    assert result.reason_code == "MYL-INC-002"
    assert result.seed_control.status == calibration.SEED_NOT_RUN
    # Not recorded: a later authorized run starts from nothing.
    assert calibration.lookup(target_registry.resolve_target(FAMILY, None), None) is None


# --- the registry ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_survives_clear_runtime_targets() -> None:
    spec = _register()
    result = await _calibrate(_Launcher(_Store()))
    assert calibration.lookup(spec, None) is result
    target_registry.clear_runtime_targets()
    assert calibration.lookup(spec, None) is result


def test_spec_key_depends_on_the_probe_and_the_scope() -> None:
    a = _register()
    target_registry.clear_runtime_targets()
    b = _register(EffectProbeSpec(verify_tool="list_outbox", expect_marker="other"))
    assert calibration.spec_key(a, None) == calibration.spec_key(a, None)
    assert calibration.spec_key(a, None) != calibration.spec_key(b, None)
    assert calibration.spec_key(a, None) != calibration.spec_key(a, "scope-x")


def test_spec_key_ignores_env_values() -> None:
    """Env values may carry secrets; the key is built from their names only."""
    spec = _register()
    one = target_registry.TargetSpec(**{**spec.__dict__, "extra_env": {"TOKEN": "a"}})
    two = target_registry.TargetSpec(**{**spec.__dict__, "extra_env": {"TOKEN": "b"}})
    assert calibration.spec_key(one, None) == calibration.spec_key(two, None)


# --- timeout -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_hung_verify_read_is_bounded_by_the_target_timeout() -> None:
    spec = _register(timeout_s=0.05)
    store = _Store()
    store.verify_delay = 5.0
    launcher = _Launcher(store)
    adapter = build_adapter_for_spec(spec, scope=None, model="m")
    started = time.monotonic()
    result = await _calibrate(launcher, adapter=adapter)
    assert time.monotonic() - started < 3.0
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"


# --- every code used is registered -------------------------------------------------


def test_every_code_the_module_emits_is_registered() -> None:
    from mylonite import reason_codes

    for code in calibration.EMITTED_CODES:
        assert reason_codes.get(code).category == reason_codes.CATEGORY_INCONCLUSIVE
    assert set(calibration.EMITTED_CODES) == {f"MYL-INC-00{n}" for n in range(2, 8)}


# --- calibrate_custom_target: wiring, opt-in, caching ------------------------------


@pytest.mark.asyncio
async def test_calibrate_custom_target_certifies_an_authorized_stdio_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "auto" (the default) allows controls on an authorized stdio target."""
    _register()
    launcher = _Launcher(_Store())
    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", launcher)
    adapter = MCPStdioAdapter(family=FAMILY, scope=None)
    result = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert result.calibrated is True
    assert len(launcher.sessions) == 1


@pytest.mark.asyncio
async def test_calibrate_custom_target_caches_a_second_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cached: a repeat call for the same spec+scope is a no-op (no new launch)."""
    _register()
    launcher = _Launcher(_Store())
    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", launcher)
    adapter = MCPStdioAdapter(family=FAMILY, scope=None)
    first = await calibration.calibrate_custom_target(adapter, authorized=True)
    second = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert second is first
    assert len(launcher.sessions) == 1


@pytest.mark.asyncio
async def test_calibrate_custom_target_makes_no_calls_when_not_authorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register()
    launcher = _Launcher(_Store())
    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", launcher)
    adapter = MCPStdioAdapter(family=FAMILY, scope=None)
    result = await calibration.calibrate_custom_target(adapter, authorized=False)
    assert launcher.sessions == []
    assert result.calibrated is False
    assert result.status == calibration.STATUS_NOT_AUTHORIZED


@pytest.mark.asyncio
async def test_calibrate_custom_target_degrades_when_the_target_fails_to_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """calibrate() itself lets a launch/list_tools failure propagate;
    calibrate_custom_target must degrade to a not-calibrated result instead of
    raising, and still cache it (so a broken target isn't relaunched every call)."""

    class _FailingLauncher:
        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            @asynccontextmanager
            async def _ctx() -> Any:
                raise RuntimeError("could not launch")
                yield  # pragma: no cover — never reached

            return _ctx()

    _register()
    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", _FailingLauncher())
    adapter = MCPStdioAdapter(family=FAMILY, scope=None)
    result = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert result.calibrated is False
    assert result.status != calibration.STATUS_CERTIFIED
    spec = target_registry.resolve_target(FAMILY, None)
    assert calibration.lookup(spec, None) is result


def _fake_spec_adapter(spec: target_registry.TargetSpec) -> Any:
    """A bare adapter stand-in: calibrate_custom_target reads only _spec/_scope
    off it before dispatching to (a monkeypatched) calibrate()."""
    return SimpleNamespace(_spec=spec, _scope=None)


@pytest.mark.asyncio
async def test_calibrate_custom_target_auto_withholds_consent_for_a_remote_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "auto" on a remote (sse/http) target makes no calls — only "allow" does."""
    seen: list[bool] = []

    async def fake_calibrate(adapter: Any, allow_writes: bool) -> calibration.CalibrationResult:
        seen.append(allow_writes)
        return calibration.CalibrationResult(
            spec_key="k",
            status=calibration.STATUS_NOT_AUTHORIZED,
            reason_code=calibration.INC_NOT_CALIBRATED,
            detail="stub",
            tools=(),
            seed_control=calibration.SeedControl(
                calibration.SEED_NOT_RUN, calibration.INC_NOT_CALIBRATED, "stub"
            ),
        )

    monkeypatch.setattr(calibration, "calibrate", fake_calibrate)
    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            transport="sse",
            url="https://agent.example/mcp",
            command="",
            weakness_classes=["W2"],
        )
    )
    target_registry.register_target(spec)
    adapter = _fake_spec_adapter(spec)
    result = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert seen == [False]
    assert result.status == calibration.STATUS_NOT_AUTHORIZED


@pytest.mark.asyncio
async def test_calibrate_custom_target_allow_runs_on_a_remote_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []

    async def fake_calibrate(adapter: Any, allow_writes: bool) -> calibration.CalibrationResult:
        seen.append(allow_writes)
        return calibration.CalibrationResult(
            spec_key="k",
            status=calibration.STATUS_CERTIFIED,
            reason_code=None,
            detail="stub",
            tools=(),
            seed_control=calibration.SeedControl(calibration.SEED_NOT_DECLARED, None, "stub"),
        )

    monkeypatch.setattr(calibration, "calibrate", fake_calibrate)
    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            transport="sse",
            url="https://agent.example/mcp",
            command="",
            weakness_classes=["W2"],
            calibration=CalibrationSettings(controls="allow"),
        )
    )
    target_registry.register_target(spec)
    adapter = _fake_spec_adapter(spec)
    result = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert seen == [True]
    assert result.calibrated is True


@pytest.mark.asyncio
async def test_calibrate_custom_target_controls_skip_makes_no_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []

    async def fake_calibrate(adapter: Any, allow_writes: bool) -> calibration.CalibrationResult:
        seen.append(allow_writes)
        return calibration.CalibrationResult(
            spec_key="k",
            status=calibration.STATUS_NOT_AUTHORIZED,
            reason_code=calibration.INC_NOT_CALIBRATED,
            detail="stub",
            tools=(),
            seed_control=calibration.SeedControl(
                calibration.SEED_NOT_RUN, calibration.INC_NOT_CALIBRATED, "stub"
            ),
        )

    monkeypatch.setattr(calibration, "calibrate", fake_calibrate)
    spec = _register(calibration_controls="skip")
    adapter = _fake_spec_adapter(spec)
    result = await calibration.calibrate_custom_target(adapter, authorized=True)
    assert seen == [False]
    assert result.status == calibration.STATUS_NOT_AUTHORIZED


# --- the summary a scan carries ---------------------------------------------------


@pytest.mark.asyncio
async def test_summarise_carries_the_certificate() -> None:
    _register()
    result = await _calibrate(_Launcher(_Store()))
    summary = calibration.summarise(result)
    assert summary.status == calibration.STATUS_CERTIFIED
    assert summary.reason_code is None
    assert summary.seed_status == result.seed_control.status
    assert summary.certified_tools == result.certified_tools
    assert summary.calibrated is True


@pytest.mark.asyncio
async def test_the_adapter_reports_its_recorded_calibration() -> None:
    _register()
    await _calibrate(_Launcher(_Store()))
    summary = MCPStdioAdapter(family=FAMILY, scope=None).calibration_summary()
    assert summary is not None
    assert summary.status == calibration.STATUS_CERTIFIED


def test_an_uncalibrated_probe_reads_not_calibrated() -> None:
    """A declared probe that never ran its controls (skip, or no authorization)
    is reported as such, never as nothing."""
    _register()
    summary = MCPStdioAdapter(family=FAMILY, scope=None).calibration_summary()
    assert summary is not None
    assert summary.status == calibration.STATUS_NOT_AUTHORIZED
    assert summary.reason_code == "MYL-INC-002"
    assert summary.seed_status == calibration.SEED_NOT_RUN


def test_a_target_with_nothing_to_calibrate_has_no_summary() -> None:
    _register(None, seed_arm=None)
    assert MCPStdioAdapter(family=FAMILY, scope=None).calibration_summary() is None


# --- verify arguments must render the way an attempt renders them ---------------


@pytest.mark.asyncio
async def test_a_payload_placeholder_in_verify_args_is_never_certified() -> None:
    """Calibration would render ``{payload}`` as its own short token, but an
    attempt renders it as the whole attack text. A search that finds the
    token proves nothing about the search an attempt runs, so the probe is
    never certified, and no control write is made."""
    tools = dict(_DEFAULT_TOOLS)
    tools["search_outbox"] = _schema(query="string")
    _register(
        EffectProbeSpec(
            verify_tool="search_outbox",
            verify_args_template={"query": "{payload}"},
            expect_marker=MARKER,
        )
    )
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"
    assert "{payload}" in result.detail
    assert launcher.called("send_email") == []


# --- a launch failure is reported as such ------------------------------------------


@pytest.mark.asyncio
async def test_a_launch_failure_is_not_calibrated_and_blames_no_probe_wiring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingLauncher:
        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            @asynccontextmanager
            async def _ctx() -> Any:
                raise RuntimeError("could not launch")
                yield  # pragma: no cover — never reached

            return _ctx()

    _register(seed_arm=None)
    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", _FailingLauncher())
    result = await calibration.calibrate_custom_target(
        MCPStdioAdapter(family=FAMILY, scope=None), authorized=True
    )
    assert result.reason_code == calibration.INC_NOT_CALIBRATED
    assert "launch" in result.detail
    # No seed_arm is declared, so there is no seed control to blame.
    assert result.seed_control.status == calibration.SEED_NOT_DECLARED
    assert result.seed_control.reason_code is None


# --- the launch is part of what calibration proved --------------------------------


@pytest.mark.asyncio
async def test_calibration_of_one_launch_is_not_reused_for_the_vulnerable_twin() -> None:
    from mylonite.plugins._mcp.factory import LaunchIntent
    from mylonite.plugins._mcp.target_registry import LaunchOverride

    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            command="python",
            args=["-m", "srv"],
            weakness_classes=["W4"],
            effect_probe=_PROBE,
            vulnerable_launch=LaunchOverride(env={"GUARD": "off"}),
        )
    )
    target_registry.register_target(spec)
    guarded = build_adapter_for_spec(spec, scope=None, model="m")
    vulnerable = build_adapter_for_spec(
        spec, scope=None, model="m", intent=LaunchIntent(vulnerable=True)
    )
    result = await _calibrate(_Launcher(_Store()), adapter=guarded)
    assert result.calibrated is True
    assert guarded.calibration_summary().status == calibration.STATUS_CERTIFIED
    assert vulnerable.calibration_summary().status != calibration.STATUS_CERTIFIED


# --- #324: structuredContent readback -----------------------------------------
#
# A real Go-SDK MCP server (go-memory, a declared line-for-line port of
# server-memory) echoes a write back only through ``structuredContent``: its
# ``content`` stays a fixed, unrelated reply ("Nodes searched successfully").
# The W2 seed control's recall check used to read only ``content``, so a
# genuinely-recalled record read as "not recalled" (``MYL-INC-006``).


@pytest.mark.asyncio
async def test_seed_control_recognises_a_structured_content_only_echo() -> None:
    _register()
    store = _Store()
    store.structured_only_recall = True
    result = await _calibrate(_Launcher(store))
    assert result.seed_control.status == calibration.SEED_PASSED
    assert result.seed_control.recall_tool == "recall"


# --- #324 review I2: the recall check must not pass on an echo of its own query ---
#
# Every required argument of a recall call is filled with the token itself
# (``_fill_required_args(recall, {}, token)``), so a recall tool whose reply
# echoes its own query argument -- a common shape for a typed
# ``structuredContent`` result -- used to read ``token in content`` as
# "planted and recalled" with nothing actually stored. The check must now
# take a pre-plant baseline read with the SAME args and require the token's
# count to grow after planting.


@pytest.mark.asyncio
async def test_seed_control_recall_echo_of_the_query_is_inc_006_not_passed() -> None:
    tools = dict(_DEFAULT_TOOLS)
    tools["recall"] = _schema(query="string")
    _register()
    store = _Store()
    store.echo_recall_query = True
    result = await _calibrate(_Launcher(store, tools))
    assert result.seed_control.status == calibration.SEED_FAILED
    assert result.seed_control.reason_code == "MYL-INC-006"


@pytest.mark.asyncio
async def test_seed_control_recall_through_a_query_arg_passes_for_a_real_store() -> None:
    """The same required ``query`` argument shape as the echo test above, but
    a genuine store: the token's count grows after planting, so it passes."""
    tools = dict(_DEFAULT_TOOLS)
    tools["recall"] = _schema(query="string")
    _register()
    store = _Store()
    result = await _calibrate(_Launcher(store, tools))
    assert result.seed_control.status == calibration.SEED_PASSED
    assert result.seed_control.recall_tool == "recall"


@pytest.mark.asyncio
async def test_seed_control_recall_whose_baseline_raised_cannot_pass_on_an_echo() -> None:
    """#324 re-review: the recall tool's baseline read (before anything is
    planted) raises, so it proves nothing about this tool's post-plant
    count. The post-plant call then succeeds and merely echoes its own
    query argument -- the exact I2 echo shape. Defaulting the failed
    baseline to a zero count would let `1 > 0` pass as SEED_PASSED with
    nothing actually recalled; excluding the tool from the check once its
    baseline fails must not."""
    tools = dict(_DEFAULT_TOOLS)
    tools["recall"] = _schema(query="string")
    _register()
    store = _Store()
    store.recall_baseline_raises_once = True
    result = await _calibrate(_Launcher(store, tools))
    assert result.seed_control.status == calibration.SEED_FAILED
    assert result.seed_control.reason_code == "MYL-INC-006"


# --- #324: the content-slot walker resolves a union/nullable-typed field ----------
#
# mcp-redis's own ``set`` types its content argument as a Pydantic
# ``Union[str, bytes, int, float, dict]`` -- an ``anyOf`` with no inline
# ``"type"`` key at all. It used to be invisible to the content-slot walker,
# which fell through to a two-required-argument tool it could not fully
# construct a call for (``expire``, reported as a schema failure,
# ``MYL-INC-005``).


def test_candidate_tools_sees_a_redis_like_sets_anyof_union_value() -> None:
    set_tool = ToolSpec(
        name="set",
        description="",
        json_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "title": "Key"},
                "value": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "string", "format": "binary"},
                        {"type": "integer"},
                        {"type": "number"},
                        {"type": "object", "additionalProperties": True},
                    ],
                    "title": "Value",
                },
            },
            "required": ["key", "value"],
        },
    )
    spec = build_target_spec(
        TargetFile(
            family=FAMILY,
            command="python",
            args=["-m", "srv"],
            weakness_classes=["W4"],
            effect_probe=EffectProbeSpec(
                verify_tool="get", verify_args_template={"key": "mylonite-tpv-seed"}
            ),
            control_config=ControlConfig(consequential_tools=("set",)),
        )
    )
    candidates = calibration._candidate_tools([set_tool], spec, "get")
    by_name = {tool.name: template for tool, template in candidates}
    assert by_name["set"] == {"value": "{payload}"}

    # The backfilled call -- "key" (required, missing from the template) --
    # must be schema-VALID, never sent with it missing.
    token = "myl-cal-abc123"
    write_args = calibration._fill_required_args(set_tool, {"value": token}, token)
    assert write_args is not None
    assert calibration.validate_args(set_tool.json_schema, write_args) == []


# --- #324: the readback control on a memory-style store ----------------------------
#
# On a knowledge-graph or key-value store the effect probe reads back the one
# record the seed_arm writes (``search_nodes(query=<entity name>)``), so no
# consequential tool's control write can show up in it, and a tool that amends
# an existing record (``add_observations``) has no record to amend before the
# plant. The positive control used to run before anything was planted and
# failed with ``MYL-INC-003``. Calibration now checks the probe on the planted
# record: baseline reads, the plant, a positive read, then a read that must not
# change or show a token that was never planted.

_SEED_ENTITY = "mylonite-tpv-seed"


def _memory_tool_schemas() -> dict[str, dict[str, Any]]:
    return {tool.name: dict(tool.json_schema) for tool in memory_tools()}


def _memory_subset(*names: str) -> dict[str, dict[str, Any]]:
    return {n: s for n, s in _memory_tool_schemas().items() if n in names}


class _MemoryStore:
    """A server-memory-shaped knowledge graph that outlives one session."""

    def __init__(self) -> None:
        self.entities: dict[str, list[str]] = {}
        self.search_calls = 0
        #: Writes reply "ok" but store nothing; search echoes its own query.
        self.echo_only = False
        #: Search always returns the same text, whatever was written.
        self.frozen_search = False
        #: Search raises until something has been planted.
        self.search_raises_until_planted = False
        #: The first search call raises; later ones work.
        self.search_raises_once = False
        #: Search prefixes every reply with its own query.
        self.search_echoes_query = False
        #: A search that matches nothing returns ``isError``.
        self.search_error_when_no_match = False
        #: A search that matches nothing returns an empty result.
        self.search_empty_when_no_match = False
        #: Once planted, the second read of the seed entity returns ``isError``.
        self.second_seed_read_errors = False
        self.seed_reads_after_plant = 0


class _MemorySession(_Session):
    """A fake session over a ``_MemoryStore``."""

    def __init__(self, memory: _MemoryStore, tools: dict[str, dict[str, Any]]) -> None:
        super().__init__(_Store(), tools)
        self.memory = memory

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, dict(arguments)))
        mem = self.memory
        if name == "create_entities":
            if mem.echo_only:
                return _text(f"created {arguments}")
            for entity in arguments.get("entities", []):
                # Like the real server: an entity whose name exists is ignored.
                mem.entities.setdefault(entity["name"], list(entity.get("observations", [])))
            return _text("created")
        if name == "add_observations":
            if mem.echo_only:
                return _text(f"added {arguments}")
            for obs in arguments.get("observations", []):
                entity_name = obs["entityName"]
                if entity_name not in mem.entities:
                    return _text(f"Entity with name {entity_name} not found", is_error=True)
                mem.entities[entity_name].extend(obs.get("contents", []))
            return _text("added")
        if name == "create_relations":
            return _text("relations created")
        if name in ("search_nodes", "open_nodes", "read_graph"):
            mem.search_calls += 1
            if mem.search_raises_once and mem.search_calls == 1:
                raise RuntimeError("search failed")
            if mem.search_raises_until_planted and not mem.entities:
                raise RuntimeError("search failed")
            if mem.frozen_search:
                return _text("graph: (no matches)")
            query = str(arguments.get("query", ""))
            if mem.echo_only:
                return _text(f"searched for {query}")
            if mem.entities and query == _SEED_ENTITY:
                mem.seed_reads_after_plant += 1
                if mem.second_seed_read_errors and mem.seed_reads_after_plant == 2:
                    return _text("graph unavailable", is_error=True)
            hits = [
                name_ + ": " + "; ".join(obs)
                for name_, obs in mem.entities.items()
                if not query or query in name_ or any(query in o for o in obs)
            ]
            if not hits and mem.search_error_when_no_match:
                return _text("nothing found", is_error=True)
            if not hits and mem.search_empty_when_no_match:
                return CallToolResult(content=[], isError=False)
            reply = "\n".join(hits) or "no matches"
            if mem.search_echoes_query:
                reply = f"results for {query}:\n{reply}"
            return _text(reply)
        return _text(f"{name} ok")


class _MemoryLauncher(_Launcher):
    """``_Launcher`` over a ``_MemoryStore``."""

    def __init__(
        self, memory: _MemoryStore, tools: dict[str, dict[str, Any]] | None = None
    ) -> None:
        super().__init__(_Store(), tools if tools is not None else _memory_tool_schemas())
        self.memory = memory

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        session = _MemorySession(self.memory, self.tools)
        self.sessions.append(session)

        @asynccontextmanager
        async def _ctx() -> Any:
            yield session

        return _ctx()


def _register_memory(
    *,
    consequential: tuple[str, ...] = ("add_observations", "create_relations"),
    marker: str | None = None,
) -> None:
    _register(
        EffectProbeSpec(
            verify_tool="search_nodes",
            verify_args_template={"query": _SEED_ENTITY},
            expect_marker=marker,
        ),
        seed_arm=SeedArmSpec(
            tool="create_entities",
            args_template={
                "entities": [
                    {"name": _SEED_ENTITY, "entityType": "note", "observations": ["{payload}"]}
                ]
            },
        ),
        control_config=ControlConfig(
            consequential_tools=consequential,
            read_tool_names=("search_nodes", "open_nodes", "read_graph"),
            destructive_tools=("delete_entities", "delete_observations", "delete_relations"),
        ),
    )


@pytest.mark.asyncio
async def test_memory_store_is_confirm_only_through_the_planted_record() -> None:
    _register_memory()
    store = _MemoryStore()
    launcher = _MemoryLauncher(store)

    result = await _calibrate(launcher)

    # The probe can confirm a planted record appears; it cannot clear a call
    # that changed nothing. Never ``certified``, and not calibrated.
    assert result.status == calibration.STATUS_CONFIRM_ONLY
    assert result.calibrated is False
    assert "cannot clear a call that changed nothing" in result.detail
    # The consequential tools still showed nothing, so none is certified and
    # their code stays.
    assert result.certified_tools == ()
    assert result.reason_code == "MYL-INC-003"
    readback = result.tools[-1]
    assert readback.tool == "create_entities"
    assert readback.status == calibration.TOOL_READBACK
    # One plant serves the readback and the seed control (the store ignores a
    # second entity with the same name), and both pass.
    assert len(launcher.called("create_entities")) == 1
    assert result.seed_control.status == calibration.SEED_PASSED
    assert any("myl-cal-" in o for o in store.entities[_SEED_ENTITY])
    # The order: two baseline reads, the plant, then the positive and negative reads.
    names = [
        n
        for n, args in launcher.calls
        if n == "create_entities" or args.get("query") == _SEED_ENTITY
    ]
    plant_at = names.index("create_entities")
    assert names[plant_at - 2 : plant_at] == ["search_nodes", "search_nodes"]
    assert names[plant_at + 1 :] == ["search_nodes", "search_nodes"]


@pytest.mark.asyncio
async def test_memory_store_summary_is_confirm_only_and_not_calibrated() -> None:
    _register_memory()
    await _calibrate(_MemoryLauncher(_MemoryStore()))
    summary = calibration.summary_for(target_registry.resolve_target(FAMILY, None), None)
    assert summary is not None
    assert summary.status == "confirm_only"
    assert summary.calibrated is False
    assert summary.certified_tools == ()
    assert summary.reason_code == "MYL-INC-003"


@pytest.mark.asyncio
async def test_memory_store_with_no_writable_candidate_is_confirm_only() -> None:
    """No consequential candidate at all (go-memory before its schemas resolved)."""
    _register_memory(consequential=("no_such_tool",))
    tools = _memory_subset("create_entities", "search_nodes")
    result = await _calibrate(_MemoryLauncher(_MemoryStore(), tools))
    assert result.status == calibration.STATUS_CONFIRM_ONLY
    assert result.calibrated is False
    assert result.certified_tools == ()
    assert result.tools[-1].status == calibration.TOOL_READBACK


@pytest.mark.asyncio
async def test_echo_only_memory_store_is_not_calibrated() -> None:
    _register_memory()
    store = _MemoryStore()
    store.echo_only = True
    result = await _calibrate(_MemoryLauncher(store))
    assert result.calibrated is False
    assert result.status == calibration.STATUS_FAILED
    assert result.reason_code == "MYL-INC-003"
    assert result.tools[-1].tool == "create_entities"
    assert result.tools[-1].status == calibration.TOOL_FAILED
    assert result.seed_control.status == calibration.SEED_FAILED


@pytest.mark.asyncio
async def test_memory_store_whose_readback_never_changes_is_not_calibrated() -> None:
    _register_memory()
    store = _MemoryStore()
    store.frozen_search = True
    result = await _calibrate(_MemoryLauncher(store))
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"
    assert result.tools[-1].reason_code == "MYL-INC-003"
    assert "did not show the record planted" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_memory_store_whose_baseline_read_raises_is_not_calibrated() -> None:
    """The readback's first baseline read raises: nothing after it can certify."""
    _register_memory(consequential=("no_such_tool",))
    store = _MemoryStore()
    store.search_raises_once = True
    result = await _calibrate(
        _MemoryLauncher(store, _memory_subset("create_entities", "search_nodes"))
    )
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-003"
    assert result.tools[-1].is_read_failure is True


@pytest.mark.asyncio
async def test_memory_store_whose_reads_raise_before_the_plant_is_not_calibrated() -> None:
    """Every read before the plant raises. The seed control's baseline guard
    (#324 re-review) and the readback both refuse the reads after it."""
    _register_memory()
    store = _MemoryStore()
    store.search_raises_until_planted = True
    result = await _calibrate(_MemoryLauncher(store))
    assert result.calibrated is False
    assert result.status == calibration.STATUS_FAILED
    assert result.seed_control.status == calibration.SEED_FAILED
    assert result.seed_control.reason_code == "MYL-INC-006"


@pytest.mark.asyncio
async def test_readback_never_runs_after_the_probe_changed_on_its_own() -> None:
    """A negative-control failure is about the probe; a plant cannot fix it."""
    _register(EffectProbeSpec(verify_tool="list_outbox"))
    store = _Store()
    store.noisy_verify = True
    result = await _calibrate(_Launcher(store))
    assert result.reason_code == "MYL-INC-004"
    assert all(t.status != calibration.TOOL_READBACK for t in result.tools)
    assert all(t.tool != "remember" for t in result.tools)


@pytest.mark.asyncio
async def test_a_certifying_target_stays_certified_and_never_runs_the_readback() -> None:
    """A consequential tool's write shows up: ``certified``, as before."""
    _register()
    launcher = _Launcher(_Store())
    result = await _calibrate(launcher)
    assert result.status == calibration.STATUS_CERTIFIED
    assert result.calibrated is True
    assert result.reason_code is None
    assert result.certified_tools == ("send_email",)
    assert all(t.status != calibration.TOOL_READBACK for t in result.tools)


@pytest.mark.asyncio
async def test_confirm_only_never_calibrates_an_attempt_even_with_no_dispatch() -> None:
    """Every consumer reads ``confirm_only`` like a failed calibration: the
    per-attempt ``calibrated`` flag the verdict reads is computed from
    ``CalibrationResult.calibrated``, which is False whatever was dispatched."""
    _register_memory()
    result = await _calibrate(_MemoryLauncher(_MemoryStore()))
    cal = calibration.lookup(target_registry.resolve_target(FAMILY, None), None)
    assert cal is result
    for dispatched in (set(), {"add_observations"}, {"create_entities"}):
        assert not (cal.calibrated and dispatched <= set(cal.certified_tools))


# --- the discrimination read: a never-planted token through the verify slot ------
#
# The last read must show that the verify read can tell a planted record from
# one that was never planted: the same tool and argument slot, sent a
# never-planted token, must answer with a non-empty, non-error result that
# lacks it. The earlier check read through the fixed template, so the token
# never reached the server and an error, empty or echoing read still passed.


async def _memory_run(**flags: bool) -> tuple[calibration.CalibrationResult, _MemoryLauncher]:
    _register_memory()
    store = _MemoryStore()
    for flag, value in flags.items():
        setattr(store, flag, value)
    launcher = _MemoryLauncher(store)
    return await _calibrate(launcher), launcher


def _sent_a_fresh_token(launcher: _MemoryLauncher, result: calibration.CalibrationResult) -> bool:
    """The discrimination read went to the server with a token no plant carried."""
    planted = "".join(str(a) for a in launcher.called("create_entities"))
    queries = [str(a.get("query", "")) for a in launcher.called("search_nodes")]
    return any(q.startswith("myl-cal-") and q not in planted for q in queries)


@pytest.mark.asyncio
async def test_discrimination_read_that_errors_is_not_confirm_only() -> None:
    result, launcher = await _memory_run(search_error_when_no_match=True)
    assert _sent_a_fresh_token(launcher, result)
    assert result.status == calibration.STATUS_FAILED
    assert result.reason_code == "MYL-INC-003"
    assert "returned an error" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_discrimination_read_that_is_empty_is_not_confirm_only() -> None:
    result, launcher = await _memory_run(search_empty_when_no_match=True)
    assert _sent_a_fresh_token(launcher, result)
    assert result.status == calibration.STATUS_FAILED
    assert result.reason_code == "MYL-INC-003"
    assert "returned nothing" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_discrimination_read_that_echoes_the_token_is_not_confirm_only() -> None:
    result, launcher = await _memory_run(search_echoes_query=True)
    assert _sent_a_fresh_token(launcher, result)
    assert result.status == calibration.STATUS_FAILED
    assert result.reason_code == "MYL-INC-003"
    assert result.tools[-1].reason_code == "MYL-INC-004"
    assert "echoed" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_a_discriminating_read_gives_confirm_only() -> None:
    result, launcher = await _memory_run()
    assert _sent_a_fresh_token(launcher, result)
    assert result.status == calibration.STATUS_CONFIRM_ONLY
    assert result.tools[-1].status == calibration.TOOL_READBACK


@pytest.mark.asyncio
async def test_a_second_read_that_errors_after_the_plant_is_not_confirm_only() -> None:
    """``isError`` reads as an empty text. With a marker, "no change" only
    means "the marker did not grow", so an error read must still fail."""
    _register_memory(marker="calibration-marker")
    store = _MemoryStore()
    store.second_seed_read_errors = True
    result = await _calibrate(_MemoryLauncher(store))
    assert result.status == calibration.STATUS_FAILED
    assert "no longer showed the planted record" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_a_verify_template_with_no_string_slot_is_not_confirm_only() -> None:
    _register(
        EffectProbeSpec(verify_tool="read_graph", verify_args_template={}),
        seed_arm=SeedArmSpec(
            tool="create_entities",
            args_template={
                "entities": [
                    {"name": _SEED_ENTITY, "entityType": "note", "observations": ["{payload}"]}
                ]
            },
        ),
        control_config=ControlConfig(consequential_tools=("add_observations",)),
    )
    result = await _calibrate(_MemoryLauncher(_MemoryStore()))
    assert result.status == calibration.STATUS_FAILED
    assert "no argument to send a never-planted token" in result.tools[-1].detail


@pytest.mark.asyncio
async def test_readback_plants_itself_when_the_seed_control_has_no_recall_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(calibration, "_recall_candidates", lambda *a, **k: [])
    _register_memory()
    launcher = _MemoryLauncher(_MemoryStore())
    result = await _calibrate(launcher)
    assert result.seed_control.status == calibration.SEED_NOT_RUN
    assert len(launcher.called("create_entities")) == 1
    assert result.status == calibration.STATUS_CONFIRM_ONLY


@pytest.mark.asyncio
async def test_readback_self_plant_that_fails_the_schema_is_not_confirm_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(calibration, "_recall_candidates", lambda *a, **k: [])
    _register(
        EffectProbeSpec(verify_tool="search_nodes", verify_args_template={"query": _SEED_ENTITY}),
        seed_arm=SeedArmSpec(tool="create_entities", args_template={"wrong": "{payload}"}),
        control_config=ControlConfig(consequential_tools=("add_observations",)),
    )
    launcher = _MemoryLauncher(_MemoryStore())
    result = await _calibrate(launcher)
    assert result.status == calibration.STATUS_FAILED
    assert result.tools[-1].reason_code == "MYL-INC-005"
    assert launcher.called("create_entities") == []
