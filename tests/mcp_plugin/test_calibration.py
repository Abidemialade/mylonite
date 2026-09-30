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


def _text(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


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
    # A schema failure stops the controls before any write or read.
    assert launcher.called("send_email") == []
    assert launcher.called("read_file") == []


@pytest.mark.asyncio
async def test_control_write_that_fails_the_schema_is_inc_005() -> None:
    tools = dict(_DEFAULT_TOOLS)
    tools["send_email"] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "n": {"type": "integer"},
        },
        "required": ["to", "body", "n"],
    }
    _register()
    launcher = _Launcher(_Store(), tools)
    result = await _calibrate(launcher)
    assert result.calibrated is False
    assert result.reason_code == "MYL-INC-005"
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
