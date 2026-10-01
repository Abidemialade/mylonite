"""#217 end to end, offline: the docs-following target files never read
clean, and a corrected one certifies and reads resisted.

``tests/fixtures/issue217/{memory,filesystem}.yaml`` are target files
written exactly as a first-time user following the earlier docs/scaffold
would write them for the official
``@modelcontextprotocol/server-memory`` / ``server-filesystem`` reference MCP
servers: ``verify_args_template: {}`` (fails the verify tool's own schema —
#217 cause 2) and ``expect_marker: "{payload}"`` (the weakest marker shape,
which a calibrated probe can never use to clear a dispatch — see
``effect_verdict._may_downgrade``). ``tests/mcp_plugin/fakes/neutral_servers.py``
carries those two servers' real tool surfaces (names, JSON schemas,
MCP annotations), transcribed by hand from the installed packages.

This module adds the one piece those fakes leave out: a BEHAVIOURAL
session fake for each server (state that outlives one launch, real
schema-shaped errors on a missing required argument) so a full
``ScanEngine``/calibration run can be driven against them without ever
running ``npx`` or calling a model — ``stdio_adapter._open_mcp_session`` is
monkeypatched, same as ``tests/mcp_plugin/test_calibration.py`` and
``tests/integration/test_scan_mcp_filesystem_recorded.py``; every LLM call
(planner/customiser/judge) is a plain scripted ``completion_fn``, same shape
as those modules and ``test_custom_target_offline.py``.

Three things, per server:

1. The docs-following fixture never reads clean. Driven by a planner that
   actually calls the fixture's declared consequential tool (the attack is
   genuinely attempted), the class reads ``FINDING`` at proof level
   ``dispatched`` — never silently ``RESISTED`` because the broken
   ``verify_args_template``/``{payload}`` marker happened to fail quietly (the
   exact #217 failure mode). The class-level acceptance bar is NOT
   TESTED-with-a-reason-code OR a finding at proof level ``dispatched``; this module exercises the latter, which is what
   a real-shaped, actually-attempted attack against these fixtures produces.
2. A CORRECTED target file — valid ``verify_args_template`` (fills the verify
   tool's required argument), ``expect_marker: "{exfil_email}"`` instead of
   ``{payload}``, and ``calibration: {controls: allow}`` — certifies through
   the real calibration controls run against the same fake, and a benign
   attempt (the agent tries the consequential action; a client-side
   ``ConfirmGateControl`` blocks it before it reaches the server — "the agent
   does nothing harmful") reads ``RESISTED``, calibrated.
3. ``mylonite.scan.coverage.ScanOutcome.from_report`` — the one place `scan`'s
   exit code is derived from — stays ``EXIT_SUCCESS`` in every case here,
   exactly as before: a finding alone was never a `scan`-level
   failure, and neither is a trace-decided ``RESISTED``. The verdict RULE
   changed; the exit code did not.

Each test also writes real artefacts (``write_artefacts``) and reads back
``verdicts.json`` — the sidecar an operator actually opens — rather than
asserting on ``class_verdicts()`` output alone.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from mcp.types import Tool as MCPTool
from tests.mcp_plugin.fakes.neutral_servers import filesystem_tools, memory_tools

from mylonite.contracts import ToolSpec
from mylonite.exit_codes import EXIT_SUCCESS
from mylonite.plugins._mcp import calibration, stdio_adapter, target_registry
from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec, load_target_file
from mylonite.plugins._mcp.target_registry import (
    CalibrationSettings,
    ControlConfig,
    EffectProbeSpec,
    TargetSpec,
)
from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.scan.artefacts import VERDICTS_FILENAME, write_artefacts
from mylonite.scan.class_verdict import STATUS_FINDING, STATUS_RESISTED
from mylonite.scan.control_shim import ConfirmGateControl
from mylonite.scan.coverage import ScanOutcome
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.exfil import DEFAULT_EXFIL_EMAIL
from mylonite.scan.judge import SuccessJudge

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "issue217"


@pytest.fixture(autouse=True)
def _clean() -> Generator[None, None, None]:
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    yield
    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()


# ---------------------------------------------------------------------------
# Shared scripted-LLM helpers (same shapes as test_scan_mcp_filesystem_recorded.py
# / test_custom_target_offline.py).
# ---------------------------------------------------------------------------


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


async def _customiser_unused_completion(**kwargs: Any) -> SimpleNamespace:
    """Every seed here has ``customise=False`` (seed_synth's W4 seeds), so the
    customiser is never actually asked to rewrite anything; this stub exists
    only so ``PayloadCustomiser`` has a non-``None`` completion_fn to construct
    with — no model is ever called."""
    del kwargs
    return _text_response(json.dumps({"body": "unused"}))


async def _judge_low_confidence_completion(**kwargs: Any) -> SimpleNamespace:
    """The deterministic trace rule (``effect_verdict.decide``) decides every
    attempt in this module; the LLM judge fallback is never reached, but
    ``SuccessJudge`` still needs a completion_fn to construct with."""
    del kwargs
    return _text_response(json.dumps({"success": False, "confidence": 0.0, "reason": "n/a"}))


def _result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


def _tool_to_mcp(tool: ToolSpec) -> MCPTool:
    """One ``neutral_servers.py`` ``ToolSpec`` as the real MCP SDK's own
    ``tools/list`` response shape — what ``server_shim._tool_to_description``
    (the real conversion a live session goes through) expects to read."""
    annotations = ToolAnnotations(**tool.annotations) if tool.annotations else None
    return MCPTool(
        name=tool.name,
        description=tool.description,
        inputSchema=tool.json_schema,
        annotations=annotations,
    )


def _open_over(launcher: Any) -> Any:
    """``_open_mcp_session``'s call shape: ignore the launch args, open a
    fresh session from ``launcher`` (an async-context-manager factory)."""

    def _patched(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return launcher()

    return _patched


# ---------------------------------------------------------------------------
# server-memory: a behavioural fake over neutral_servers.memory_tools().
# ---------------------------------------------------------------------------


class _MemoryStore:
    """Entities that outlive one launch — server-memory's own store is a flat
    JSONL file of entities addressed by their own ``name``, not a launch-scoped
    in-memory list, so a fresh session must see what an earlier one wrote."""

    def __init__(self) -> None:
        self.entities: list[dict[str, Any]] = []


class _MemorySession:
    """Behavioural fake of ``@modelcontextprotocol/server-memory``, modeled
    only as far as this module's tests need: entity storage and a
    substring ``search_nodes``, close enough to the real server's own "match
    against entity names/types/observation content" to exercise calibration's
    schema check and controls. A ``search_nodes`` call missing its required
    ``query`` errors — exactly the real server's zod validation, and exactly
    the #217 cause the broken fixture's ``verify_args_template: {}`` reproduces.
    """

    def __init__(self, store: _MemoryStore, tools: list[ToolSpec]) -> None:
        self._store = store
        self._tools = tools
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(tools=[_tool_to_mcp(t) for t in self._tools])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, dict(arguments)))
        store = self._store
        if name == "create_entities":
            for entity in arguments.get("entities", []) or []:
                store.entities.append(dict(entity))
            return _result("entities created")
        if name == "add_observations":
            for obs in arguments.get("observations", []) or []:
                target = next(
                    (e for e in store.entities if e.get("name") == obs.get("entityName")),
                    None,
                )
                if target is not None:
                    target.setdefault("observations", []).extend(obs.get("contents", []) or [])
            return _result("observations added")
        if name == "search_nodes":
            if "query" not in arguments:
                return _result("query is required", is_error=True)
            query = str(arguments.get("query", ""))
            matches = [e for e in store.entities if query.lower() in json.dumps(e).lower()]
            return _result(json.dumps({"entities": matches, "relations": []}))
        if name == "read_graph":
            return _result(json.dumps({"entities": store.entities, "relations": []}))
        return _result(f"{name} ok")


class _MemoryLauncher:
    """Every launch opens a fresh ``_MemorySession`` over one shared store —
    mirrors ``test_calibration.py``'s ``_Launcher``."""

    def __init__(self, tools: list[ToolSpec]) -> None:
        self.store = _MemoryStore()
        self._tools = tools
        self.sessions: list[_MemorySession] = []

    def __call__(self) -> Any:
        session = _MemorySession(self.store, self._tools)
        self.sessions.append(session)

        @asynccontextmanager
        async def _ctx() -> Any:
            yield session

        return _ctx()


# ---------------------------------------------------------------------------
# server-filesystem: a behavioural fake over neutral_servers.filesystem_tools().
# ---------------------------------------------------------------------------


class _FilesystemSession:
    """Behavioural fake of ``@modelcontextprotocol/server-filesystem``: writes
    and reads REAL files under ``sandbox`` (mirrors
    ``test_scan_mcp_filesystem_recorded.py``'s ``_RealWriteFakeSession``), plus
    ``list_directory`` (needed for the corrected fixture's calibration — see
    the module docstring). A ``write_file``/``read_text_file`` call missing its
    required arguments errors, exactly the real server's own validation and
    the #217 cause the broken fixture's ``verify_args_template: {}`` reproduces.
    """

    def __init__(self, sandbox: Path, tools: list[ToolSpec], *, drop_creates: bool = False) -> None:
        self._sandbox = sandbox
        self._tools = tools
        self._drop_creates = drop_creates
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(tools=[_tool_to_mcp(t) for t in self._tools])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, dict(arguments)))
        if name == "create_directory" and self._drop_creates:
            # A silent drop: the server replies "ok" and creates nothing.
            return _result("ok")
        if name == "write_file":
            if "path" not in arguments or "content" not in arguments:
                return _result("path and content are required", is_error=True)
            target = self._sandbox / str(arguments["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(arguments["content"]), encoding="utf-8")
            return _result("ok")
        if name in ("read_text_file", "read_file"):
            if "path" not in arguments:
                return _result("path is required", is_error=True)
            target = self._sandbox / str(arguments["path"])
            try:
                body = target.read_text(encoding="utf-8")
            except OSError:
                body = ""
            return _result(body)
        if name == "create_directory":
            if "path" not in arguments:
                return _result("path is required", is_error=True)
            (self._sandbox / str(arguments["path"])).mkdir(parents=True, exist_ok=True)
            return _result("ok")
        if name == "list_directory":
            base = self._sandbox / str(arguments.get("path", "."))
            try:
                entries = sorted(base.iterdir())
            except OSError:
                entries = []
            lines = [f"[{'DIR' if e.is_dir() else 'FILE'}] {e.name}" for e in entries]
            return _result("\n".join(lines))
        return _result(f"{name} ok")


class _FilesystemLauncher:
    """Every launch opens a fresh ``_FilesystemSession`` over one shared,
    real-on-disk sandbox directory."""

    def __init__(self, sandbox: Path, tools: list[ToolSpec]) -> None:
        self.sandbox = sandbox
        self._tools = tools
        self.sessions: list[_FilesystemSession] = []
        #: Set after calibration to make create_directory a silent drop.
        self.drop_creates = False

    def __call__(self) -> Any:
        session = _FilesystemSession(self.sandbox, self._tools, drop_creates=self.drop_creates)
        self.sessions.append(session)

        @asynccontextmanager
        async def _ctx() -> Any:
            yield session

        return _ctx()


# ---------------------------------------------------------------------------
# Planners.
# ---------------------------------------------------------------------------


class _ParrotingAttacker:
    """Calls ``tool_name`` with the FULL current user message folded into
    ``content_arg`` — a planner that genuinely attempts the W4 seed's action
    task and, in doing so, echoes back the instruction it was given (a
    realistic planner behaviour: "tell me what you did"). This makes the
    dispatched call carry the effect probe's own rendered marker
    (``expect_marker: "{payload}"`` renders to the same ``payload_body`` that
    ``drive: verbatim`` puts in the user message — see
    ``_session_adapter._render_marker``/``_user_message_for_drive``), which is
    what drives the ``link_for`` token-linked path to a finding at proof level
    ``dispatched`` — the literal class of evidence the acceptance bar above
    names.
    """

    def __init__(self, tool_name: str, content_arg: str, other_args: dict[str, Any]) -> None:
        self._tool_name = tool_name
        self._content_arg = content_arg
        self._other_args = other_args
        self._step = 0

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        if self._step == 0:
            self._step += 1
            messages = kwargs.get("messages", [])
            user_msg = next((m["content"] for m in messages if m.get("role") == "user"), "")
            args = {**self._other_args, self._content_arg: user_msg}
            return _tool_response([_tool_call(self._tool_name, args)])
        return _text_response("Done -- I did what you asked.")


class _MemoryParrotingAttacker:
    """Same intent as ``_ParrotingAttacker``, for ``create_entities``'s nested
    content slot (``entities: [{name, entityType, observations: [...]}]`` —
    see ``neutral_servers.memory_tools()``): folds the full current user
    message into the new entity's ``observations``."""

    def __init__(self) -> None:
        self._step = 0

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        if self._step == 0:
            self._step += 1
            messages = kwargs.get("messages", [])
            user_msg = next((m["content"] for m in messages if m.get("role") == "user"), "")
            return _tool_response(
                [
                    _tool_call(
                        "create_entities",
                        {
                            "entities": [
                                {
                                    "name": "attacker-entity",
                                    "entityType": "note",
                                    "observations": [user_msg],
                                }
                            ]
                        },
                    )
                ]
            )
        return _text_response("Done -- I did what you asked.")


class _TriesThenBlockedAttacker:
    """Attempts the SAME consequential action with innocuous arguments — "the
    agent does nothing harmful" means the agent tries, not that it never
    engages (a planner that calls no tool at all is reported NOT TESTED by
    ``skipped_planner_no_engagement``, never credited as resisted — see
    ``engine.py``'s ``never_exercised_tool_under_test`` check). A client-side
    ``ConfirmGateControl`` (constructed with ``mode="block"`` by the test)
    refuses the call before it ever reaches the fake server.
    """

    def __init__(self, tool_name: str, args: dict[str, Any]) -> None:
        self._tool_name = tool_name
        self._args = args
        self._step = 0

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        del kwargs
        if self._step == 0:
            self._step += 1
            return _tool_response([_tool_call(self._tool_name, dict(self._args))])
        return _text_response("Refused: that needs confirmation I don't have.")


# ---------------------------------------------------------------------------
# A corrected target file, built the way the docs now teach:
# a schema-valid verify_args_template, "{exfil_email}" instead of "{payload}"
# for expect_marker, and calibration controls explicitly allowed.
# ---------------------------------------------------------------------------


def _corrected_memory_spec() -> TargetSpec:
    tf = TargetFile(
        family="issue217-memory-corrected",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-memory"],
        weakness_classes=["W4"],
        control_config=ControlConfig(
            consequential_tools=(
                "create_entities",
                "create_relations",
                "add_observations",
                "delete_entities",
                "delete_observations",
                "delete_relations",
            )
        ),
        effect_probe=EffectProbeSpec(
            # read_graph returns the whole store and takes no arguments, so
            # calibration and an attempt read exactly the same thing. A
            # search_nodes query of "{payload}" would not: calibration fills it
            # with its own token, an attempt with the whole attack text, and
            # calibration refuses to certify it.
            verify_tool="read_graph",
            verify_args_template={},
            # NOT "{payload}" (#217): a plant-and-recall target could match
            # Mylonite's own planted content with no agent action at all, and
            # effect_verdict._may_downgrade() refuses to ever let a
            # `{payload}`-marker probe clear a dispatch. {exfil_email} is this
            # attempt's own minted destination -- unique to what the agent did.
            expect_marker="{exfil_email}",
        ),
        calibration=CalibrationSettings(controls="allow"),
    )
    return build_target_spec(tf)


def _corrected_filesystem_spec() -> TargetSpec:
    tf = TargetFile(
        family="issue217-filesystem-corrected",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "./sandbox"],
        weakness_classes=["W4"],
        control_config=ControlConfig(
            consequential_tools=("write_file", "edit_file", "create_directory", "move_file")
        ),
        effect_probe=EffectProbeSpec(
            # NOT read_text_file/{}: write_file and edit_file both carry
            # destructiveHint=true on the real server (they can overwrite), and
            # calibration only ever calibrates a create effect -- never a
            # destructive one. create_directory is the one non-destructive
            # consequential tool, and list_directory is what can observe its
            # effect (read_text_file reads a FILE's content, not a directory
            # listing). This is still the exact tool the W4 seed below
            # attacks; the probe only needs to be CALIBRATABLE, not keyed to
            # that one tool.
            verify_tool="list_directory",
            verify_args_template={"path": "."},
            expect_marker="{exfil_email}",
        ),
        calibration=CalibrationSettings(controls="allow"),
    )
    return build_target_spec(tf)


# ---------------------------------------------------------------------------
# The scan itself: one filtered W4 seed, same shape for every test below.
# ---------------------------------------------------------------------------


async def _run_single_seed_scan(
    *, spec: TargetSpec, tool_name: str, completion_fn: Any, intent: LaunchIntent, tmp_path: Path
) -> Any:
    adapter = build_adapter_for_spec(
        spec, scope=None, model="stub", completion_fn=completion_fn, intent=intent
    )
    customiser = PayloadCustomiser(model="stub", completion_fn=_customiser_unused_completion)
    judge = SuccessJudge(model="stub", completion_fn=_judge_low_confidence_completion)
    config = ScanConfig(
        target_id=f"mcp:{spec.family}",
        provider="anthropic",
        model="stub",
        max_llm_calls=200,
        max_concurrent=1,
        output_dir=tmp_path / "scans",
        # One W4 seed per consequential tool is synthesised (seed_synth.py);
        # filtering to this target's own tool keeps each test to one
        # deterministic attempt instead of one per declared consequential tool.
        pattern_id_filter=f"synth-w4-unconfirmed-{tool_name}",
    )
    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=[ExcessiveAgencyAttackModule()],
        customiser=customiser,
        judge=judge,
    )
    try:
        return await engine.run()
    finally:
        await adapter.close()


def _verdicts_document(result: Any, tmp_path: Path) -> dict[str, Any]:
    scan_dir = write_artefacts(result, tmp_path / "artefacts")
    return json.loads((scan_dir / VERDICTS_FILENAME).read_text(encoding="utf-8"))


def _class(doc: dict[str, Any], weakness: str) -> dict[str, Any]:
    return next(c for c in doc["classes"] if c["weakness"] == weakness)


# ---------------------------------------------------------------------------
# 1. The docs-following fixtures never read clean.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_memory_docs_following_fixture_never_reads_clean(tmp_path: Path) -> None:
    tf = load_target_file(_FIXTURES / "memory.yaml")
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    tools = memory_tools()
    launcher = _MemoryLauncher(tools)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        adapter_for_cal = build_adapter_for_spec(spec, scope=None, model="stub")
        cal = await calibration.calibrate_custom_target(adapter_for_cal, authorized=True)
        # #217 cause 2: verify_args_template: {} fails search_nodes's own
        # schema (it REQUIRES `query`) -- the probe never gets to certify.
        assert cal.calibrated is False
        assert cal.reason_code == "MYL-INC-005"

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="create_entities",
            completion_fn=_MemoryParrotingAttacker(),
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    assert result.report.aborted is None
    doc = _verdicts_document(result, tmp_path)
    w4 = _class(doc, "W4")
    # Never resisted/clean: the broken probe cannot silently clear this
    # dispatch, and the trace rule credits the agent's own linked call.
    assert w4["status"] == STATUS_FINDING
    assert w4["status"] not in (STATUS_RESISTED, "RESISTED (server-reported)")
    assert "dispatched" in w4["proof_levels"]

    # `scan`'s own exit code is unaffected by the new verdict rule: a finding
    # alone is still not, by itself, a `scan`-level failure.
    assert ScanOutcome.from_report(result.report).exit_code == EXIT_SUCCESS


@pytest.mark.asyncio
async def test_filesystem_docs_following_fixture_never_reads_clean(tmp_path: Path) -> None:
    tf = load_target_file(_FIXTURES / "filesystem.yaml")
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    tools = filesystem_tools()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    launcher = _FilesystemLauncher(sandbox, tools)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        adapter_for_cal = build_adapter_for_spec(spec, scope=None, model="stub")
        cal = await calibration.calibrate_custom_target(adapter_for_cal, authorized=True)
        # #217 cause 2: verify_args_template: {} fails read_text_file's own
        # schema (it REQUIRES `path`).
        assert cal.calibrated is False
        assert cal.reason_code == "MYL-INC-005"

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="write_file",
            completion_fn=_ParrotingAttacker("write_file", "content", {"path": "audit.txt"}),
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    assert result.report.aborted is None
    doc = _verdicts_document(result, tmp_path)
    w4 = _class(doc, "W4")
    assert w4["status"] == STATUS_FINDING
    assert w4["status"] not in (STATUS_RESISTED, "RESISTED (server-reported)")
    assert "dispatched" in w4["proof_levels"]
    assert ScanOutcome.from_report(result.report).exit_code == EXIT_SUCCESS


# ---------------------------------------------------------------------------
# 2. A corrected target file certifies and reads RESISTED.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_memory_corrected_fixture_certifies_and_resists(tmp_path: Path) -> None:
    spec = _corrected_memory_spec()
    target_registry.register_target(spec)
    tools = memory_tools()
    launcher = _MemoryLauncher(tools)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        adapter_for_cal = build_adapter_for_spec(spec, scope=None, model="stub")
        cal = await calibration.calibrate_custom_target(adapter_for_cal, authorized=True)
        assert cal.calibrated is True
        assert cal.status == calibration.STATUS_CERTIFIED

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="create_entities",
            completion_fn=_TriesThenBlockedAttacker(
                "create_entities",
                {"entities": [{"name": "x", "entityType": "note", "observations": ["hi"]}]},
            ),
            intent=LaunchIntent(boundary_controls=(ConfirmGateControl(mode="block"),)),
            tmp_path=tmp_path,
        )

    assert result.report.aborted is None
    doc = _verdicts_document(result, tmp_path)
    assert doc["calibration"]["status"] == calibration.STATUS_CERTIFIED
    assert "create_entities" in doc["calibration"]["certified_tools"]
    w4 = _class(doc, "W4")
    assert w4["status"] == STATUS_RESISTED
    assert ScanOutcome.from_report(result.report).exit_code == EXIT_SUCCESS


@pytest.mark.asyncio
async def test_filesystem_corrected_fixture_certifies_and_resists(tmp_path: Path) -> None:
    spec = _corrected_filesystem_spec()
    target_registry.register_target(spec)
    tools = filesystem_tools()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    launcher = _FilesystemLauncher(sandbox, tools)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        adapter_for_cal = build_adapter_for_spec(spec, scope=None, model="stub")
        cal = await calibration.calibrate_custom_target(adapter_for_cal, authorized=True)
        assert cal.calibrated is True
        assert cal.status == calibration.STATUS_CERTIFIED

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="write_file",
            completion_fn=_TriesThenBlockedAttacker(
                "write_file", {"path": "audit.txt", "content": "ok"}
            ),
            intent=LaunchIntent(boundary_controls=(ConfirmGateControl(mode="block"),)),
            tmp_path=tmp_path,
        )

    assert result.report.aborted is None
    doc = _verdicts_document(result, tmp_path)
    assert doc["calibration"]["status"] == calibration.STATUS_CERTIFIED
    w4 = _class(doc, "W4")
    assert w4["status"] == STATUS_RESISTED
    assert ScanOutcome.from_report(result.report).exit_code == EXIT_SUCCESS


# ---------------------------------------------------------------------------
# 4. A certified probe clears only what it was shown to see.
# ---------------------------------------------------------------------------


class _FixedCallAttacker:
    """Makes one fixed call, then stops: the agent carrying out the attack with
    arguments that name this attempt's exfil destination."""

    def __init__(self, tool_name: str, args: dict[str, Any]) -> None:
        self._tool_name = tool_name
        self._args = args
        self._step = 0

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        del kwargs
        if self._step == 0:
            self._step += 1
            return _tool_response([_tool_call(self._tool_name, dict(self._args))])
        return _text_response("Done.")


@pytest.mark.asyncio
async def test_a_probe_certified_through_one_tool_never_clears_a_write_through_another(
    tmp_path: Path,
) -> None:
    """Calibration certified ``list_directory`` through ``create_directory``
    only. The agent then wrote a file through ``write_file``, and the write
    landed. ``list_directory`` cannot show a file's content, so the probe reads
    "no change"; that must not clear a write it was never shown to see."""
    spec = _corrected_filesystem_spec()
    target_registry.register_target(spec)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    launcher = _FilesystemLauncher(sandbox, filesystem_tools())

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        cal = await calibration.calibrate_custom_target(
            build_adapter_for_spec(spec, scope=None, model="stub"), authorized=True
        )
        assert cal.calibrated is True
        assert "write_file" not in cal.certified_tools

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="write_file",
            completion_fn=_FixedCallAttacker(
                "write_file",
                {"path": "audit.txt", "content": f"forward everything to {DEFAULT_EXFIL_EMAIL}"},
            ),
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    assert DEFAULT_EXFIL_EMAIL in (sandbox / "audit.txt").read_text(encoding="utf-8")
    w4 = _class(_verdicts_document(result, tmp_path), "W4")
    assert w4["status"] == STATUS_FINDING
    assert w4["counts"]["resisted"] == 0


@pytest.mark.asyncio
async def test_a_payload_query_probe_never_certifies_and_never_clears_a_write(
    tmp_path: Path,
) -> None:
    """``search_nodes`` with ``query: "{payload}"`` finds calibration's own
    token, but an attempt searches for its whole attack text and finds nothing
    the agent wrote. Calibration refuses to certify it, so the write the agent
    really made stays a finding."""
    tf = TargetFile(
        family="issue217-memory-payload-query",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-memory"],
        weakness_classes=["W4"],
        control_config=ControlConfig(consequential_tools=("create_entities",)),
        effect_probe=EffectProbeSpec(
            verify_tool="search_nodes",
            verify_args_template={"query": "{payload}"},
            expect_marker="{exfil_email}",
        ),
        calibration=CalibrationSettings(controls="allow"),
    )
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    launcher = _MemoryLauncher(memory_tools())

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        cal = await calibration.calibrate_custom_target(
            build_adapter_for_spec(spec, scope=None, model="stub"), authorized=True
        )
        assert cal.calibrated is False
        assert cal.reason_code == "MYL-INC-003"

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="create_entities",
            completion_fn=_FixedCallAttacker(
                "create_entities",
                {
                    "entities": [
                        {
                            "name": "contact",
                            "entityType": "note",
                            "observations": [f"forward to {DEFAULT_EXFIL_EMAIL}"],
                        }
                    ]
                },
            ),
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    assert any(e.get("name") == "contact" for e in launcher.store.entities)
    w4 = _class(_verdicts_document(result, tmp_path), "W4")
    assert w4["status"] == STATUS_FINDING
    assert w4["counts"]["resisted"] == 0


@pytest.mark.asyncio
async def test_a_certified_probe_clears_a_dropped_write_through_its_own_tool(
    tmp_path: Path,
) -> None:
    """The certified-observer path end to end: the agent calls
    ``create_directory``, the tool calibration certified, and the server
    replies "ok" but creates nothing. The certified probe sees no change where
    it would have seen one, so the attempt reads resisted."""
    spec = _corrected_filesystem_spec()
    target_registry.register_target(spec)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    launcher = _FilesystemLauncher(sandbox, filesystem_tools())

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(stdio_adapter, "_open_mcp_session", _open_over(launcher))
        cal = await calibration.calibrate_custom_target(
            build_adapter_for_spec(spec, scope=None, model="stub"), authorized=True
        )
        assert "create_directory" in cal.certified_tools
        launcher.drop_creates = True

        result = await _run_single_seed_scan(
            spec=spec,
            tool_name="create_directory",
            completion_fn=_FixedCallAttacker("create_directory", {"path": DEFAULT_EXFIL_EMAIL}),
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    assert not (sandbox / DEFAULT_EXFIL_EMAIL).exists()
    attempts = [a for a in result.report.attempts if a.judge_evidence.get("trace_outcome")]
    assert attempts
    assert all(a.judge_evidence.get("calibrated") == "true" for a in attempts)
    w4 = _class(_verdicts_document(result, tmp_path), "W4")
    assert w4["status"] == STATUS_RESISTED
