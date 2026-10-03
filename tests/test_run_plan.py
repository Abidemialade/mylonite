"""The pre-spend run plan (``mylonite.commands.run_plan``).

Before a live ``scan``, ``validate`` or ``gate``, the CLI prints the model, the
system-prompt source, the consequential tools the run may drive, the
``never_call`` list, and a line saying to run against a test instance. The
ordering tests follow ``tests/test_cost_estimate.py``: the plan must print
before the first live call, and never under ``--dry-run``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from tests.test_cost_estimate import _benign_response
from typer.testing import CliRunner

import mylonite.commands.run_plan as run_plan_module
from mylonite.cli import app
from mylonite.commands.run_plan import (
    DEFAULT_PROMPT_WARNING,
    TEST_INSTANCE_LINE,
    drivable_tools,
    prompt_source,
    run_plan_lines,
)
from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp.target_file import TargetFile
from mylonite.plugins._mcp.target_registry import ControlConfig

runner = CliRunner()
MODEL = "anthropic/claude-haiku-4-5-20251001"


def _tf(**fields: Any) -> TargetFile:
    return TargetFile(family="myapp", command="python", **fields)


def _lines(tf: TargetFile | None, target_id: str = "mcp:myapp", **kw: Any) -> list[str]:
    return run_plan_lines(
        planner="m", customiser="m", judge="m", target_file=tf, target_id=target_id, **kw
    )


# --- the block's content --------------------------------------------------------


def test_an_undeclared_prompt_is_named_as_the_default_and_warned_about() -> None:
    text, warning = prompt_source(_tf(), "mcp:myapp")
    assert "generic default" in text
    assert warning == DEFAULT_PROMPT_WARNING
    assert "system_prompt_file:" in warning
    assert DEFAULT_PROMPT_WARNING in _lines(_tf())


def test_a_declared_prompt_is_named_and_not_warned_about(tmp_path: Path) -> None:
    inline, warning = prompt_source(_tf(system_prompt="You triage mail."), "mcp:myapp")
    assert "declared inline" in inline
    assert warning is None
    from_file, warning = prompt_source(_tf(system_prompt_file=Path("prompt.txt")), "mcp:myapp")
    assert "prompt.txt" in from_file
    assert warning is None


def test_the_block_names_the_model_never_call_and_the_test_instance_line() -> None:
    tf = _tf(control_config=ControlConfig(never_call=("wipe_account",)))
    lines = _lines(tf)
    assert lines[0].startswith("Run plan")
    assert any("Model: m" in line for line in lines)
    assert any("never_call" in line and "wipe_account" in line for line in lines)
    assert TEST_INSTANCE_LINE in lines


def test_different_role_models_are_each_named() -> None:
    lines = run_plan_lines(
        planner="p", customiser="c", judge="j", target_file=None, target_id="reference:vulnerable"
    )
    assert any("planner p, customiser c, judge j" in line for line in lines)


def test_drivable_tools_come_from_the_tool_list_minus_never_call() -> None:
    tools = [
        ToolSpec(name="send_email", description="send an email"),
        ToolSpec(name="wipe_account", description="delete everything"),
        ToolSpec(name="read_note", description="read a note"),
    ]
    adapter = SimpleNamespace(
        _last_descriptor=SimpleNamespace(tools=tools),
        _spec=SimpleNamespace(control_config=None),
    )
    tf = _tf(
        control_config=ControlConfig(
            consequential_tools=("send_email", "wipe_account"), never_call=("wipe_account",)
        )
    )
    assert drivable_tools(target_file=tf, target_id="mcp:myapp", adapter=adapter) == "send_email"


def test_validate_names_the_recorded_calls_when_nothing_is_declared() -> None:
    out = drivable_tools(
        target_file=_tf(), target_id="mcp:myapp", recorded_tools=["send_email", "send_email"]
    )
    assert out.startswith("send_email (the calls the recorded finding made)")


def test_the_practice_app_drives_no_real_tool() -> None:
    assert drivable_tools(target_file=None, target_id="reference:vulnerable").startswith("none")


# --- CLI wiring: before the first live call, never under --dry-run ---------------


def _track_plan(monkeypatch: pytest.MonkeyPatch, order: list[str]) -> None:
    original = run_plan_module.print_run_plan

    def _tracking(**kwargs: Any) -> None:
        order.append("plan")
        original(**kwargs)

    monkeypatch.setattr(run_plan_module, "print_run_plan", _tracking)


def _track_llm(monkeypatch: pytest.MonkeyPatch, order: list[str]) -> None:
    import litellm

    async def _acompletion(*_a: Any, **_kw: Any) -> SimpleNamespace:
        order.append("llm")
        return _benign_response()

    def _completion(*_a: Any, **_kw: Any) -> SimpleNamespace:
        order.append("llm")
        return _benign_response()

    monkeypatch.setattr(litellm, "acompletion", _acompletion)
    monkeypatch.setattr(litellm, "completion", _completion)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret


def test_scan_dry_run_prints_no_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    result = runner.invoke(app, ["scan", "reference:vulnerable", "--model", MODEL, "--dry-run"])
    out = result.stderr or result.output
    assert "Run plan" not in out, out
    assert TEST_INSTANCE_LINE not in out


def test_scan_prints_the_plan_before_the_first_live_call(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    _track_plan(monkeypatch, order)
    _track_llm(monkeypatch, order)
    result = runner.invoke(app, ["scan", "reference:vulnerable", "--model", MODEL])
    out = result.stderr or result.output
    assert order and order[0] == "plan", order
    assert TEST_INSTANCE_LINE in out
    assert "practice app's built-in prompt" in out


def test_gate_prints_the_plan_before_the_first_live_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []
    _track_plan(monkeypatch, order)
    _track_llm(monkeypatch, order)
    result = runner.invoke(
        app, ["gate", "reference:vulnerable", "--model", MODEL, "--out", str(tmp_path / "g")]
    )
    assert order and order[0] == "plan", (order, result.stderr or result.output)
    assert TEST_INSTANCE_LINE in (result.stderr or result.output)


def test_scan_of_a_custom_target_prints_the_plan_before_calibration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Calibration's control writes are the first calls a live custom scan
    makes on the target, so the plan (and its default-prompt warning) must
    come before them."""
    order: list[str] = []
    _track_plan(monkeypatch, order)
    _track_llm(monkeypatch, order)

    def _calibrate(_adapter: Any) -> None:
        order.append("calibrate")
        raise typer.Exit(code=0)

    monkeypatch.setattr("mylonite.cli._calibrate_custom_target_now", _calibrate)
    monkeypatch.setattr(
        "mylonite.plugins.cli_targets.refuse_uncoverable_weakness_classes", lambda *a, **k: None
    )
    monkeypatch.setattr(run_plan_module, "_listed_tools", lambda _adapter: None)
    tf = tmp_path / "t.yaml"
    tf.write_text(
        "family: myapp\ncommand: echo\nargs: []\nweakness_classes: [W4]\n"
        "control_config:\n  consequential_tools: [send_email]\n  never_call: [wipe_account]\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["scan", "--target-file", str(tf), "--authorize", "myapp", "--model", MODEL]
    )
    out = result.stderr or result.output
    assert order[:2] == ["plan", "calibrate"], (order, out)
    assert "never_call (blocked before the server): wipe_account" in out
    assert "warning: no system prompt declared" in out


def test_validate_custom_prints_the_plan_before_the_live_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_cli import _sample_exploit

    from mylonite.cli import _validate_custom
    from mylonite.plugins._mcp import target_registry

    order: list[str] = []
    _track_plan(monkeypatch, order)

    def _preflight(*_a: Any, **_kw: Any) -> bool:
        order.append("preflight")
        return True

    monkeypatch.setattr("mylonite.cli._provider_preflight_direct", _preflight)

    class _StubValidator:
        def __init__(self, **_kw: Any) -> None:
            pass

        def validate(self, *_a: Any, **_k: Any) -> Any:
            return SimpleNamespace(kept=True, gating_legs=[])

    monkeypatch.setattr(
        "mylonite.plugins._reference.reference_validator.DifferentialValidator", _StubValidator
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    tf = tmp_path / "t.yaml"
    tf.write_text(
        "family: myapp\ncommand: echo\nargs: []\nweakness_classes: [W2]\n"
        "seed_arm:\n  tool: remember\n  args_template: {content: '{payload}'}\n",
        encoding="utf-8",
    )
    gen = SimpleNamespace(exploit=_sample_exploit().model_copy(update={"target_id": "mcp:myapp"}))
    target_registry.clear_runtime_targets()
    try:
        _validate_custom(gen, tf, 1, "anthropic", "anthropic/m", fast=False, authorize="myapp")
    finally:
        target_registry.clear_runtime_targets()
    assert order == ["plan", "preflight"], order


def test_the_scaffold_says_why_the_system_prompt_matters() -> None:
    from mylonite.plugins._mcp.scaffold import _render_target_scaffold

    text = _render_target_scaffold(
        tf=_tf(), tool_names=[], suggested_weaknesses=[], system_prompt_file=None
    )
    assert "some weaknesses only show under it" in text
    assert "# system_prompt_file: prompt.txt" in text
