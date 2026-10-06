"""`mylonite validate` stops with one line and the right exit code when a run
cannot reach a verdict: a spent LLM budget exits 3, a target that never came
up exits 2. Neither prints a traceback. The validator is a test double; no
request leaves the machine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.test_cli import _generated_dir
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG
from mylonite.plugins._reference import reference_validator
from mylonite.plugins._reference.reference_validator import TargetLaunchError
from mylonite.scan._llm import BudgetExceededError, LLMRequestCeilingError

runner = CliRunner()


def _raising_validator(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    class _Raises:
        def __init__(self, **_: Any) -> None:
            pass

        def validate(self, *_: Any, **__: Any) -> Any:
            raise exc

    monkeypatch.setattr(reference_validator, "DifferentialValidator", _Raises)


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> Any:
    out_dir = _generated_dir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    monkeypatch.setattr("mylonite.cli._provider_preflight", lambda *_, **__: True)
    _raising_validator(monkeypatch, exc)
    return runner.invoke(app, ["validate", str(out_dir)])


def test_a_spent_budget_exits_3_with_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(tmp_path, monkeypatch, BudgetExceededError("cap of 50 reached"))

    assert result.exit_code == EXIT_BUDGET, result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, BudgetExceededError)
    lines = [line for line in result.output.splitlines() if "MYL-ABT-001" in line]
    assert len(lines) == 1, result.output
    assert "no verdict" in lines[0]


def test_the_request_ceiling_is_reported_once_by_the_root_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(tmp_path, monkeypatch, LLMRequestCeilingError(7))

    assert result.exit_code == EXIT_BUDGET, result.output
    assert "Traceback" not in result.output
    assert result.output.count("MYL-ABT-001") == 1, result.output
    assert "LLM request ceiling of 7 reached" in result.output
    assert "budget exhausted" not in result.output


def test_a_target_that_never_came_up_exits_2_with_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(tmp_path, monkeypatch, TargetLaunchError("the target could not be described"))

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, TargetLaunchError)
    lines = [line for line in result.output.splitlines() if "MYL-ABT-006" in line]
    assert len(lines) == 1, result.output
    assert "could not be described" in lines[0]


def test_a_target_that_went_down_part_way_does_not_blame_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exc = TargetLaunchError("server exited (after 2 of 3 runs finished)", completed_runs=2)
    result = _invoke(tmp_path, monkeypatch, exc)

    assert result.exit_code == EXIT_CONFIG, result.output
    line = next(line for line in result.output.splitlines() if "MYL-ABT-006" in line)
    assert "went down part-way" in line
    assert "check the target file" not in line


def test_the_budget_line_names_no_flag_validate_lacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(tmp_path, monkeypatch, BudgetExceededError("cap of 50 reached"))

    line = next(line for line in result.output.splitlines() if "MYL-ABT-001" in line)
    assert "--iterations" in line
    assert "Raise the budget" not in line


def test_gate_reports_a_target_that_did_not_come_up_in_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The validator's launch failure escapes the gate orchestrator; the gate
    handler maps it to exit 2 with one line, never a traceback."""
    from tests.test_cli import (
        _SERVER_LAYER_TARGET_YAML,
        _canned_finding_result,
        _sample_exploit,
        _skip_uncoverable_refusal,
    )

    from mylonite.plugins._mcp import target_registry
    from mylonite.scan.engine import ScanEngine

    _skip_uncoverable_refusal(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    target_registry.clear_runtime_targets()
    exploit = _sample_exploit().model_copy(update={"target_id": "mcp:myapp-server"})
    canned = _canned_finding_result("mcp:myapp-server", exploit)

    async def _fake_run(self: Any) -> Any:
        return canned

    monkeypatch.setattr(ScanEngine, "run", _fake_run)
    _raising_validator(monkeypatch, TargetLaunchError("the target could not be described"))

    target_yaml = tmp_path / "target.yaml"
    target_yaml.write_text(_SERVER_LAYER_TARGET_YAML, encoding="utf-8")
    try:
        result = runner.invoke(
            app,
            [
                "gate",
                "--target-file",
                str(target_yaml),
                "--authorize",
                "myapp-server",
                "--out",
                str(tmp_path / "gate_out"),
                "--no-workflows",
            ],
        )
    finally:
        target_registry.clear_runtime_targets()

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, TargetLaunchError)
    lines = [line for line in result.output.splitlines() if "MYL-ABT-006" in line]
    assert len(lines) == 1, result.output
    assert "later findings were not validated" in lines[0]
    assert "gate_out" in lines[0]


def test_an_unrecordable_fixtures_folder_exits_2_before_any_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fixtures folder recorded in an older replay-key format is refused
    before the provider pre-flight, so no paid call is spent on a run that
    could not record."""
    out_dir = _generated_dir(tmp_path)
    fixtures = out_dir / "fixtures"
    fixtures.mkdir(exist_ok=True)
    (fixtures / "_meta.json").write_text('{"cache_key_version": 2}', encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    calls: list[str] = []
    monkeypatch.setattr(
        "mylonite.cli._provider_preflight", lambda *_, **__: calls.append("preflight") or True
    )
    _raising_validator(monkeypatch, AssertionError("the validator must not run"))

    result = runner.invoke(app, ["validate", str(out_dir)])

    assert result.exit_code == EXIT_CONFIG, result.output
    assert calls == []
    assert "Traceback" not in result.output
    assert "cache_key_version=2" in result.output


def test_a_fixture_error_mid_run_exits_2_with_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mylonite._replay import FixtureConflictError

    result = _invoke(tmp_path, monkeypatch, FixtureConflictError("key collided"))

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "Traceback" not in result.output
    assert "recording the replay fixtures failed" in result.output
