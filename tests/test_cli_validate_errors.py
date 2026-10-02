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
