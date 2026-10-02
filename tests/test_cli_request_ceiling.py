"""CLI behaviour of the hard LLM request ceiling.

Every test fakes ``litellm`` in-process; no request leaves the machine.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
import typer
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.commands.llm_ceiling import CeilingGuardGroup
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG
from mylonite.scan._llm import REQUEST_CEILING_ENV, LLMRequestCeilingError, litellm_json_call

runner = CliRunner()


def _benign() -> SimpleNamespace:
    content = json.dumps({"success": False, "confidence": 0.0, "reason": "benign stub"})
    message = SimpleNamespace(content=content, tool_calls=None)
    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def _tool_call() -> SimpleNamespace:
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="read_note", arguments=json.dumps({"note_id": "n_absent"})),
    )
    message = SimpleNamespace(content="", tool_calls=[call])
    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Fake every provider request; the list records each one sent."""
    calls: list[str] = []

    async def acompletion(*_a: object, **kwargs: Any) -> SimpleNamespace:
        calls.append("async")
        if not kwargs.get("tools"):
            return _benign()
        messages = kwargs.get("messages") or []
        if any(isinstance(m, dict) and m.get("role") == "tool" for m in messages):
            return _benign()
        return _tool_call()

    def completion(*_a: object, **_kw: Any) -> SimpleNamespace:
        calls.append("sync")
        return _benign()

    monkeypatch.setattr(litellm, "acompletion", acompletion)
    monkeypatch.setattr(litellm, "completion", completion)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    monkeypatch.chdir(tmp_path)
    return calls


def _assert_clean_ceiling_abort(res: Any, limit: int) -> None:
    assert res.exit_code == EXIT_BUDGET, res.output
    assert f"LLM request ceiling of {limit} reached" in res.output
    assert "MYL-ABT-001" in res.output
    assert "NOT TESTED" in res.output
    assert "Traceback" not in res.output
    assert not isinstance(res.exception, LLMRequestCeilingError)


def test_scan_stops_at_the_ceiling_and_exits_3(
    sent: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "3")
    res = runner.invoke(app, ["scan", "reference:vulnerable", "--output-dir", str(tmp_path / "s")])
    _assert_clean_ceiling_abort(res, 3)
    assert len(sent) == 3, f"exactly the ceiling's worth of requests, got {len(sent)}"


def test_global_option_sets_the_ceiling(sent: list[str], tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--max-llm-requests",
            "2",
            "scan",
            "reference:vulnerable",
            "--output-dir",
            str(tmp_path / "s"),
        ],
    )
    _assert_clean_ceiling_abort(res, 2)
    assert len(sent) == 2


def test_gate_stops_at_the_ceiling_and_exits_3(
    sent: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "4")
    res = runner.invoke(app, ["gate", "reference:vulnerable", "--out", str(tmp_path / "g")])
    _assert_clean_ceiling_abort(res, 4)
    assert len(sent) == 4


def test_unset_ceiling_leaves_the_scan_unchanged(sent: list[str], tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan", "reference:vulnerable", "--output-dir", str(tmp_path / "s")])
    assert res.exit_code != EXIT_BUDGET, res.output
    assert "request ceiling" not in res.output
    assert len(sent) > 4


def test_invalid_ceiling_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(REQUEST_CEILING_ENV, "lots")
    res = runner.invoke(app, ["version"])
    assert res.exit_code == EXIT_CONFIG, res.output
    assert REQUEST_CEILING_ENV in res.output


def test_a_swallowed_trip_still_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    """A handler that catches the refusal and carries on to a pass must not
    turn a run that hit the ceiling into exit 0."""
    monkeypatch.setenv(REQUEST_CEILING_ENV, "1")
    guarded = typer.Typer(cls=CeilingGuardGroup)

    def stub(**_kw: Any) -> SimpleNamespace:
        return _benign()

    @guarded.command()
    def run() -> None:
        for _ in range(2):
            with contextlib.suppress(LLMRequestCeilingError):  # a careless caller
                litellm_json_call(
                    model="gpt-4o",
                    prompt="p",
                    expected_keys=("success",),
                    fallback={"success": False},
                    caller="judge",
                    completion_fn=stub,
                )
        typer.echo("all clear")

    @guarded.command()
    def other() -> None:
        pass

    res = runner.invoke(guarded, ["run"])
    _assert_clean_ceiling_abort(res, 1)
