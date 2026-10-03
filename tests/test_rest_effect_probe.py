"""A ``transport: rest`` target that declares an ``effect_probe`` is refused.

The field used to be dropped without a word, and ``validate`` then told the
user to declare one. Every command now stops on load, with exit 2 and one
message, before it connects to anything or calls a model.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.exit_codes import EXIT_CONFIG

runner = CliRunner()

_REFUSAL = "effect_probe is not supported on a rest target"

_REST_WITH_PROBE = (
    "family: my-agent\n"
    "transport: rest\n"
    "weakness_classes: [W2]\n"
    "request:\n"
    "  url: http://127.0.0.1:9/chat\n"
    '  body: \'{"prompt": "{prompt}"}\'\n'
    "effect_probe:\n"
    "  verify_tool: list_outbox\n"
)


@pytest.fixture
def rest_with_probe(tmp_path: Path) -> Path:
    path = tmp_path / "agent.yaml"
    path.write_text(_REST_WITH_PROBE, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def reached(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record any adapter build or model request a command makes.

    Recorded, not raised: several commands map any exception to exit 2, so a
    raise here could pass for the refusal.
    """
    from mylonite.plugins._mcp import factory
    from mylonite.scan import _llm

    calls: list[str] = []

    def _record(name: str) -> Any:
        def _stub(*_: Any, **__: Any) -> Any:
            calls.append(name)
            raise RuntimeError(name)

        return _stub

    monkeypatch.setattr(factory, "build_mcp_adapter", _record("build_mcp_adapter"))
    monkeypatch.setattr(factory, "build_adapter_for_spec", _record("build_adapter_for_spec"))
    monkeypatch.setattr(_llm, "_charge_request", _record("model request"))
    return calls


def test_check_refuses_a_rest_effect_probe_before_connecting(
    rest_with_probe: Path, reached: list[str]
) -> None:
    """`check` used to connect, find no tools and stop there with exit 0."""
    result = runner.invoke(app, ["check", "--target-file", str(rest_with_probe)])
    assert result.exit_code == EXIT_CONFIG, result.output
    out = result.output + (result.stderr or "")
    assert _REFUSAL in out
    assert "no tools" not in out
    assert reached == []


def _generated_dir(root: Path) -> Path:
    """A `generate` output folder for a custom target, as `validate` reads it."""
    from .test_cli import _write_custom_exploit_json

    out_dir = root / "gen"
    out_dir.mkdir()
    _write_custom_exploit_json(out_dir / "exploit_pid.json")
    (out_dir / "test_security_pid.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8"
    )
    return out_dir


_MODEL = ["--authorize", "my-agent", "--model", "ollama/llama3.2:3b"]


@pytest.mark.parametrize("command", ["scan", "check", "validate", "gate", "ablate"])
def test_every_command_refuses_a_rest_effect_probe_before_any_spend(
    command: str, rest_with_probe: Path, tmp_path: Path, reached: list[str]
) -> None:
    args = [command]
    if command == "validate":
        args.append(str(_generated_dir(tmp_path)))
    args += ["--target-file", str(rest_with_probe)]
    if command != "check":
        args += _MODEL
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_CONFIG, result.output
    assert _REFUSAL in result.output + (result.stderr or "")
    assert reached == []


def test_validate_refuses_a_saved_rest_target_yaml_with_an_effect_probe(
    tmp_path: Path, reached: list[str]
) -> None:
    """An older scan folder whose saved target.yaml carries the block stops too."""
    out_dir = _generated_dir(tmp_path)
    (out_dir / "target.yaml").write_text(_REST_WITH_PROBE, encoding="utf-8")
    result = runner.invoke(app, ["validate", str(out_dir), *_MODEL])
    assert result.exit_code == EXIT_CONFIG, result.output
    assert _REFUSAL in result.output + (result.stderr or "")
    assert reached == []


def _validate_black_box(*, fired: bool, consensus: float) -> Any:
    """Validate a rest (black-box) target whose runs all fire, or all don't."""
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
    from mylonite.plugins._reference.reference_validator import (
        DifferentialValidator,
        ReferenceVulnerableOracle,
        _CustomRun,
    )

    from .plugins.test_differential_validator import (
        _cust_completion,
        _custom_exploit,
        _FakeCustomAdapter,
    )

    test = ReferencePytestGenerator().emit(_custom_exploit())

    def _run(self: Any, target: Any, pattern_id: str, *, factory: Any = None) -> _CustomRun:
        return _CustomRun(
            finding=fired,
            effect_confirmed="unprobed",
            response=None,
            verdict_mechanism="llm" if fired else None,
            evidence_tier="judge-only" if fired else None,
            resisted=not fired,
            black_box=True,
        )

    validator = DifferentialValidator(
        model="stub",
        iterations=2,
        vuln_threshold=2,
        completion_fn=_cust_completion,
        run_build=False,
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(DifferentialValidator, "_run_custom_iteration", _run, raising=True)
        mp.setattr(DifferentialValidator, "_multi_judge_consensus", lambda self, runs, p: consensus)
        return validator.validate(test, _FakeCustomAdapter("unprobed"), ReferenceVulnerableOracle())


def _rendered(report: Any) -> str:
    import io

    from rich.console import Console

    from mylonite.report.render import _render_validation_report

    buffer = io.StringIO()
    _render_validation_report(report, console=Console(file=buffer, width=400, force_terminal=False))
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("fired", "consensus"),
    [(True, 1.0), (True, 0.0), (False, 0.0)],
    ids=["kept", "judges-disagree", "never-fired"],
)
def test_validate_never_tells_a_rest_user_to_declare_an_effect_probe(
    fired: bool, consensus: float
) -> None:
    """The effect leg on a black box is report-only because there is no state to
    read, and neither it nor the rendered remediation may point at a field the
    rest transport refuses."""
    report = _validate_black_box(fired=fired, consensus=consensus)
    effect = next(o for o in report.outcomes if o.stage == "effect")
    assert effect.report_only is True
    assert "effect_probe" not in effect.detail
    assert "black-box" in effect.detail
    rendered = _rendered(report)
    assert "effect_probe" not in rendered
    if fired and consensus < 0.5:  # the consensus remediation line
        assert "--judge-model" in rendered
