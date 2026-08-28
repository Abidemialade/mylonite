"""Offline CLI tests for `mylonite gate`.

These tests do NOT make any LLM or network calls.  They exercise only:
  - that the gate command is registered and exposes its flags
  - that `gate --help` renders without crashing
  - the --authorize gate for custom targets (must exit 2 without it)

Flag presence is checked via Click introspection rather than by scraping the
rendered ``--help`` text: Rich wraps option names and emits ANSI escapes at
narrow/CI terminal widths, so substring checks against rendered help are
flaky across environments. Introspection is render-independent.
"""

import click
import typer
from typer.testing import CliRunner

from mylonite.cli import app

runner = CliRunner()


def _gate_option_names() -> set[str]:
    """All option strings (e.g. ``--open-pr``) declared on the gate command."""
    command = typer.main.get_command(app)
    ctx = click.Context(command)
    gate_cmd = command.get_command(ctx, "gate")  # type: ignore[attr-defined]
    assert gate_cmd is not None, "the `gate` command is not registered"
    names: set[str] = set()
    for param in gate_cmd.params:
        names.update(param.opts)
        names.update(param.secondary_opts)
    return names


def test_gate_exposes_open_pr_and_target_file_flags():
    names = _gate_option_names()
    assert "--open-pr" in names
    assert "--target-file" in names


def test_gate_exposes_runs_on_and_workflows_flags():
    names = _gate_option_names()
    assert "--runs-on" in names
    # bool flag declared as ``--workflows/--no-workflows``
    assert "--workflows" in names or "--no-workflows" in names


def _gate_param(name: str) -> click.Parameter:
    command = typer.main.get_command(app)
    ctx = click.Context(command)
    gate_cmd = command.get_command(ctx, "gate")  # type: ignore[attr-defined]
    param = next((p for p in gate_cmd.params if p.name == name), None)
    assert param is not None, f"`gate` has no parameter named {name!r}"
    return param


def test_gate_does_not_scaffold_workflows_by_default():
    """Writing into someone's .github/workflows/ is opt-in, not opt-out.

    `--workflows` used to default True, so a plain `mylonite gate` dropped
    mylonite-gate.yml and mylonite-discovery.yml into the operator's repository
    alongside the branch and commit it also made uninvited.
    """
    assert _gate_param("workflows").default is False


def test_gate_help_renders_without_crashing():
    # The real render-health check: help renders and exits 0 (no traceback).
    res = runner.invoke(app, ["gate", "--help"])
    assert res.exit_code == 0


def test_gate_requires_authorize_for_custom(tmp_path):
    # A custom target without --authorize must exit EXIT_CONFIG (2), mirroring scan.
    tf = tmp_path / "t.yaml"
    tf.write_text(
        "family: demo\ncommand: 'python'\nargs: ['-c', 'pass']\n",
        encoding="utf-8",
    )
    res = runner.invoke(app, ["gate", "--target-file", str(tf)])
    assert res.exit_code == 2


def test_gate_rejects_bundled_mcp_target_with_explicit_target_file(tmp_path):
    # DCR-0001: a real 'mcp:<family>' positional target combined with an
    # explicit --target-file must be rejected loudly rather than silently
    # gating the target-file's target and discarding the positional argument.
    tf = tmp_path / "custom-app.yaml"
    tf.write_text(
        "family: demo\ncommand: 'python'\nargs: ['-c', 'pass']\n",
        encoding="utf-8",
    )
    res = runner.invoke(
        app,
        [
            "gate",
            "mcp:filesystem:/scope",
            "--target-file",
            str(tf),
            "--authorize",
            "my-app",
        ],
    )
    assert res.exit_code == 2, res.output
    assert "mcp:filesystem:/scope" in res.output
    assert "--target-file" in res.output


def test_gate_exposes_role_model_flags():
    """T14: gate gets the same three-role model split scan already had --
    DifferentialValidator/ScanConfig always accepted planner_model/
    customiser_model/judge_model; this was purely a missing CLI flag."""
    names = _gate_option_names()
    assert "--planner-model" in names
    assert "--customiser-model" in names
    assert "--judge-model" in names


def test_gate_planner_model_override_rejects_unroutable_model(tmp_path):
    """Mirrors scan's identical guard: a role override drives the SAME LiteLLM
    call path as --model, so an unroutable one must reject at CLI-argument
    time -- before any live scan -- not fail later mid-gate."""
    res = runner.invoke(
        app,
        [
            "gate",
            "reference:vulnerable",
            "--planner-model",
            "not-a-real-model-xyz123",
        ],
    )
    assert res.exit_code == 2, res.output
    assert "can't determine a provider" in (res.stderr or res.output)


def test_gate_rejects_bundled_mcp_target_with_autodiscovered_target_file(tmp_path, monkeypatch):
    # DCR-0001: the same rejection must fire even when target_file comes from an
    # auto-discovered ./mylonite.yaml and NO --target-file flag was typed at all.
    tf = tmp_path / "custom-app.yaml"
    tf.write_text(
        "family: demo\ncommand: 'python'\nargs: ['-c', 'pass']\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "mylonite.yaml"
    cfg.write_text(f"target_file: {tf.name}\nauthorize: my-app\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["gate", "mcp:filesystem:/scope"])
    assert res.exit_code == 2, res.output
    assert "mcp:filesystem:/scope" in res.output
    assert "mylonite.yaml" in res.output
