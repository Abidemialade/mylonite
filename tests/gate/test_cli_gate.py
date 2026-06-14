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
