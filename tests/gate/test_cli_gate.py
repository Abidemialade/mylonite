"""Offline CLI tests for `mylonite gate`.

These tests do NOT make any LLM or network calls.  They exercise only:
  - --help output (flag presence)
  - the --authorize gate for custom targets (must exit 2 without it)
"""

from typer.testing import CliRunner

from mylonite.cli import app

runner = CliRunner()


def test_gate_help_lists_open_pr_flag():
    res = runner.invoke(app, ["gate", "--help"])
    assert res.exit_code == 0
    assert "--open-pr" in res.output
    assert "--target-file" in res.output


def test_gate_requires_authorize_for_custom(tmp_path):
    # A custom target without --authorize must exit EXIT_CONFIG (2), mirroring scan.
    tf = tmp_path / "t.yaml"
    tf.write_text(
        "family: demo\ncommand: 'python'\nargs: ['-c', 'pass']\n",
        encoding="utf-8",
    )
    res = runner.invoke(app, ["gate", "--target-file", str(tf)])
    assert res.exit_code == 2


def test_gate_help_lists_runs_on_and_no_workflows():
    res = runner.invoke(app, ["gate", "--help"])
    assert "--runs-on" in res.output
    assert "--no-workflows" in res.output or "--workflows" in res.output
