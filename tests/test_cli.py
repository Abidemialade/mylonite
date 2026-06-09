"""End-to-end Typer CLI smoke tests."""

from __future__ import annotations

from typer.testing import CliRunner

import mylonite
from mylonite.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == mylonite.__version__


def test_taxonomy_list_owasp_llm() -> None:
    result = runner.invoke(app, ["taxonomy", "list", "--framework", "owasp-llm"])
    assert result.exit_code == 0
    for i in range(1, 11):
        assert f"LLM{i:02d}" in result.stdout


def test_taxonomy_list_owasp_asi() -> None:
    result = runner.invoke(app, ["taxonomy", "list", "--framework", "owasp-asi"])
    assert result.exit_code == 0
    for i in range(1, 11):
        assert f"ASI{i:02d}" in result.stdout


def test_scan_is_stub() -> None:
    result = runner.invoke(app, ["scan", "./fake-target"])
    assert result.exit_code == 2
    assert "not implemented" in result.stderr.lower()


def test_generate_is_stub() -> None:
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 2


def test_validate_is_stub() -> None:
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 2


def test_init_is_stub() -> None:
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 2
