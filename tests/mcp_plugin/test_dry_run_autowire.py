"""`scan --dry-run` wires a seed_arm the same way a real scan does.

A dry run used to skip the seed_arm auto-wire, so on a server with a
store-and-recall pair it warned that W2 could not be covered ("no tool that can
store content") while a real scan would wire W2 and run it. The free preview
said less than the scan would do. Detection needs no LLM, so the dry run now
runs it too.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.exit_codes import EXIT_SUCCESS
from mylonite.plugins._mcp import stdio_adapter, target_registry

runner = CliRunner()


def _patch_store_and_recall(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Session:
        async def initialize(self) -> None:
            return None

        async def list_tools(self) -> Any:
            body = {"properties": {"body": {"type": "string"}}, "required": ["body"]}
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name="save_note", description="Save a note.", inputSchema=body),
                    SimpleNamespace(
                        name="list_notes", description="List saved notes.", inputSchema={}
                    ),
                ]
            )

    @asynccontextmanager
    async def _open(*_a: Any, **_k: Any):  # type: ignore[no-untyped-def]
        yield _Session()

    monkeypatch.setattr(stdio_adapter, "_open_mcp_session", _open)


def test_dry_run_auto_wires_w2_like_a_real_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_registry.clear_runtime_targets()
    _patch_store_and_recall(monkeypatch)
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: acme\ncommand: python\nargs: [-m, srv]\nweakness_classes: [W2]\n",
        encoding="utf-8",
    )
    try:
        result = runner.invoke(
            app, ["scan", "--target-file", str(p), "--authorize", "acme", "--dry-run"]
        )
    finally:
        target_registry.clear_runtime_targets()
    out = result.stderr or result.output
    assert result.exit_code == EXIT_SUCCESS, out
    assert "auto-wire: inferred seed_arm: save_note" in out
    assert "no tool that can store content" not in out
    assert "need a seed_arm" not in out
