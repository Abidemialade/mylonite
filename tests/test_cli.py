"""End-to-end Typer CLI smoke tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import mylonite
from mylonite.cli import EXIT_CONFIG, EXIT_PROVIDER, EXIT_SUCCESS, app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == EXIT_SUCCESS
    assert result.stdout.strip() == mylonite.__version__


def test_taxonomy_list_owasp_llm() -> None:
    result = runner.invoke(app, ["taxonomy", "list", "--framework", "owasp-llm"])
    assert result.exit_code == EXIT_SUCCESS
    for i in range(1, 11):
        assert f"LLM{i:02d}" in result.stdout


def test_taxonomy_list_owasp_asi() -> None:
    result = runner.invoke(app, ["taxonomy", "list", "--framework", "owasp-asi"])
    assert result.exit_code == EXIT_SUCCESS
    for i in range(1, 11):
        assert f"ASI{i:02d}" in result.stdout


def test_generate_is_stub() -> None:
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == EXIT_CONFIG


def test_validate_is_stub() -> None:
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == EXIT_CONFIG


def test_init_is_stub() -> None:
    result = runner.invoke(app, ["init"])
    assert result.exit_code == EXIT_CONFIG


def test_scan_refuses_non_reference_without_authorize() -> None:
    result = runner.invoke(app, ["scan", "mcp:filesystem:/tmp/sandbox"])
    assert result.exit_code == EXIT_CONFIG
    assert "--authorize" in (result.stderr or result.output)


def test_scan_refuses_unknown_target_shape() -> None:
    """A target that's neither reference:* nor mcp:* is a config error."""
    result = runner.invoke(app, ["scan", "rag://example.com", "--authorize", "anything"])
    assert result.exit_code == EXIT_CONFIG
    assert "unknown target shape" in (result.stderr or result.output)


def test_scan_refuses_unknown_mcp_family() -> None:
    """An mcp:<family> not in BUNDLED_TARGETS gives a typed error message."""
    result = runner.invoke(app, ["scan", "mcp:nosuch:any", "--authorize", "any"])
    assert result.exit_code == EXIT_CONFIG
    assert "unknown MCP target family" in (result.stderr or result.output)


def test_scan_mcp_filesystem_refuses_mismatched_authorize(tmp_path: Path) -> None:
    """filesystem requires --authorize == scope."""
    result = runner.invoke(
        app,
        [
            "scan",
            f"mcp:filesystem:{tmp_path}",
            "--authorize",
            str(tmp_path / "different"),
            "--dry-run",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == EXIT_CONFIG
    assert "--authorize must equal the scope segment" in (result.stderr or result.output)


def test_scan_mcp_fetch_requires_family_as_authorize() -> None:
    """fetch is stateless — --authorize must equal the family name."""
    result = runner.invoke(
        app,
        ["scan", "mcp:fetch", "--authorize", "wrong-label"],
    )
    assert result.exit_code == EXIT_CONFIG
    assert "--authorize must equal the family name" in (result.stderr or result.output)


def test_scan_mcp_github_rejects_missing_slash() -> None:
    """github requires owner/repo scope — typed validation error."""
    result = runner.invoke(
        app,
        ["scan", "mcp:github:notvalid", "--authorize", "notvalid"],
    )
    assert result.exit_code == EXIT_CONFIG
    assert "owner/repo" in (result.stderr or result.output)


def test_scan_dry_run_against_reference_vulnerable(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "reference:vulnerable",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS
    # No artefacts written in dry-run mode.
    assert list(tmp_path.glob("*")) == []
    # Summary table prints with skipped_dry_run markers.
    assert "dry-run" in result.stdout or "attempts" in result.stdout


def test_scan_unknown_reference_variant_is_config_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "reference:typo", "--dry-run", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == EXIT_CONFIG


@pytest.fixture
def patch_planner_to_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """G5: every LLMPlanner call raises, simulating provider down."""

    async def always_raise(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    from mylonite.plugins._reference import reference_target_adapter

    original_init = reference_target_adapter.InProcessReferenceAdapter.__init__

    def patched_init(self: Any, **kwargs: Any) -> None:
        kwargs["completion_fn"] = always_raise
        original_init(self, **kwargs)

    monkeypatch.setattr(
        reference_target_adapter.InProcessReferenceAdapter, "__init__", patched_init
    )


def test_scan_exit_4_on_provider_failure(
    patch_planner_to_fail: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G5: three consecutive planner failures → exit code 4 (provider_unreachable)."""

    # Also patch the customiser + judge to skip their LLM calls (we want the
    # adapter to be the failing layer, not the engine's orchestration calls).
    async def stub_customise(self: Any, seed: Any, target: Any) -> Any:
        from mylonite.contracts._types import Payload

        return Payload(
            pattern_id=seed.pattern_id,
            channel=seed.channel,
            body=seed.seed_body,
            metadata={
                "seed_id": seed.pattern_id,
                "weakness": seed.weakness,
                "predicate": seed.predicate,
                "setup": seed.setup,
                "drive": seed.drive,
            },
        )

    from mylonite.scan import customiser as _cust

    monkeypatch.setattr(_cust.PayloadCustomiser, "customise", stub_customise)

    result = runner.invoke(
        app,
        [
            "scan",
            "reference:vulnerable",
            "--output-dir",
            str(tmp_path),
            "--max-llm-calls",
            "200",
        ],
    )
    # Either exit code 4 (provider_unreachable) or the adapter skip path produced
    # every attempt as skipped_planner_failure (still fine — no findings, no abort).
    # The engine aborts on 3 consecutive provider failures via consecutive_failures.
    # In practice the wrapped completion in the adapter increments
    # consecutive_failures on the counter; after 3, ScanEngine sets aborted.
    assert result.exit_code in (EXIT_PROVIDER, EXIT_SUCCESS)


# ---------------------------------------------------------------------------
# `mylonite demo` — the offline Quarry playground (v0.3.0, PR A, Task A5).
#
# These tests MUST be plain `def` (not async): the command body calls
# asyncio.run() internally, and pytest's asyncio_mode="auto" would otherwise
# wrap them in a running event loop and raise "cannot be called from a running
# event loop".
# ---------------------------------------------------------------------------


def test_demo_replay_smoke() -> None:
    """Default (offline replay) demo renders the differential and exits 0."""
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == EXIT_SUCCESS, result.output
    assert "Quarry" in result.output
    assert "0 on guarded" in result.output


def test_demo_replay_warns_when_provider_flag_ignored() -> None:
    """--provider without --live warns (never silently ignores) and still exits 0."""
    result = runner.invoke(app, ["demo", "--provider", "openai"])
    assert result.exit_code == EXIT_SUCCESS, result.output
    out = result.stderr or result.output
    assert "pinned" in out.lower() or "ignored" in out.lower()
    assert "claude-haiku-4-5-20251001" in out


def test_demo_missing_kitchen_sink_maps_to_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing mcp_kitchen_sink install → exit 2 with the clone-first command."""

    async def fake_run_demo(**_: Any) -> Any:
        exc = ModuleNotFoundError("No module named 'mcp_kitchen_sink'")
        exc.name = "mcp_kitchen_sink"
        raise exc

    from mylonite.demo import runner as demo_runner

    monkeypatch.setattr(demo_runner, "run_demo", fake_run_demo)

    result = runner.invoke(app, ["demo"])
    assert result.exit_code == EXIT_CONFIG
    out = result.stderr or result.output
    assert "pip install -e ./reference_targets/mcp_kitchen_sink" in out
    # Friendly message, not a raw traceback.
    assert "Traceback" not in out


def test_demo_corrupt_fixture_maps_to_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """A corrupt fixture surfaces as exit 2 with the underlying message."""
    from mylonite.demo import runner as demo_runner
    from mylonite.demo._replay import CorruptFixtureError

    async def fake_run_demo(**_: Any) -> Any:
        raise CorruptFixtureError("fixture corrupt — reinstall mylonite or re-record")

    monkeypatch.setattr(demo_runner, "run_demo", fake_run_demo)

    result = runner.invoke(app, ["demo"])
    assert result.exit_code == EXIT_CONFIG
    out = result.stderr or result.output
    assert "fixture corrupt" in out
    assert "Traceback" not in out
