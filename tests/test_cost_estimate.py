"""The pre-spend LLM call estimate (``mylonite.commands.cost_estimate``).

Every bracket test here reuses ``scripts/count_llm_calls.py``'s scripted fake
model to measure a REAL offline reference run, then asserts the estimate this
module predicts for the same inputs contains that measured count -- so a
future change to the reference seed catalogue, the differential fixture, or
the per-call constants below is caught the moment the estimate no longer
brackets reality, not just when someone remembers to re-check the docs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.commands.cost_estimate import (
    estimate_scan_calls,
    estimate_scan_seed_count,
    estimate_validate_calls,
    format_estimate_line,
    gate_estimate_line,
    redrives_per_finding,
    scan_estimate_line,
    validate_estimate_line,
)
from mylonite.exit_codes import EXIT_SUCCESS
from mylonite.scan._llm import configure_request_ceiling

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import count_llm_calls as counter  # noqa: E402

runner = CliRunner()


def _benign_response() -> SimpleNamespace:
    """A text-only LiteLLM reply: no tool calls, so the planner terminates
    immediately and the customiser/judge both fall back harmlessly on
    non-JSON content. Reused from the pattern in
    ``tests/gate/test_gate_e2e_offline.py``."""
    content = json.dumps({"success": False, "confidence": 0.0, "reason": "benign stub"})
    message = SimpleNamespace(content=content, tool_calls=None)
    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=1, total_tokens=1)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


async def _benign_acompletion(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
    return _benign_response()


# ---------------------------------------------------------------------------
# Seed-count estimate: exact for the bundled reference target
# ---------------------------------------------------------------------------


def test_reference_seed_count_matches_the_kitchen_sink_catalogue() -> None:
    low, high = estimate_scan_seed_count("reference:vulnerable")
    assert low == high
    assert low > 0


def test_weakness_class_filter_narrows_the_seed_count() -> None:
    unfiltered_low, _ = estimate_scan_seed_count("reference:vulnerable")
    filtered_low, filtered_high = estimate_scan_seed_count(
        "reference:vulnerable", weakness_classes=["W1"]
    )
    assert filtered_low == filtered_high
    assert 0 < filtered_low < unfiltered_low


def test_an_unknown_family_has_no_seeds() -> None:
    assert estimate_scan_seed_count("mcp:nonexistent-family") == (0, 0)


def test_declared_classes_use_a_one_to_three_seed_per_class_range() -> None:
    low, high = estimate_scan_seed_count("mcp:custom", declared_classes=["W2", "W4"])
    assert (low, high) == (2, 6)


def test_declared_classes_are_intersected_with_the_weakness_class_flag() -> None:
    low, high = estimate_scan_seed_count(
        "mcp:custom", declared_classes=["W2", "W4"], weakness_classes=["W4"]
    )
    assert (low, high) == (1, 3)


# ---------------------------------------------------------------------------
# Bracket checks against a measured offline reference scan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["vulnerable", "guarded"])
def test_scan_estimate_brackets_the_measured_reference_count(variant: str) -> None:
    _, fake = counter.run_reference_scan(variant)  # type: ignore[arg-type]
    seed_low, seed_high = estimate_scan_seed_count(f"reference:{variant}")
    low, high = estimate_scan_calls(seed_low, seed_high)
    assert low <= fake.total <= high, (
        f"measured {fake.total} calls outside estimated [{low}, {high}] for {seed_low}-"
        f"{seed_high} seeds"
    )


def test_scan_estimate_line_contains_the_seed_count_and_a_call_range() -> None:
    line = scan_estimate_line("reference:vulnerable")
    assert "Estimated LLM calls for this scan" in line
    assert "Cost depends on the provider and model" in line
    assert "\n" not in line


# ---------------------------------------------------------------------------
# Bracket check against a measured offline differential validation
# ---------------------------------------------------------------------------


def test_validate_estimate_brackets_the_measured_reference_count(tmp_path: Path) -> None:
    import json

    meta = json.loads(
        (ROOT / counter.EXAMPLE_DIRNAME / "differential_fixtures" / "_meta.json").read_text(
            encoding="utf-8"
        )
    )
    run = counter.run_reference_gate(tmp_path / "gate")
    low, high = estimate_validate_calls(
        iterations=int(meta["iterations"]),
        metamorphic_variants=len(meta["metamorphic_strategies"]),
        twins=2,
    )
    assert low <= run.validate.total <= high, (
        f"measured {run.validate.total} calls outside estimated [{low}, {high}]"
    )


def test_redrives_per_finding_matches_the_docs_formula() -> None:
    # docs/ci-gating.md's sizing box: "(iterations + 7) x 2" at the default
    # iterations=5 with the full built-in metamorphic strategy set.
    assert redrives_per_finding(iterations=5, metamorphic_variants=7, twins=2) == 24


def test_validate_estimate_line_names_the_reference_metamorphic_pass() -> None:
    line = validate_estimate_line(is_reference=True, iterations=3, twins=2, fast=False)
    assert "metamorphic" in line
    assert "Estimated LLM calls for this validation" in line


def test_validate_estimate_line_omits_metamorphic_for_a_custom_target() -> None:
    line = validate_estimate_line(is_reference=False, iterations=3, twins=1, fast=False)
    assert "metamorphic" not in line


def test_fast_reduces_the_reference_metamorphic_pass_to_one_strategy() -> None:
    fast_low, fast_high = estimate_validate_calls(iterations=3, metamorphic_variants=1, twins=2)
    full_low, full_high = estimate_validate_calls(iterations=3, metamorphic_variants=7, twins=2)
    assert fast_low < full_low
    assert fast_high < full_high


# ---------------------------------------------------------------------------
# gate: scan-phase estimate brackets the same measured scan, plus a
# per-finding (not per-run) validation note
# ---------------------------------------------------------------------------


def test_gate_estimate_line_scan_part_brackets_the_measured_scan() -> None:
    _, fake = counter.run_reference_scan("vulnerable")  # type: ignore[arg-type]
    line = gate_estimate_line("reference:vulnerable", is_reference=True, iterations=3, fast=False)
    seed_low, seed_high = estimate_scan_seed_count("reference:vulnerable")
    scan_low, scan_high = estimate_scan_calls(seed_low, seed_high)
    assert scan_low <= fake.total <= scan_high
    assert "Estimated LLM calls for this gate run" in line
    assert f"{scan_low}" in line
    assert "per finding kept and validated" in line


# ---------------------------------------------------------------------------
# format_estimate_line: the ceiling clause and the cost caveat
# ---------------------------------------------------------------------------


def test_format_estimate_line_names_the_ceiling_when_one_is_set() -> None:
    configure_request_ceiling(42)
    line = format_estimate_line("scan", 1, 2, "1 seed")
    assert "42 requests" in line
    assert "--max-llm-requests" in line


def test_format_estimate_line_says_no_ceiling_when_none_is_set() -> None:
    line = format_estimate_line("scan", 1, 2, "1 seed")
    assert "No hard ceiling is set" in line


def test_format_estimate_line_never_invents_a_price() -> None:
    line = format_estimate_line("scan", 1, 2, "1 seed")
    assert "Cost depends on the provider and model" in line
    assert "$" not in line


# ---------------------------------------------------------------------------
# CLI wiring: the line prints before any live call, and never under --dry-run
# ---------------------------------------------------------------------------


def test_scan_dry_run_never_prints_the_estimate(monkeypatch: pytest.MonkeyPatch) -> None:
    """--dry-run makes no LLM call at all, so the estimate -- which exists to
    warn about spend that's about to happen -- must not appear."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    result = runner.invoke(
        app,
        [
            "scan",
            "reference:vulnerable",
            "--model",
            "anthropic/claude-haiku-4-5-20251001",
            "--dry-run",
        ],
    )
    out = result.stderr or result.output
    assert "Estimated LLM calls" not in out, out


def test_scan_live_prints_the_estimate_before_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _benign_acompletion)
    monkeypatch.setattr(litellm, "completion", lambda *a, **kw: _benign_response())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret

    result = runner.invoke(
        app,
        ["scan", "reference:vulnerable", "--model", "anthropic/claude-haiku-4-5-20251001"],
    )

    out = result.stderr or result.output
    assert "Estimated LLM calls for this scan" in out, out
    assert "No hard ceiling is set" in out


def test_validate_cli_prints_the_estimate_before_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reference ``validate`` branch: ``DifferentialValidator`` is a canned
    double (no live call), matching ``tests/test_cli.py``'s own
    ``test_validate_kept_true_exit_0`` -- the estimate line must still appear,
    printed before the (stubbed) validator ever runs."""
    from tests.test_cli import _generated_dir, _patch_validator

    out_dir = _generated_dir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    monkeypatch.setattr("mylonite.cli._provider_preflight", lambda *_, **__: True)
    _patch_validator(monkeypatch, kept=True)

    result = runner.invoke(app, ["validate", str(out_dir)])

    assert result.exit_code == EXIT_SUCCESS, result.output
    out = result.stderr or result.output
    assert "Estimated LLM calls for this validation" in out, out


def test_gate_prints_the_estimate_before_any_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The offline no-finding gate path (matching
    ``tests/gate/test_gate_e2e_offline.py``'s Part A): the planner never
    calls a tool, so ``gate`` finds nothing and exits 0 -- but the estimate,
    printed before the scan phase even starts, must still have appeared."""
    import litellm

    monkeypatch.setattr(litellm, "acompletion", _benign_acompletion)
    monkeypatch.setattr(litellm, "completion", lambda *a, **kw: _benign_response())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret

    result = runner.invoke(
        app,
        ["gate", "reference:vulnerable", "--out", str(tmp_path / "gate")],
    )

    out = result.stderr or result.output
    assert "Estimated LLM calls for this gate run" in out, out
