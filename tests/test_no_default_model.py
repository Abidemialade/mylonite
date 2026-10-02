"""The headline behaviour this track exists for: there is no default model.

With ``MYLONITE_MODEL`` (and ``--model``/``mylonite.yaml``) all unset, every
live command stops at ``EXIT_PROVIDER`` (4) with one line naming every
approved provider and its key env var, before touching a target -- never a
hardcoded fallback picked silently, and never a traceback.

Unlike the rest of the suite (which relies on ``tests/conftest.py``'s
autouse ``MYLONITE_MODEL`` default so unrelated tests keep exercising OTHER
behaviour), every test here explicitly clears it via ``env={"MYLONITE_MODEL":
None}`` on the ``CliRunner.invoke`` call -- the per-call override documented
on that fixture -- so a default reappearing through any env-less path would
be caught here even if every other test stayed green.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.exit_codes import EXIT_PROVIDER
from mylonite.providers.registry import PROVIDERS

runner = CliRunner()

#: Clears the ambient MYLONITE_MODEL default (see module docstring) for one
#: invocation, without having to delenv/restore it for the whole test.
_NO_MODEL_ENV = {"MYLONITE_MODEL": None, "MYLONITE_PROVIDER": None}

#: Every adapter-construction entry point a live command could reach, as
#: named in cli.py's own module namespace (it imports these by name, so
#: patching the SOURCE module they're defined in would not intercept cli.py's
#: already-bound references). A spy on all four, asserted un-called, is the
#: proof that the command stopped before any of them ran -- not just that
#: the exit code happened to come back right.
_ADAPTER_FACTORY_NAMES = (
    "mylonite.cli._build_adapter_for_reference",
    "mylonite.cli._build_adapter_for_mcp",
    "mylonite.cli._build_adapter_for_custom",
)


def _invoke_with_adapters_spied(argv: list[str]):
    with (
        patch(_ADAPTER_FACTORY_NAMES[0]) as reference_spy,
        patch(_ADAPTER_FACTORY_NAMES[1]) as mcp_spy,
        patch(_ADAPTER_FACTORY_NAMES[2]) as custom_spy,
        patch("asyncio.create_subprocess_exec") as subprocess_spy,
    ):
        result = runner.invoke(app, argv, env=_NO_MODEL_ENV)
        for spy in (reference_spy, mcp_spy, custom_spy, subprocess_spy):
            spy.assert_not_called()
    return result


#: One argv per command this applies to. `ablate` needs --target-file (any
#: path -- it is never read before the model check) and --authorize to get
#: past its OWN earlier preconditions and actually reach the model check;
#: the other three reach it with nothing else needed at all (see the model
#: checks' placement in cli.py -- scan/gate/validate all resolve a model
#: before checking the target shape or --authorize).
_LIVE_COMMAND_ARGVS = [
    pytest.param(["scan"], id="scan"),
    pytest.param(["scan", "--dry-run"], id="scan-dry-run"),
    pytest.param(["gate"], id="gate"),
    pytest.param(["validate", "/nonexistent/generated/dir"], id="validate"),
    pytest.param(
        ["ablate", "--target-file", "/nonexistent/target.yaml", "--authorize", "x"], id="ablate"
    ),
]


@pytest.mark.parametrize("argv", _LIVE_COMMAND_ARGVS)
def test_no_model_configured_exits_provider_before_any_adapter_or_subprocess(argv):
    result = _invoke_with_adapters_spied(argv)
    assert result.exit_code == EXIT_PROVIDER, result.output


@pytest.mark.parametrize("argv", _LIVE_COMMAND_ARGVS)
def test_no_model_configured_prints_exactly_one_line(argv):
    result = _invoke_with_adapters_spied(argv)
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1, result.output


@pytest.mark.parametrize("argv", _LIVE_COMMAND_ARGVS)
def test_no_model_configured_names_every_approved_provider_and_key_var(argv):
    result = _invoke_with_adapters_spied(argv)
    for info in PROVIDERS.values():
        assert info.id in result.output, f"{info.id!r} missing from: {result.output}"
        if info.key_env:
            assert info.key_env[0] in result.output, (
                f"{info.key_env[0]!r} (the {info.id!r} key var) missing from: {result.output}"
            )


@pytest.mark.parametrize("argv", _LIVE_COMMAND_ARGVS)
def test_no_model_configured_never_raises_a_traceback(argv):
    result = _invoke_with_adapters_spied(argv)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output


# --- the inverse: these need no model at all ------------------------------


def test_check_needs_no_model(tmp_path):
    """`check` never calls an LLM -- `describe()` only -- so it must not
    hit the model check even with none configured."""
    result = runner.invoke(
        app,
        ["check", "reference:vulnerable"],
        env={**_NO_MODEL_ENV, "MYLONITE_EXPERIMENTAL": "1"},
    )
    assert "no model configured" not in result.output.lower()


def test_scan_scaffold_needs_no_model(tmp_path):
    """`--scaffold` introspects a server -- no LLM call -- so it must not
    hit the model check either, even though it still needs a real server to
    actually introspect (a missing --command fails for THAT reason, not a
    model one)."""
    out = tmp_path / "target.yaml"
    result = runner.invoke(app, ["scan", "--scaffold", str(out)], env=_NO_MODEL_ENV)
    assert "no model configured" not in result.output.lower()


def test_demo_replay_needs_no_model(tmp_path, monkeypatch):
    """The offline replay path is pinned to its own recorded fixtures'
    identity -- it must keep working with nothing configured at all."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo"], env=_NO_MODEL_ENV)
    assert "no model configured" not in result.output.lower()
    assert result.exit_code != EXIT_PROVIDER
