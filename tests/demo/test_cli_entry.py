"""Unit tests for ``mylonite.demo.cli_entry.run_demo_command``.

No default provider or model: ``--live`` makes a real call, so it needs a
model chosen for it exactly like ``scan``/``validate``/``gate``/``ablate``
do. Replay (the default, no ``--live``) needs none at all -- it is pinned
to the recorded fixtures' own identity (``DEMO_MODEL``/``DEMO_PROVIDER``),
never a live default.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import typer

from mylonite.demo.cli_entry import run_demo_command
from mylonite.exit_codes import EXIT_PROVIDER


def test_live_with_no_model_exits_provider_before_any_call() -> None:
    """`--live` with no `--model` must stop before `run_demo` (and therefore
    before any adapter/LiteLLM call) is ever reached -- exit 4, one line
    naming the approved providers, no traceback."""
    with patch("mylonite.demo.runner.run_demo") as fake_run_demo:
        with pytest.raises(typer.Exit) as excinfo:
            run_demo_command(live=True, provider=None, model=None)
        assert excinfo.value.exit_code == EXIT_PROVIDER
        fake_run_demo.assert_not_called()


def test_live_with_no_model_prints_the_registry_built_message(capsys) -> None:
    with pytest.raises(typer.Exit):
        run_demo_command(live=True, provider=None, model=None)
    out = capsys.readouterr().err or capsys.readouterr().out
    assert "no model configured" in out.lower()


def test_live_with_a_provider_but_no_model_still_exits_provider() -> None:
    """A `--provider` alone (no `--model`) is still "no model chosen" --
    `--provider` without `--model` was never a complete configuration."""
    with patch("mylonite.demo.runner.run_demo") as fake_run_demo:
        with pytest.raises(typer.Exit) as excinfo:
            run_demo_command(live=True, provider="anthropic", model=None)
        assert excinfo.value.exit_code == EXIT_PROVIDER
        fake_run_demo.assert_not_called()


def test_replay_needs_no_model_at_all() -> None:
    """The inverse: replay mode (no --live) never reaches the --live-only
    model requirement, even though no --model was passed either."""
    fake_variant = SimpleNamespace(report=SimpleNamespace(aborted=None))
    fake_result = SimpleNamespace(
        vulnerable=fake_variant, guarded=fake_variant, mode="replay", elapsed_s=0.0
    )
    with (
        patch("mylonite.demo.runner.run_demo", new=AsyncMock(return_value=fake_result)) as fake,
        patch("mylonite.demo.render.render_demo"),
    ):
        with contextlib.suppress(typer.Exit):
            # render_demo's own downstream behaviour isn't this test's concern
            run_demo_command(live=False, provider=None, model=None)
        fake.assert_called_once()
        _, kwargs = fake.call_args
        assert kwargs["live"] is False
