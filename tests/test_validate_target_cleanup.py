"""`validate --target-file` must not leave its custom target registered (#244).

This module deliberately has NO autouse registry-isolation fixture (the one in
``tests/test_cli.py``, added for #230, would mask the very leak under test), so
the test clears the registry itself and checks it is empty after a failure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli import _sample_exploit
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.plugins._mcp import target_registry

_TARGET_YAML = "family: myapp\ncommand: python\nargs: [-m, my_server]\nweakness_classes: [W2]\n"


def test_validate_clears_its_target_when_it_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "gen"
    out_dir.mkdir()
    exploit = _sample_exploit().model_copy(update={"target_id": "mcp:myapp"})
    (out_dir / "exploit_pid.json").write_text(
        json.dumps(exploit.model_dump(mode="json")), encoding="utf-8"
    )
    (out_dir / "test_security_pid.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8"
    )
    target_file = tmp_path / "target.yaml"
    target_file.write_text(_TARGET_YAML, encoding="utf-8")

    # Get past authorization and the provider preflight, so the target is
    # registered, then fail the way a real run can (an error mid-validation).
    # The sample exploit names an Anthropic model, and validate checks for its
    # credential before calibrating. A dummy key gets past that check the same
    # way on every machine, and keeps a real key on a developer's shell out of
    # the run; calibration below fails before any model call.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")  # pragma: allowlist secret
    monkeypatch.setattr("mylonite.cli._provider_preflight_direct", lambda *a, **k: True)

    def _boom(*_a: object, **_k: object) -> None:
        msg = "calibration blew up"
        raise RuntimeError(msg)

    monkeypatch.setattr("mylonite.cli._calibrate_custom_target_now", _boom)

    target_registry.clear_runtime_targets()
    try:
        result = CliRunner().invoke(
            app,
            [
                "validate",
                str(out_dir),
                "--target-file",
                str(target_file),
                "--authorize",
                "myapp",
            ],
        )
        assert result.exit_code != 0
        assert isinstance(result.exception, RuntimeError), result.output
        assert "myapp" not in target_registry.known_families()
    finally:
        target_registry.clear_runtime_targets()
