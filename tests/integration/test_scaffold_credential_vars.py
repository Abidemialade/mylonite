"""0.10.3 Task 1, end to end: scaffold a real stdio MCP server with a secret
``--env``, then load the written file with ``check``.

Before 0.10.3 the scaffold kept the secret out of the file (correct) but never
said so, so the documented next step (``check --target-file``) stopped on an
unset ``MYLONITE_TARGET_*`` variable the user had never heard of. This runs the
real CLI (``python -m mylonite``, this test's own interpreter) against the
bundled kitchen-sink stdio server and checks both halves: scaffold names the
variable, and ``check`` either names the fix or passes once the variable is set.

A subprocess, not ``CliRunner``: the stdio MCP client needs a real stderr file
descriptor to launch the server, which ``CliRunner``'s captured stream lacks.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp_kitchen_sink")

_SECRET = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234"  # pragma: allowlist secret
_VAR = "MYLONITE_TARGET_ENV_GITHUB_TOKEN"
_EXPORT = f"export {_VAR}='<your GITHUB_TOKEN>'"
_EXIT_SUCCESS = 0
_EXIT_CONFIG = 2


def _mylonite(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    # Inherits os.environ (so monkeypatch.setenv/delenv apply); UTF-8 output so
    # the Windows console code page cannot fail the run.
    # The child imports the same mylonite / mcp_kitchen_sink this test did, not
    # whatever an installed copy or a relative PYTHONPATH would resolve to.
    import mcp_kitchen_sink

    import mylonite

    roots = [str(Path(m.__file__).resolve().parents[1]) for m in (mylonite, mcp_kitchen_sink)]
    pythonpath = os.pathsep.join([*roots, os.environ.get("PYTHONPATH", "")])
    env = {
        **os.environ,
        "PYTHONPATH": pythonpath,
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    return subprocess.run(
        [sys.executable, "-m", "mylonite", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


def test_scaffold_names_credential_vars_and_check_follows_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_VAR, raising=False)
    out = tmp_path / "app.yaml"
    scaffold = _mylonite(
        [
            "scan",
            "--command",
            sys.executable,
            "--arg",
            "-m",
            "--arg",
            "mcp_kitchen_sink.stdio_vulnerable",
            "--env",
            f"GITHUB_TOKEN={_SECRET}",
            "--env",
            "LOG_LEVEL=debug",
            "--scope",
            "my-app",
            "--scaffold",
            str(out),
        ],
        tmp_path,
    )
    assert scaffold.returncode == _EXIT_SUCCESS, scaffold.stderr
    err = scaffold.stderr
    assert _EXPORT in err
    assert f"$env:{_VAR} = '<your GITHUB_TOKEN>'" in err
    # The plain value is not a secret, so it needs no variable.
    assert "MYLONITE_TARGET_ENV_LOG_LEVEL" not in err
    # The block comes before the scaffold's `next:` line.
    assert err.index(_EXPORT) < err.index("next:")
    assert _SECRET not in err + scaffold.stdout
    assert _SECRET not in out.read_text(encoding="utf-8")

    # Unset: `check` stops with exit 2 and names the variable, its key and the fix.
    missing = _mylonite(["check", "--target-file", str(out)], tmp_path)
    assert missing.returncode == _EXIT_CONFIG, missing.stderr
    assert _VAR in missing.stderr
    assert "GITHUB_TOKEN" in missing.stderr
    assert _EXPORT in missing.stderr
    assert _SECRET not in missing.stderr + missing.stdout

    # Set: the same file loads and `check` runs against the real server.
    monkeypatch.setenv(_VAR, _SECRET)
    ok = _mylonite(["check", "--target-file", str(out)], tmp_path)
    assert ok.returncode == _EXIT_SUCCESS, ok.stderr
    assert "write_note" in ok.stdout
