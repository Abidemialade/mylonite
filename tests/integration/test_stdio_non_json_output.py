"""#195 end to end: a stdio MCP server that prints non-JSON to stdout must
not flood the console with a Python traceback per garbage line.

The SDK's own ``mcp.client.stdio`` read loop calls ``logger.exception(...)``
for every line it can't parse as a JSON-RPC message. With no handler
configured for that third-party logger, Python's ``logging.lastResort``
prints each one to stderr as a full traceback -- one per garbage line, on
every attempt. The parse failure is re-raised through the stream regardless,
so ``check``'s own catch site already turns the resulting connection failure
into one clear line; the traceback spam is pure noise on top of it.

A subprocess, not ``CliRunner``: the stdio MCP client needs a real stderr
file descriptor to launch the server.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

_EXIT_CONFIG = 2

_GARBAGE_SERVER = textwrap.dedent(
    """\
    import sys
    import time

    for _ in range(5):
        print("not json at all, just log noise from a misconfigured server", flush=True)
    time.sleep(2)
    sys.exit(1)
    """
)


def _mylonite(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    # Inherits os.environ (MYLONITE_EXPERIMENTAL=1 is set for the whole suite
    # by tests/conftest.py's autouse fixture, so `check` runs for real here).
    # PYTHONPATH points the child at the SAME `mylonite` this test imports --
    # not whatever an installed copy or a relative path would resolve to.
    import mylonite

    root = str(Path(mylonite.__file__).resolve().parents[1])
    pythonpath = os.pathsep.join([root, os.environ.get("PYTHONPATH", "")])
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
        timeout=60,
        check=False,
    )


def test_check_against_a_non_json_stdout_server_prints_no_traceback(tmp_path: Path) -> None:
    server = tmp_path / "garbage_server.py"
    server.write_text(_GARBAGE_SERVER, encoding="utf-8")
    target = tmp_path / "garbage.yaml"
    # args_with_scope / primary_tools etc. default fine; the server never
    # gets far enough to need a real tool surface.
    target.write_text(
        "family: garbagetest\n"
        f"command: {sys.executable}\n"
        f"args: ['{server.as_posix()}']\n"
        "weakness_classes: [W3]\n",
        encoding="utf-8",
    )
    result = _mylonite(["check", "--target-file", str(target)], tmp_path)
    assert result.returncode == _EXIT_CONFIG, (result.stdout, result.stderr)
    out = result.stdout + result.stderr
    assert "Failed to parse JSONRPC message" not in out, out
    assert "Traceback (most recent call last)" not in out, out
    # The real failure (the server closed the connection) still reaches the
    # operator as a clean, one-line error that names the executable -- this
    # isn't a silent swallow (#210). Never the script path/arg value itself
    # (#195 review finding): only the executable and an argument count.
    assert "could not launch or connect to the target" in out, out
    assert sys.executable in out
    assert str(server) not in out
    assert server.as_posix() not in out
    assert "1 argument(s), values withheld" in out
