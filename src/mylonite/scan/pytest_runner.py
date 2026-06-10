"""Programmatic pytest runner used by the validation engine (Phase 2).

The validator (PR 5) hands an *emitted* pytest file to ``run_test_file`` and
needs a clean pass/fail signal plus captured output. This runner shells out to
``sys.executable -m pytest`` in a **subprocess** rather than calling
``pytest.main()`` in-process, deliberately:

* The validator that calls this is itself executing under pytest, so an
  in-process ``pytest.main()`` would be a re-entrant pytest invocation — a
  documented footgun (shared plugin state, fixture caches, capture managers).
* The emitted test drives ``asyncio.run`` against an MCP target; nesting an
  event loop inside an already-running one is fragile. A fresh process gets a
  fresh interpreter and a fresh default event loop.
* Process isolation also means a crash / hang in the target can't take down the
  validator: we cap it with ``timeout`` and reap the child.

**Windows UTF-8 handling (A3 — this project has a cp1252 history).** On Windows
the child interpreter's stdio defaults to the legacy ANSI code page, so a test
that prints non-ASCII (or pytest rendering a unicode assertion repr) raises
``UnicodeEncodeError`` in the child and/or yields mojibake we can't decode. We
force the child to emit UTF-8 via ``PYTHONUTF8=1`` *and* ``PYTHONIOENCODING=utf-8``
(``PYTHONUTF8`` alone is insufficient on 3.11; ``PYTHONIOENCODING`` covers the
remaining stdio paths), and decode the captured bytes as UTF-8 with
``errors="replace"`` as a final backstop so a stray undecodable byte never
crashes the runner.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PytestRunResult", "run_test_file"]


@dataclass(frozen=True)
class PytestRunResult:
    """Outcome of running a single emitted test file under pytest.

    Attributes:
        passed: True only when pytest exited 0 (every collected test passed).
        exit_code: The child pytest process exit code (``-1`` on timeout).
        collected: False when pytest failed to *collect* the file (import /
            syntax error → exit 2) or timed out before running; True once the
            file was collected, even if no tests were found (exit 5) or some
            failed (exit 1).
        stdout: Decoded child stdout (UTF-8, ``errors="replace"``).
        stderr: Decoded child stderr (UTF-8, ``errors="replace"``).
        detail: One-line human-readable summary of the outcome.
    """

    passed: bool
    exit_code: int
    collected: bool
    stdout: str
    stderr: str
    detail: str


# pytest's documented ExitCode values (see ``pytest.ExitCode``):
#   0 OK              — all collected tests passed
#   1 TESTS_FAILED    — tests ran, some failed
#   2 INTERRUPTED     — collection error / interrupted before/while running
#   3 INTERNAL_ERROR  — internal pytest error
#   4 USAGE_ERROR     — bad CLI usage
#   5 NO_TESTS_COLLECTED — file collected but contained no tests
def _classify(exit_code: int) -> tuple[bool, bool, str]:
    """Map a pytest exit code to ``(passed, collected, detail)``."""
    if exit_code == 0:
        return True, True, "all tests passed"
    if exit_code == 1:
        return False, True, "tests ran but some failed"
    if exit_code == 2:
        # Collection error (import/syntax error) or interruption before run.
        return False, False, "collection error or interruption (exit 2)"
    if exit_code == 3:
        return False, False, "internal pytest error (exit 3)"
    if exit_code == 4:
        return False, False, "pytest usage error (exit 4)"
    if exit_code == 5:
        return False, True, "no tests collected"
    return False, False, f"unexpected pytest exit code {exit_code}"


def run_test_file(
    path: str | os.PathLike[str],
    *,
    timeout: float = 120.0,
) -> PytestRunResult:
    """Run a single test file under pytest in an isolated subprocess.

    Args:
        path: Path to the emitted pytest file.
        timeout: Seconds before the child is killed; on expiry a result with
            ``passed=False, collected=False, exit_code=-1`` is returned (the
            ``TimeoutExpired`` is caught, never propagated).

    Returns:
        A :class:`PytestRunResult` describing the outcome.
    """
    test_path = Path(path)
    # Use the test file's parent as an isolated rootdir so the project's own
    # pytest config / plugins / addopts don't bleed into the emitted run. A bare
    # filename has an empty parent (``Path("")``); fall back to the cwd.
    rootdir = test_path.parent if str(test_path.parent) else Path.cwd()

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(test_path),
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",  # do NOT inherit the repo's addopts (coverage, -ra, etc.)
        "--rootdir",
        str(rootdir),
        "-q",
    ]

    # Force the child to speak UTF-8 on every platform (Windows A3 guard).
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    }

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        # Decode any partial captured output for diagnostics; never re-raise.
        out = _coerce_stream(exc.stdout)
        err = _coerce_stream(exc.stderr)
        return PytestRunResult(
            passed=False,
            collected=False,
            exit_code=-1,
            stdout=out,
            stderr=err,
            detail=f"pytest timed out after {timeout:g}s",
        )

    passed, collected, detail = _classify(completed.returncode)
    return PytestRunResult(
        passed=passed,
        collected=collected,
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        detail=detail,
    )


def _coerce_stream(stream: str | bytes | None) -> str:
    """Normalise a possibly-bytes/None subprocess stream to a UTF-8 string."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream
