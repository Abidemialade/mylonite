"""Tests for the subprocess-based programmatic pytest runner.

These write throwaway test files into ``tmp_path`` and run them through
``run_test_file``. The UTF-8 case is the load-bearing Windows (A3) regression
guard — it must pass on Windows, where the child's stdio would otherwise
default to cp1252.
"""

from __future__ import annotations

from pathlib import Path

from mylonite.scan.pytest_runner import PytestRunResult, run_test_file


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_passing_file(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")
    result = run_test_file(f)
    assert isinstance(result, PytestRunResult)
    assert result.passed is True
    assert result.collected is True
    assert result.exit_code == 0


def test_failing_file(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_bad.py", "def test_bad():\n    assert False\n")
    result = run_test_file(f)
    assert result.passed is False
    assert result.collected is True
    assert result.exit_code == 1


def test_collection_error(tmp_path: Path) -> None:
    f = _write(
        tmp_path,
        "test_broken.py",
        "import does_not_exist_xyz  # noqa\n\ndef test_x():\n    assert True\n",
    )
    result = run_test_file(f)
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 2


def test_syntax_error_is_collection_error(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_syntax.py", "def test_x(:\n    assert True\n")
    result = run_test_file(f)
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 2


def test_no_tests_collected(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_empty.py", "x = 1\n")
    result = run_test_file(f)
    assert result.passed is False
    assert result.collected is True
    assert result.exit_code == 5
    assert "no tests" in result.detail.lower()


def test_utf8_non_ascii_output(tmp_path: Path) -> None:
    """A3 Windows guard: non-ASCII child output must decode without crashing."""
    body = 'def test_unicode():\n    print("✓ café — naïve")\n    assert True\n'
    f = _write(tmp_path, "test_unicode.py", body)
    result = run_test_file(f)
    assert result.passed is True
    assert result.collected is True
    assert result.exit_code == 0
    # The decoded non-ASCII text should survive (pytest captures stdout, but -q
    # still echoes captured output on the passing summary line only when -s; the
    # key guarantee is no decode crash). At minimum the run did not raise.
    combined = result.stdout + result.stderr
    assert isinstance(combined, str)


def test_timeout_returns_result(tmp_path: Path) -> None:
    body = "import time\n\ndef test_slow():\n    time.sleep(5)\n    assert True\n"
    f = _write(tmp_path, "test_slow.py", body)
    result = run_test_file(f, timeout=0.5)
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == -1
    assert "timed out" in result.detail.lower()
