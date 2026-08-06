"""Tests for the subprocess-based programmatic pytest runner.

These write throwaway test files into ``tmp_path`` and run them through
``run_test_file``. The UTF-8 case is the load-bearing Windows (A3) regression
guard — it must pass on Windows, where the child's stdio would otherwise
default to cp1252.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.scan import pytest_runner
from mylonite.scan.pytest_runner import PytestOutcome, PytestRunResult, run_test_file


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _reset_pytest_available_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with a clean (unpopulated) import-preflight cache.

    ``monkeypatch`` restores the module attribute to whatever it was before
    the test on teardown, so a test that forces the cache to a specific value
    (or clears it) never leaks into a sibling test.
    """
    monkeypatch.setattr(pytest_runner, "_pytest_available_cache", None)


def test_passing_file(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")
    result = run_test_file(f)
    assert isinstance(result, PytestRunResult)
    assert result.outcome is PytestOutcome.PASSED
    assert result.passed is True
    assert result.collected is True
    assert result.exit_code == 0


def test_failing_file_with_pytest_genuinely_present(tmp_path: Path) -> None:
    """Exit 1 when pytest IS installed and genuinely ran → FAILED, collected=True.

    This is the non-ambiguous half of exit 1: pytest imported fine (the
    preflight passed), it ran the file, and a real assertion failed.
    """
    f = _write(tmp_path, "test_bad.py", "def test_bad():\n    assert False\n")
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.FAILED
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
    assert result.outcome is PytestOutcome.COLLECTION_ERROR
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 2


def test_syntax_error_is_collection_error(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_syntax.py", "def test_x(:\n    assert True\n")
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.COLLECTION_ERROR
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 2


def test_no_tests_collected_is_not_collected(tmp_path: Path) -> None:
    """Bug 2 regression guard: exit 5 (no tests collected) must NOT count as
    ``collected`` — an empty file (or every test deselected) was not
    meaningfully validated, even though pytest itself ran cleanly."""
    f = _write(tmp_path, "test_empty.py", "x = 1\n")
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.NO_TESTS
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 5
    assert "no tests" in result.detail.lower()


def test_utf8_non_ascii_output(tmp_path: Path) -> None:
    """A3 Windows guard: non-ASCII child output must round-trip intact, not just
    avoid a crash.

    Route the non-ASCII through a FAILING assert message — pytest echoes assert
    messages even under ``-q``, so the text reaches ``result.stdout``. A silent
    cp1252 decode regression would turn ``café`` into mojibake (``cafÃ©``) or
    drop it; asserting the exact bytes survive is what actually guards A3. (A
    passing test's ``print`` is captured/suppressed under ``-q`` and would never
    surface the corruption.)
    """
    marker = "café — naïve ✓ Ω"
    body = f'def test_unicode():\n    assert False, "{marker}"\n'
    f = _write(tmp_path, "test_unicode.py", body)
    result = run_test_file(f)
    assert result.passed is False
    assert result.collected is True
    assert result.exit_code == 1
    # The exact non-ASCII assert message must survive decoding intact.
    assert marker in result.stdout, result.stdout


def test_timeout_returns_result(tmp_path: Path) -> None:
    body = "import time\n\ndef test_slow():\n    time.sleep(5)\n    assert True\n"
    f = _write(tmp_path, "test_slow.py", body)
    result = run_test_file(f, timeout=0.5)
    assert result.outcome is PytestOutcome.TIMEOUT
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == -1
    assert "timed out" in result.detail.lower()


# --- Bug 1: import preflight (pytest missing must not masquerade as "ran") ---


def test_missing_pytest_is_not_collected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression guard for Bug 1: on OLD code, a missing pytest surfaced as
    exit 1 ("tests ran but some failed"), which was misclassified as
    ``collected=True``. Simulate pytest being unavailable via the preflight
    seam (never touching the real subprocess) and assert the runner refuses to
    claim the file was collected/run at all."""
    monkeypatch.setattr(pytest_runner, "_probe_pytest_importable", lambda: False)
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.PYTEST_UNAVAILABLE
    assert result.passed is False
    assert result.collected is False


def test_missing_pytest_never_invokes_real_pytest_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the preflight says pytest is unavailable, ``run_test_file`` must
    return WITHOUT ever shelling out to ``sys.executable -m pytest`` — that
    invocation is exactly what would have produced the ambiguous exit 1."""
    monkeypatch.setattr(pytest_runner, "_probe_pytest_importable", lambda: False)
    calls: list[list[str]] = []
    real_run = pytest_runner.subprocess.run

    def _spy_run(cmd: list[str], **kwargs: object) -> object:
        calls.append(cmd)
        return real_run(cmd, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pytest_runner.subprocess, "run", _spy_run)
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")
    run_test_file(f)
    assert calls == []


def test_import_preflight_is_memoized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``run_test_file`` may be called once per emitted test, potentially many
    times per validation run — the cheap ``import pytest`` probe must only
    shell out ONCE per process, not once per call."""
    real_probe = pytest_runner._probe_pytest_importable
    call_count = 0

    def _counting_probe() -> bool:
        nonlocal call_count
        call_count += 1
        return real_probe()

    monkeypatch.setattr(pytest_runner, "_probe_pytest_importable", _counting_probe)
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")

    run_test_file(f)
    run_test_file(f)

    assert call_count == 1
