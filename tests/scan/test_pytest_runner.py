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


# --- a pass means a test actually ran and passed ------------------------------


def test_all_skipped_file_is_not_a_pass(tmp_path: Path) -> None:
    """Exit 0 with every test skipped ran nothing. It must not read as a pass."""
    f = _write(
        tmp_path,
        "test_skip.py",
        "import pytest\n\n@pytest.mark.skip(reason='x')\ndef test_x():\n    assert False\n",
    )
    result = run_test_file(f)
    assert result.exit_code == 0
    assert result.outcome is PytestOutcome.ALL_SKIPPED
    assert result.passed is False


def test_one_pass_among_skips_is_a_pass(tmp_path: Path) -> None:
    f = _write(
        tmp_path,
        "test_mixed.py",
        "import pytest\n\n@pytest.mark.skip(reason='x')\ndef test_a():\n    pass\n\n"
        "def test_b():\n    assert True\n",
    )
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.PASSED
    assert result.passed is True


def test_exit_zero_without_a_summary_is_not_a_pass() -> None:
    """With no readable pass count, exit 0 is not taken as proof of a pass."""
    assert pytest_runner._classify(0, stdout="") == (
        PytestOutcome.ALL_SKIPPED,
        "pytest exited 0 but no test passed (every test was skipped or none ran)",
    )


def test_collect_only_collects_without_running(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_bad.py", "def test_bad():\n    assert False\n")
    result = run_test_file(f, collect_only=True)
    assert result.outcome is PytestOutcome.COLLECTED
    assert result.passed is False
    assert result.collected is True


# --- failure_tail: a bare exit code says WHAT, not WHY ------------------------


def test_internal_error_from_a_raising_hook(tmp_path: Path) -> None:
    """A conftest hook that raises during configure crashes pytest itself
    (exit 3), not the test it's running — the real-world shape of an
    ``INTERNALERROR`` that a wheel-install plugin mismatch can also produce."""
    (tmp_path / "conftest.py").write_text(
        "def pytest_configure(config):\n    raise RuntimeError('boom-configure')\n",
        encoding="utf-8",
    )
    f = _write(tmp_path, "test_ok.py", "def test_ok():\n    assert True\n")
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.INTERNAL_ERROR
    assert result.passed is False
    assert result.collected is False
    assert result.exit_code == 3
    tail = pytest_runner.failure_tail(result)
    assert "INTERNALERROR" in tail
    assert "boom-configure" in tail


def test_failure_tail_is_bounded_and_prioritises_diagnostic_lines() -> None:
    """Noisy stdout surrounding a short ``INTERNALERROR`` block must not push
    the diagnostic lines out of the budget."""
    noise = "\n".join(f"captured stdout line {i}" for i in range(200))
    result = PytestRunResult(
        outcome=PytestOutcome.INTERNAL_ERROR,
        exit_code=3,
        stdout=noise,
        stderr="INTERNALERROR> Traceback (most recent call last):\nINTERNALERROR> RuntimeError: boom\n",
        detail="internal pytest error (exit 3)",
    )
    tail = pytest_runner.failure_tail(result, max_chars=600)
    assert len(tail) <= 600
    assert "INTERNALERROR" in tail
    assert "RuntimeError: boom" in tail


def test_failure_tail_redacts_secret_shaped_strings() -> None:
    """A secret-shaped token captured in a test's own output (e.g. echoed from
    an env var) must never reach a report un-redacted."""
    secret = "sk-ant-" + "a" * 24  # pragma: allowlist secret
    result = PytestRunResult(
        outcome=PytestOutcome.INTERNAL_ERROR,
        exit_code=3,
        stdout="",
        stderr=f"INTERNALERROR> RuntimeError: boom {secret}\n",
        detail="internal pytest error (exit 3)",
    )
    tail = pytest_runner.failure_tail(result)
    assert secret not in tail
    assert "REDACTED" in tail


def test_ini_file_discovery_cannot_find_an_ancestor_project_config(tmp_path: Path) -> None:
    """Root-cause regression guard for a real CI-only internal error.

    pytest's ini-file discovery ignores ``--rootdir`` and walks UP from the
    test file looking for an ini (``pyproject.toml``/``pytest.ini``/...). When
    the emitted test is written inside a project whose OWN ini sets
    ``filterwarnings = ["error"]`` next to an option no installed plugin
    recognises (mylonite's own `pyproject.toml` does exactly this, pairing
    `filterwarnings=error` with `asyncio_mode`, an option `pytest-asyncio`
    defines — absent from a plain wheel install), pytest's own "unknown
    config option" warning gets promoted to an exception raised inside the
    `pytest_collection` hook, where nothing catches it: INTERNALERROR (exit
    3). ``-o addopts=`` alone does not stop this — only pinning an isolated
    ini with ``-c`` does, regardless of where the emitted test lives."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'filterwarnings = ["error"]\n'
        'mylonite_regression_guard_unknown_option = "x"\n',
        encoding="utf-8",
    )
    nested = tmp_path / "generated"
    nested.mkdir()
    f = _write(nested, "test_ok.py", "def test_ok():\n    assert True\n")

    result = run_test_file(f)

    assert result.outcome is PytestOutcome.PASSED, (result.detail, result.stdout, result.stderr)
    assert result.passed is True
    assert result.exit_code == 0


def test_failure_tail_empty_when_no_output() -> None:
    result = PytestRunResult(
        outcome=PytestOutcome.TIMEOUT, exit_code=-1, stdout="", stderr="", detail="timed out"
    )
    assert pytest_runner.failure_tail(result) == ""


def test_collect_only_on_a_broken_file_is_a_collection_error(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_syntax.py", "def test_x(:\n    assert True\n")
    result = run_test_file(f, collect_only=True)
    assert result.outcome is PytestOutcome.COLLECTION_ERROR
    assert result.collected is False


def test_collect_only_on_an_empty_file_is_no_tests(tmp_path: Path) -> None:
    f = _write(tmp_path, "test_empty.py", "x = 1\n")
    result = run_test_file(f, collect_only=True)
    assert result.outcome is PytestOutcome.NO_TESTS
    assert result.collected is False


def test_pass_count_in_a_warning_is_not_a_pass(tmp_path: Path) -> None:
    """Only pytest's final summary line counts: a warning that says "3 passed"
    on a file whose every test skipped must not read as a pass."""
    f = _write(
        tmp_path,
        "test_warn.py",
        "import warnings\n\nimport pytest\n\n\n"
        "def test_a():\n"
        "    warnings.warn('3 passed')\n"
        "    pytest.skip('no target')\n",
    )
    result = run_test_file(f)
    assert result.exit_code == 0
    assert "3 passed" in result.stdout
    assert result.outcome is PytestOutcome.ALL_SKIPPED
    assert result.passed is False


def test_inherited_pytest_addopts_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """-rA would print each test's captured output; it must not reach the child."""
    monkeypatch.setenv("PYTEST_ADDOPTS", "-rA")
    f = _write(
        tmp_path,
        "test_skip_print.py",
        "import pytest\n\n\ndef test_a():\n    print('1 passed')\n    pytest.skip('x')\n",
    )
    result = run_test_file(f)
    assert result.outcome is PytestOutcome.ALL_SKIPPED
    assert "SKIPPED" not in result.stdout
