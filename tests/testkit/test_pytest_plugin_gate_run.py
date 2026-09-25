"""``MYLONITE_REQUIRE_GATE_RUN``: the committed gate must actually run in CI.

Each case runs a real pytest session in a subprocess, so the ``pytest11`` plugin
is loaded exactly as it is in a consumer's environment.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_MARKED_PASS = """
import pytest

@pytest.mark.mylonite_security
def test_gate():
    assert True
"""

_MARKED_SKIP = """
import pytest

@pytest.mark.mylonite_security
@pytest.mark.skipif(True, reason="re-drives the real target live")
def test_gate():
    assert True
"""

_UNMARKED_SKIP = """
import pytest

@pytest.mark.skip(reason="the consumer's own skip")
def test_other():
    assert True

def test_passes():
    assert True
"""


def _run(tmp_path: Path, source: str, *, require: bool, extra: tuple[str, ...] = ()) -> int:
    (tmp_path / "test_gate_sample.py").write_text(source, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "MYLONITE_REQUIRE_GATE_RUN"}
    if require:
        env["MYLONITE_REQUIRE_GATE_RUN"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *extra, str(tmp_path)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode


def test_unset_leaves_a_skipped_gate_test_green(tmp_path: Path) -> None:
    """The keyless local default is unchanged."""
    assert _run(tmp_path, _MARKED_SKIP, require=False) == pytest.ExitCode.OK


def test_set_fails_a_skipped_gate_test(tmp_path: Path) -> None:
    assert _run(tmp_path, _MARKED_SKIP, require=True) == pytest.ExitCode.TESTS_FAILED


def test_set_passes_a_gate_test_that_ran(tmp_path: Path) -> None:
    assert _run(tmp_path, _MARKED_PASS, require=True) == pytest.ExitCode.OK


def test_set_fails_when_no_gate_test_was_collected(tmp_path: Path) -> None:
    source = "def test_unrelated():\n    assert True\n"
    assert _run(tmp_path, source, require=True) == pytest.ExitCode.TESTS_FAILED


def test_set_does_not_inspect_unmarked_tests(tmp_path: Path) -> None:
    """A consumer's own skipped tests are not the gate's business."""
    source = _UNMARKED_SKIP + _MARKED_PASS.replace("import pytest\n", "")
    assert _run(tmp_path, source, require=True) == pytest.ExitCode.OK


def test_set_leaves_collect_only_alone(tmp_path: Path) -> None:
    """``--collect-only`` runs nothing by design, so it is never a failure."""
    code = _run(tmp_path, _MARKED_SKIP, require=True, extra=("--collect-only",))
    assert code == pytest.ExitCode.OK
