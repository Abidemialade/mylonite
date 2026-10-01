"""Unit tests for scripts/check_test_count.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_test_count as gate  # noqa: E402

# --- read_floor -------------------------------------------------------------


def test_read_floor_reads_an_integer(tmp_path: Path) -> None:
    path = tmp_path / "floor.txt"
    path.write_text("3278\n", encoding="utf-8")
    assert gate.read_floor(path) == 3278


def test_read_floor_rejects_non_integer_content(tmp_path: Path) -> None:
    path = tmp_path / "floor.txt"
    path.write_text("not a number\n", encoding="utf-8")
    with pytest.raises(gate.CollectionError):
        gate.read_floor(path)


def test_the_committed_floor_file_is_a_single_integer() -> None:
    assert gate.read_floor() > 0


# --- collected_count: a real pytest subprocess over a tiny synthetic suite --


def test_collected_count_parses_a_real_pytest_run(tmp_path: Path) -> None:
    (tmp_path / "test_tiny.py").write_text(
        "def test_a():\n    pass\n\n\ndef test_b():\n    pass\n", encoding="utf-8"
    )
    assert gate.collected_count(cwd=tmp_path) == 2


def test_collected_count_raises_on_a_real_collection_error(tmp_path: Path) -> None:
    (tmp_path / "test_broken.py").write_text("def test_a(\n", encoding="utf-8")  # syntax error
    with pytest.raises(gate.CollectionError):
        gate.collected_count(cwd=tmp_path)


# --- collected_count: parsing edge cases, via a monkeypatched subprocess ----


class _FakeCompletedProcess:
    def __init__(self, stdout: str, stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_collected_count_accepts_the_singular_form(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess("...\n1 test collected in 0.01s\n"),
    )
    assert gate.collected_count() == 1


def test_collected_count_raises_when_no_summary_line_is_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: _FakeCompletedProcess("huh?\n"))
    with pytest.raises(gate.CollectionError):
        gate.collected_count()


def test_collected_count_raises_on_nonzero_exit_even_with_a_parseable_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(
            "3278 tests collected, 2 errors in 1.0s", returncode=2
        ),
    )
    with pytest.raises(gate.CollectionError):
        gate.collected_count()


# --- main(): the label-gated floor check ------------------------------------


def test_main_passes_when_count_is_at_or_above_the_floor(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(gate, "read_floor", lambda: 10)
    monkeypatch.setattr(gate, "collected_count", lambda **k: 10)
    assert gate.main([]) == 0
    monkeypatch.setattr(gate, "collected_count", lambda **k: 11)
    assert gate.main([]) == 0
    assert "11 tests collected" in capsys.readouterr().out


def test_main_fails_when_count_drops_below_the_floor_with_no_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate, "read_floor", lambda: 10)
    monkeypatch.setattr(gate, "collected_count", lambda **k: 9)
    assert gate.main([]) == 1


def test_main_allows_a_drop_with_the_tests_removed_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate, "read_floor", lambda: 10)
    monkeypatch.setattr(gate, "collected_count", lambda **k: 9)
    monkeypatch.setenv("PR_LABELS", "needs-review, tests-removed")
    assert gate.main(["--labels-env", "PR_LABELS"]) == 0


def test_main_ignores_an_unrelated_label(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "read_floor", lambda: 10)
    monkeypatch.setattr(gate, "collected_count", lambda **k: 9)
    monkeypatch.setenv("PR_LABELS", "no-docs")
    assert gate.main(["--labels-env", "PR_LABELS"]) == 1


def test_main_surfaces_a_collection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> int:
        raise gate.CollectionError("boom")

    monkeypatch.setattr(gate, "read_floor", _boom)
    assert gate.main([]) == 1
