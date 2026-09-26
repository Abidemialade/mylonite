"""Which Python versions Mylonite declares, and the note it prints outside them.

`requires-python` once stopped at `<3.14` because litellm 1.83.8-1.92.x did.
litellm 1.93.0 and later declare `<3.15`, so Mylonite supports 3.11-3.14. These
tests pin that range so a later edit cannot quietly drop 3.14 again, and check
that the "unsupported Python" note stays silent on every supported version.
"""

from __future__ import annotations

import tomllib
import types
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

from mylonite import cli

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
_SUPPORTED = ("3.11", "3.12", "3.13", "3.14")


def _project() -> dict[str, object]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project: dict[str, object] = data["project"]
    return project


@pytest.mark.parametrize("version", _SUPPORTED)
def test_requires_python_admits_every_supported_version(version: str) -> None:
    spec = SpecifierSet(str(_project()["requires-python"]))
    assert f"{version}.0" in spec, f"requires-python {spec} rejects Python {version}"


def test_requires_python_stops_below_3_15() -> None:
    # litellm declares <3.15; a wider bound would trade a clear "unsupported
    # Python" message for a confusing resolver error.
    spec = SpecifierSet(str(_project()["requires-python"]))
    assert "3.15.0" not in spec
    assert "3.10.0" not in spec


@pytest.mark.parametrize("version", _SUPPORTED)
def test_a_classifier_names_every_supported_version(version: str) -> None:
    classifiers = _project()["classifiers"]
    assert isinstance(classifiers, list)
    assert f"Programming Language :: Python :: {version}" in classifiers


def _run_note(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], vi: tuple[int, int]
) -> str:
    fake_sys = types.SimpleNamespace(version_info=vi)
    monkeypatch.setattr(cli, "sys", fake_sys)
    cli._warn_unsupported_python()
    monkeypatch.undo()
    return capsys.readouterr().err


@pytest.mark.parametrize("vi", [(3, 11), (3, 12), (3, 13), (3, 14)])
def test_no_unsupported_python_note_on_a_supported_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], vi: tuple[int, int]
) -> None:
    assert _run_note(monkeypatch, capsys, vi) == ""


def test_the_note_fires_on_3_15_and_names_the_supported_range(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    err = _run_note(monkeypatch, capsys, (3, 15))
    assert "3.11-3.14" in err
    assert "3.15" in err
