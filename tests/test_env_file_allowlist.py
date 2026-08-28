"""`--env-file` must accept the variables this project's own .env.example ships.

It accepted 7 of 18 and rejected 11 -- including MYLONITE_MODEL, which
.env.example itself marks required -- telling the operator they were "not a
recognised provider credential/config var name". A user following our own
example file hit an error on their first run.

The allowlist is derived from `config._EnvRunConfig`, the typed settings object
that defines which MYLONITE_* vars actually mean something, so the loader and
the consumer cannot drift apart. It is NOT a `MYLONITE_*` prefix match:
MYLONITE_API_BASE was the SSRF / key-exfiltration vector in DCR-0002 (0.7.9),
and a prefix rule would admit every future network-reaching variable
automatically.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mylonite.cli import _load_env_file

_ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"
_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=")


def _example_keys() -> list[str]:
    """Every variable named in .env.example, commented-out lines included."""
    keys: list[str] = []
    for raw in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lstrip("#").strip()
        match = _ASSIGNMENT.match(line)
        if match and match.group(1) not in keys:
            keys.append(match.group(1))
    return keys


def test_env_example_is_not_empty() -> None:
    """Guard the guard: a parsing change that finds nothing must fail loudly."""
    assert len(_example_keys()) >= 15


@pytest.mark.parametrize("key", _example_keys())
def test_every_documented_variable_is_accepted(
    key: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # `_load_env_file` writes os.environ DIRECTLY, which monkeypatch cannot undo
    # unless it already owns the key. Claiming it first makes teardown restore
    # the original (absent) value, so a loaded MYLONITE_MODEL=1 cannot leak into
    # another test's model resolution.
    monkeypatch.setenv(key, "__claimed_for_teardown__")
    monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / ".env"
    # A syntactically valid value for every shape in the file (ints, floats,
    # urls, keys) -- api_base is validated separately and must not be
    # credentialed.
    env_file.write_text(f"{key}=1\n", encoding="utf-8")

    _load_env_file(env_file)

    err = capsys.readouterr().err
    assert f"ignored {key}" not in err, err
    assert key in err  # reported as loaded


def test_an_unknown_mylonite_variable_is_still_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Not a prefix match. A name the tool does not consume is still dropped."""
    env_file = tmp_path / ".env"
    env_file.write_text("MYLONITE_TOTALLY_MADE_UP=1\n", encoding="utf-8")

    _load_env_file(env_file)

    assert "ignored MYLONITE_TOTALLY_MADE_UP" in capsys.readouterr().err


def test_an_unrelated_variable_is_still_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("PATH=/tmp/evil\nHOME=/tmp/evil\n", encoding="utf-8")

    _load_env_file(env_file)

    err = capsys.readouterr().err
    assert "ignored" in err
    assert "PATH" in err
    assert "HOME" in err
