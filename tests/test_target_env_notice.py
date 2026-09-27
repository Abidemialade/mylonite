"""0.10.3 Task 1: a target file with credential placeholders names the
variables to set.

Mylonite keeps secrets out of every target file it writes by swapping each one
for a ``${MYLONITE_TARGET_...}`` placeholder. These tests pin the helper that
reads those placeholders back out of the written text, and the notice every
writer prints so the user knows which variables to set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite._redaction import redact_target_yaml, target_env_refs
from mylonite._target_env import env_notice_lines, write_redacted_target

_SECRET = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234"  # pragma: allowlist secret


# --- target_env_refs: the one source of truth --------------------------------


def test_refs_empty_when_file_has_no_placeholders() -> None:
    text = redact_target_yaml("family: myapp\ncommand: python\nenv:\n  LOG_LEVEL: debug\n")
    assert target_env_refs(text) == []


def test_refs_name_each_placeholder_with_its_original_key() -> None:
    source = (
        "family: myapp\n"
        "transport: sse\n"
        "url: https://example.invalid/mcp\n"
        "headers:\n"
        "  X-Api-Key: abc\n"
        "env:\n"
        f"  GITHUB_TOKEN: {_SECRET}\n"
        "  LOG_LEVEL: debug\n"
        "request:\n"
        "  headers:\n"
        "    Authorization: Bearer abc\n"
    )
    refs = target_env_refs(redact_target_yaml(source))
    assert refs == [
        ("MYLONITE_TARGET_ENV_GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("MYLONITE_TARGET_HEADERS_X_API_KEY", "X-Api-Key"),
        ("MYLONITE_TARGET_REQUEST_HEADERS_AUTHORIZATION", "Authorization"),
    ]


def test_refs_follow_file_order_and_are_deduplicated() -> None:
    text = (
        "headers:\n"
        "  B: ${MYLONITE_TARGET_HEADERS_B}\n"
        "  A: ${MYLONITE_TARGET_HEADERS_A}\n"
        "env:\n"
        "  B_AGAIN: ${MYLONITE_TARGET_HEADERS_B}\n"
    )
    assert target_env_refs(text) == [
        ("MYLONITE_TARGET_HEADERS_B", "B"),
        ("MYLONITE_TARGET_HEADERS_A", "A"),
    ]


def test_refs_ignore_hand_written_non_mylonite_references() -> None:
    text = "headers:\n  Authorization: Bearer ${MY_TOKEN}\n"
    assert target_env_refs(text) == []


def test_refs_empty_for_unparseable_text() -> None:
    assert target_env_refs(": : not yaml [") == []


# --- env_notice_lines: what every writer prints -------------------------------


def test_notice_is_empty_without_placeholders() -> None:
    assert env_notice_lines("family: myapp\n", Path("app.yaml")) == []


def test_notice_names_both_shell_forms_and_never_the_secret() -> None:
    text = redact_target_yaml(f"family: myapp\nenv:\n  GITHUB_TOKEN: {_SECRET}\n")
    block = "\n".join(env_notice_lines(text, Path("app.yaml")))
    assert "secrets were kept out of app.yaml" in block
    assert "export MYLONITE_TARGET_ENV_GITHUB_TOKEN='<your GITHUB_TOKEN>'" in block
    assert "$env:MYLONITE_TARGET_ENV_GITHUB_TOKEN = '<your GITHUB_TOKEN>'" in block
    assert _SECRET not in block
    assert block.isascii()


def test_notice_survives_console_redaction() -> None:
    """The block leaves through ``_cli_io.echo``, which masks ``token=...``
    shapes; a key named ``*_TOKEN`` must still print its export line intact."""
    from mylonite._redaction import redact

    text = redact_target_yaml(f"family: myapp\nenv:\n  API_TOKEN: {_SECRET}\n")
    for line in env_notice_lines(text, Path("app.yaml")):
        assert redact(line) == line


def test_write_redacted_target_writes_masked_copy_and_prints_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "target.yaml"
    write_redacted_target(dest, f"family: myapp\nenv:\n  GITHUB_TOKEN: {_SECRET}\n")
    assert _SECRET not in dest.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert "export MYLONITE_TARGET_ENV_GITHUB_TOKEN='<your GITHUB_TOKEN>'" in err
    assert _SECRET not in err


def test_write_redacted_target_prints_nothing_without_placeholders(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_redacted_target(tmp_path / "target.yaml", "family: myapp\ncommand: python\n")
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


# --- load error names the fix -------------------------------------------------


def test_load_error_names_variable_key_and_export_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mylonite.plugins._mcp.target_file import load_target_file

    path = tmp_path / "app.yaml"
    path.write_text(
        redact_target_yaml(
            f"family: myapp\ncommand: python\nweakness_classes: [W2]\n"
            f"env:\n  GITHUB_TOKEN: {_SECRET}\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("MYLONITE_TARGET_ENV_GITHUB_TOKEN", raising=False)
    with pytest.raises(ValueError) as info:
        load_target_file(path)
    msg = str(info.value)
    assert "MYLONITE_TARGET_ENV_GITHUB_TOKEN" in msg
    assert "GITHUB_TOKEN" in msg
    assert "export MYLONITE_TARGET_ENV_GITHUB_TOKEN='<your GITHUB_TOKEN>'" in msg
    assert msg.isascii()
