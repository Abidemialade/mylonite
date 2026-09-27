"""Tell the user which environment variables a written target file needs.

Every target file Mylonite writes (``scan --scaffold``, the scan-dir copy,
``generate``'s copy, ``gate``'s copy) keeps secrets out of the file by
replacing them with ``${MYLONITE_TARGET_...}`` placeholders. Loading the file
later fails until those variables are set, so each writer prints the exact
variables here, read back from the written text by
:func:`mylonite._redaction.target_env_refs`. Secret values are never printed:
only the variable name and the original key it stands for.
"""

from __future__ import annotations

from pathlib import Path

from mylonite._redaction import REDACTION_PLACEHOLDER, redact_target_yaml, target_env_refs

__all__ = [
    "echo_env_notice",
    "env_notice_lines",
    "posix_export_line",
    "powershell_env_line",
    "write_redacted_target",
]


def _hint(key: str | None) -> str:
    # A quote in a key would break the shell line; the hint is only a label.
    return f"<your {key.replace(chr(39), '')}>" if key else "<value>"


def posix_export_line(var: str, key: str | None) -> str:
    """``export VAR='<your KEY>'`` for bash, zsh and other POSIX shells."""
    return f"export {var}='{_hint(key)}'"


def powershell_env_line(var: str, key: str | None) -> str:
    """``$env:VAR = '<your KEY>'`` for PowerShell."""
    return f"$env:{var} = '{_hint(key)}'"


def env_notice_lines(text: str, target: Path) -> list[str]:
    """The block a writer prints after writing ``text`` to ``target``.

    Empty when the file holds no placeholder, so a writer can print it
    unconditionally.
    """
    lines: list[str] = []
    refs = target_env_refs(text)
    if refs:
        lines.append(
            f"note: secrets were kept out of {target}. It reads them from these "
            "environment variables; set them before you use the file:"
        )
        lines.append("  bash/zsh:")
        lines.extend(f"    {posix_export_line(var, key)}" for var, key in refs)
        lines.append("  PowerShell:")
        lines.extend(f"    {powershell_env_line(var, key)}" for var, key in refs)
    if REDACTION_PLACEHOLDER in text:
        lines.append(
            f"note: some values in {target} are masked as {REDACTION_PLACEHOLDER} and "
            "no variable restores them; edit the file to put them back before you use it."
        )
    return lines


def echo_env_notice(text: str, target: Path) -> None:
    """Print :func:`env_notice_lines` to stderr (nothing when there is nothing to set)."""
    from mylonite._cli_io import echo_err

    for line in env_notice_lines(text, target):
        echo_err(line)


def write_redacted_target(dest: Path, source_text: str) -> str:
    """Write a secret-free copy of a target file to ``dest`` and name its variables.

    Returns the text written, so a caller can cache it.
    """
    text = redact_target_yaml(source_text)
    dest.write_text(text, encoding="utf-8")
    echo_env_notice(text, dest)
    return text
