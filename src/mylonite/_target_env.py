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

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from mylonite._redaction import (
    REDACTION_PLACEHOLDER,
    redact_target_yaml,
    target_env_refs,
    target_masked_fields,
)

__all__ = [
    "echo_env_notice",
    "env_notice_lines",
    "posix_export_line",
    "powershell_env_line",
    "repo_secret_lines",
    "write_redacted_target",
]


#: Substring that marks a derived variable name as standing for a HEADER value
#: (``MYLONITE_TARGET_HEADERS_...`` or ``MYLONITE_TARGET_REQUEST_HEADERS_...``
#: — see ``target_yaml_env_ref_name``), as opposed to an ``env:`` entry. The
#: hint differs because a header's value is the WHOLE header line (e.g.
#: ``Bearer sk-...``), not a bare token — #183: the old hint (``<your
#: Authorization>``) read the same for both, so an operator filling in a
#: header variable would plausibly type just the token and get a malformed
#: header the target then rejects.
_HEADER_VAR_MARKER: Final = "_HEADERS_"


def _hint(key: str | None, var: str = "") -> str:
    # A quote in a key would break the shell line; the hint is only a label.
    if not key:
        return "<value>"
    label = key.replace(chr(39), "")
    if _HEADER_VAR_MARKER in var:
        return f"<the full {label} header value, e.g. Bearer ...>"
    return f"<your {label}>"


def posix_export_line(var: str, key: str | None) -> str:
    """``export VAR='<your KEY>'`` for bash, zsh and other POSIX shells.

    For a ``headers``/``request.headers`` variable the hint instead reads
    ``<the full KEY header value, e.g. Bearer ...>``, since that variable must
    hold the WHOLE header value, not just the bare token (#183).
    """
    return f"export {var}='{_hint(key, var)}'"


def powershell_env_line(var: str, key: str | None) -> str:
    """``$env:VAR = '<your KEY>'`` for PowerShell.

    See :func:`posix_export_line` for the header-value hint variant.
    """
    return f"$env:{var} = '{_hint(key, var)}'"


def env_notice_lines(text: str, target: Path) -> list[str]:
    """The block a writer prints after writing ``text`` to ``target``.

    Empty when the file holds no placeholder, so a writer can print it
    unconditionally.
    """
    lines: list[str] = []
    refs = target_env_refs(text)
    if refs:
        lines.append(
            f"note: secrets in headers and env were kept out of {target}. It reads them "
            "from these environment variables; set them before you use the file:"
        )
        lines.append("  bash/zsh:")
        lines.extend(f"    {posix_export_line(var, key)}" for var, key in refs)
        lines.append("  PowerShell:")
        lines.extend(f"    {powershell_env_line(var, key)}" for var, key in refs)
    if REDACTION_PLACEHOLDER in text:
        fields = target_masked_fields(text)
        where = f" ({', '.join(fields)})" if fields else ""
        lines.append(
            f"note: some values in {target}{where} are masked as {REDACTION_PLACEHOLDER} "
            "and no variable restores them; edit the file to put them back before you use it."
        )
    return lines


def echo_env_notice(text: str, target: Path) -> None:
    """Print :func:`env_notice_lines` to stderr (nothing when there is nothing to set)."""
    from mylonite._cli_io import echo_err

    for line in env_notice_lines(text, target):
        echo_err(line)


def repo_secret_lines(refs: Sequence[tuple[str, str]]) -> list[str]:
    """The block a gate PR prints/writes when its workflow needs repository
    secrets (#185). Reuses :func:`env_notice_lines`'s wording, adapted for
    GitHub Actions: the workflow reads the redacted target's placeholders via
    ``${{ secrets.<NAME> }}``, not an environment variable set by hand, so the
    operator has to add them under the repository's Settings -> Secrets
    before the gate workflow can run. Empty when ``refs`` is, so a caller can
    print it unconditionally.
    """
    if not refs:
        return []
    lines = [
        "note: the gate workflow reads target secrets from repository secrets "
        "(Settings -> Secrets and variables -> Actions); add these before it can run:"
    ]
    lines.extend(f"  - {var} (from {key})" for var, key in refs)
    return lines


def write_redacted_target(dest: Path, source_text: str) -> str:
    """Write a secret-free copy of a target file to ``dest`` and name its variables.

    Returns the text written, so a caller can cache it.
    """
    text = redact_target_yaml(source_text)
    dest.write_text(text, encoding="utf-8")
    echo_env_notice(text, dest)
    return text
