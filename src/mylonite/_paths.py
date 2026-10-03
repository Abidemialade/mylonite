"""Containment checks for paths that arrive from untrusted config.

``target.yaml`` is a shareable, repo-editable document — a teammate mails you
one, or a pull request edits the one in your repo. Five findings across three
independent chunk reviews (DCR-0011/0012/0013/0017/0020) reduce to one missing
step: a path from that document reached ``open()`` or a subprocess argv after
SHAPE validation only, never CONTAINMENT validation. ``is_absolute()`` is not a
security check.

:func:`resolve_contained` is that step, and it is the only one.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path, PurePath

__all__ = [
    "PathEscapesBase",
    "path_for_shell",
    "quote_for_shell",
    "resolve_contained",
    "safe_slug",
]


class PathEscapesBase(ValueError):
    """Raised when a config-supplied path resolves outside its allowed base."""


def resolve_contained(candidate: str | Path, *, base: str | Path, label: str) -> Path:
    """Resolve ``candidate`` under ``base`` and require containment.

    A relative candidate resolves against ``base``; an absolute one is checked
    as given. Symlinks are followed BEFORE the check (``Path.resolve()``), so a
    link inside ``base`` pointing outside it is refused too.

    ``label`` names the offending YAML field in the error so the operator can
    find it. Raises :class:`PathEscapesBase` on any escape.
    """
    base_resolved = Path(base).resolve()
    raw = Path(candidate)
    joined = raw if raw.is_absolute() else base_resolved / raw
    resolved = joined.resolve()
    if resolved != base_resolved and base_resolved not in resolved.parents:
        # Generic on purpose: this helper is shared by callers with different
        # "base" concepts (a target file's own directory, an operator-configured
        # scope root, ...). Each caller appends its own context-appropriate
        # closing clause rather than this function guessing one.
        msg = (
            f"{label} {str(candidate)!r} resolves to {resolved}, which is outside {base_resolved}."
        )
        raise PathEscapesBase(msg)
    return resolved


_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

#: A value made ONLY of these characters never needs quoting in any shell
#: this function targets (cmd, PowerShell, bash/Git Bash) -- returned
#: unchanged. NO backslash: every path reaching this function has already
#: been rendered with forward slashes (see :func:`path_for_shell`), and a
#: raw backslash a caller passes anyway (e.g. in a non-path value) is NOT
#: safe left bare -- a POSIX shell (what ``verification/rehearsal/
#: journey.sh``'s ``eval`` runs) treats an unquoted backslash as an escape
#: character and silently eats it.
_SAFE_UNQUOTED = re.compile(r"^[A-Za-z0-9_\-./:@+=]*$")

#: Characters that behave specially inside a Windows double-quoted string in
#: at least one of cmd, PowerShell *and* Git Bash/bash (which still expands
#: ``$...``/`` `...` `` and un-escapes ``\"`` inside double quotes) -- a
#: value containing any of these can't be made safe by wrapping it in `"..."`
#: on Windows, so :func:`quote_for_shell` falls back to POSIX quoting there
#: too, with a short note explaining why the line looks POSIX-quoted even on
#: Windows.
_UNSAFE_IN_WINDOWS_DOUBLE_QUOTES = ('"', "$", "`")


def quote_for_shell(value: str | Path) -> str:
    """Shell-safe quoting for a value inside a printed "run this" command.

    Returned UNCHANGED when it contains only characters no shell this
    function targets ever treats specially (letters, digits, and
    ``_-./:@+=``) -- the common case, and the one that keeps a plain
    forward-slash path (see :func:`path_for_shell`) or a bare ``--authorize``
    value reading exactly as a user would type it.

    Otherwise quoted by platform (``os.name``), since the two platforms this
    project runs on disagree about how:

    * **Windows (`os.name == "nt"`)**: wrapped in double quotes. That one
      form parses correctly in cmd, PowerShell *and* Git Bash/bash for a
      value containing a space -- the common case a Windows user profile
      path hits. It stops being safe once the value itself contains ``"``,
      ``$`` or a backtick (bash still gives those meaning inside double
      quotes), so that case falls back to the POSIX form below, with a
      trailing note -- this one printed line will look POSIX-quoted even on
      Windows, and that's deliberate, not a mistake to copy around.
    * **Everywhere else**: ``shlex.quote``, the POSIX-shell quoting every
      printed next-step command assumed before this function existed, and
      what ``verification/rehearsal/journey.sh`` (which greps a printed
      line and feeds it to ``eval``) requires.

    A value that still carries a backslash (never true of a path rendered by
    :func:`path_for_shell`, but not assumed of every caller) is NOT in the
    safe set and is quoted like any other special character -- an unquoted
    backslash is an escape character to the POSIX shell `journey.sh` runs,
    which would silently eat it.
    """
    text = str(value)
    if _SAFE_UNQUOTED.match(text):
        return text
    if os.name == "nt" and not any(ch in text for ch in _UNSAFE_IN_WINDOWS_DOUBLE_QUOTES):
        return f'"{text}"'
    quoted = shlex.quote(text)
    if os.name == "nt":
        return f'{quoted}  # quoted for a POSIX shell (e.g. Git Bash) -- contains ", $ or `'
    return quoted


def path_for_shell(path: str | Path) -> str:
    """Render ``path`` for a printed next-step command.

    Forward slashes on EVERY platform (``PurePath.as_posix()``) -- Python
    (``open()``, ``subprocess``, ``pathlib`` itself) accepts a forward-slash
    path on Windows exactly as it does on POSIX, but a native Windows
    backslash path does not survive a POSIX shell's ``eval`` (what
    ``verification/rehearsal/journey.sh`` runs on every platform, Windows
    included, via Git Bash): an unquoted backslash is an escape character
    there and gets silently eaten, corrupting the path. Printing every path
    with forward slashes sidesteps that in the common case (no embedded
    space) without needing to quote it at all.

    Still passed through :func:`quote_for_shell` afterwards, so a forward-
    slash path that DOES contain a space (or another character a shell
    would split on) is still quoted correctly for the platform.

    ``path`` already a ``PurePath`` (the common case -- every call site
    passes a real ``Path``) is asked for its OWN ``as_posix()`` directly,
    never re-parsed through the host's native ``Path``: re-parsing a
    ``PureWindowsPath`` through ``pathlib.Path`` on a POSIX host would treat
    its backslashes as literal filename characters instead of separators,
    which is exactly wrong for a value built to look like a Windows path
    regardless of which platform renders it (see the test suite, which
    builds one with ``PureWindowsPath`` precisely so it means the same thing
    on every CI runner).
    """
    as_posix = path.as_posix() if isinstance(path, PurePath) else Path(path).as_posix()
    return quote_for_shell(as_posix)


def safe_slug(value: str, *, fallback: str = "unknown") -> str:
    """Collapse ``value`` to characters safe in a filename or an identifier.

    ``pattern_id`` is an unconstrained ``str`` that can originate in a probed
    target's tool NAME (via ``seed_synth``), i.e. it is attacker-influenceable,
    and it is interpolated into artefact paths (DCR-0011). Everything outside
    ``[A-Za-z0-9._-]`` collapses to ``-``; an empty result becomes ``fallback``.
    """
    cleaned = _SLUG_UNSAFE.sub("-", value).strip("-_.")
    return cleaned or fallback
