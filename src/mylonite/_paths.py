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

import re
from pathlib import Path

__all__ = ["PathEscapesBase", "resolve_contained", "safe_slug"]


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


def safe_slug(value: str, *, fallback: str = "unknown") -> str:
    """Collapse ``value`` to characters safe in a filename or an identifier.

    ``pattern_id`` is an unconstrained ``str`` that can originate in a probed
    target's tool NAME (via ``seed_synth``), i.e. it is attacker-influenceable,
    and it is interpolated into artefact paths (DCR-0011). Everything outside
    ``[A-Za-z0-9._-]`` collapses to ``-``; an empty result becomes ``fallback``.
    """
    cleaned = _SLUG_UNSAFE.sub("-", value).strip("-_.")
    return cleaned or fallback
