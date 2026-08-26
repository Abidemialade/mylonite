"""Mitigation-guidance snippets, keyed by weakness class.

A small, dependency-free leaf package: the per-weakness mitigation markdown lives
here as package data and is read by :func:`snippet`. Both the gate (PR-body
generation) and the plugins layer (a twin's ``control_context``) import from
here, so neither depends on the other for this text -- keeping the layering
direction clean (``plugins`` no longer reaches up into ``gate`` for it).
"""

from __future__ import annotations

from importlib import resources as _ir


def snippet(weakness_class: str) -> str:
    """The mitigation-guidance markdown for ``weakness_class`` (e.g. ``"W2"``), stripped."""
    base = _ir.files("mylonite.mitigations")
    return (base / f"{weakness_class}.md").read_text(encoding="utf-8").strip()
