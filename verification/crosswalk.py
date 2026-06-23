"""Loader + validator for ``crosswalk.yaml`` (external label -> W-class).

The crosswalk is the only Mylonite-authored input to the verification harness,
so it is validated strictly: every mapped class must be a real Mylonite weakness
class, and every row must carry a justifying note.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

#: The canonical Mylonite weakness classes (mirrors the frozenset used by
#: ``mylonite.plugins._mcp.target_file``). Kept local so the harness validates
#: against a stable contract rather than importing private internals.
WEAKNESS_CLASSES: frozenset[str] = frozenset({"W1", "W2", "W3", "W4"})

_DEFAULT_PATH = Path(__file__).with_name("crosswalk.yaml")


class CrosswalkRow(BaseModel):
    """One external label and the W-classes it maps to."""

    name: str = ""
    mylonite: list[str]
    note: str
    upstream_url: str = ""

    @field_validator("mylonite")
    @classmethod
    def _validate_classes(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("crosswalk row maps to no weakness classes")
        bad = [c for c in v if c not in WEAKNESS_CLASSES]
        if bad:
            raise ValueError(f"unknown weakness class(es) {bad}; valid: {sorted(WEAKNESS_CLASSES)}")
        return v

    @field_validator("note")
    @classmethod
    def _require_note(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("crosswalk row must carry a justifying note")
        return v


class Crosswalk(BaseModel):
    """The full crosswalk: dataset -> label -> row."""

    datasets: dict[str, dict[str, CrosswalkRow]]

    def classes_for(self, dataset: str, label: str) -> list[str]:
        """W-classes mapped for ``dataset``/``label``; raises ``KeyError`` if absent."""
        return self.datasets[dataset][label].mylonite

    def primary_class(self, dataset: str, label: str) -> str:
        """First mapped W-class — used only to group rows in reports."""
        return self.classes_for(dataset, label)[0]


def load_crosswalk(path: Path | None = None) -> Crosswalk:
    """Parse and validate ``crosswalk.yaml`` (defaults to the bundled file)."""
    raw = yaml.safe_load((path or _DEFAULT_PATH).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("crosswalk.yaml must be a mapping of dataset -> label -> row")
    return Crosswalk(datasets=raw)
