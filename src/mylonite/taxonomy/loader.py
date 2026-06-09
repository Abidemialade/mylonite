"""Loaders for the bundled threat-taxonomy YAML data files.

Each loader reads one YAML file from ``mylonite/taxonomy/data/``, validates
every entry against its Pydantic model, and returns a frozen tuple. Errors
fail loud — the data files are part of the public API and we want a clear
signal if they drift out of sync with the models.

The loaders are cached via ``functools.lru_cache`` so repeated calls don't
re-parse YAML, but the cache is per-process and resets on import.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from importlib.resources import files
from typing import TypeVar

import yaml
from pydantic import TypeAdapter

from mylonite.taxonomy.models import (
    AtlasTactic,
    AtlasTechnique,
    NistAiRmfSubcategory,
    OwaspAsiEntry,
    OwaspLlmEntry,
)

_T = TypeVar("_T")


def _load(filename: str, model: type[_T]) -> tuple[_T, ...]:
    text = files("mylonite.taxonomy.data").joinpath(filename).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if not isinstance(raw, list):
        msg = f"{filename} must be a YAML list of entries; got {type(raw).__name__}"
        raise ValueError(msg)
    adapter: TypeAdapter[list[_T]] = TypeAdapter(list[model])  # type: ignore[valid-type]
    return tuple(adapter.validate_python(raw))


@lru_cache(maxsize=1)
def load_owasp_llm() -> Sequence[OwaspLlmEntry]:
    """OWASP LLM Top 10 (2025)."""
    return _load("owasp_llm_top10_2025.yaml", OwaspLlmEntry)


@lru_cache(maxsize=1)
def load_owasp_asi() -> Sequence[OwaspAsiEntry]:
    """OWASP Agentic Security Initiative Top 10 (2026)."""
    return _load("owasp_asi_2026.yaml", OwaspAsiEntry)


@lru_cache(maxsize=1)
def load_atlas_tactics() -> Sequence[AtlasTactic]:
    """MITRE ATLAS tactics."""
    return _load("mitre_atlas_tactics.yaml", AtlasTactic)


@lru_cache(maxsize=1)
def load_atlas_techniques() -> Sequence[AtlasTechnique]:
    """MITRE ATLAS techniques (and sub-techniques)."""
    return _load("mitre_atlas_techniques.yaml", AtlasTechnique)


def load_atlas() -> Sequence[AtlasTechnique]:
    """Convenience wrapper returning ATLAS techniques.

    The CLI uses this to give a single list-shaped view; consumers that need
    tactics call :func:`load_atlas_tactics` directly.
    """
    return load_atlas_techniques()


@lru_cache(maxsize=1)
def load_nist_ai_rmf() -> Sequence[NistAiRmfSubcategory]:
    """NIST AI RMF subcategories (subset relevant to red-team evidence)."""
    return _load("nist_ai_rmf.yaml", NistAiRmfSubcategory)
