"""Pydantic models for the bundled threat-taxonomy data."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_FROZEN = ConfigDict(frozen=True, extra="forbid")

FrameworkId = Literal["owasp-llm", "owasp-asi", "atlas", "nist-ai-rmf"]


class CrossRef(BaseModel):
    """A reference from a taxonomy entry to an entry in another framework."""

    model_config = _FROZEN

    framework: FrameworkId
    id: str


class _Base(BaseModel):
    """Common fields shared by every framework entry."""

    model_config = _FROZEN

    id: str = Field(..., description="The framework's canonical ID, e.g. 'LLM01'.")
    name: str
    description: str
    source_url: str = Field(..., description="Canonical publisher URL for this entry.")
    framework_version: str = Field(
        ...,
        description="Version label as published (e.g. '2025', '2026', 'v5.4.0').",
    )
    references: list[CrossRef] = Field(default_factory=list)


class OwaspLlmEntry(_Base):
    """One of the OWASP LLM Top 10 entries."""


class OwaspAsiEntry(_Base):
    """One of the OWASP Agentic Security Initiative Top 10 entries."""


class AtlasTactic(_Base):
    """A MITRE ATLAS tactic (high-level adversary goal)."""


class AtlasTechnique(_Base):
    """A MITRE ATLAS technique. May reference a tactic via ``references``."""

    tactic_ids: list[str] = Field(
        default_factory=list,
        description="ATLAS tactic IDs this technique belongs to.",
    )
    sub_technique_of: str | None = Field(
        default=None,
        description="Parent technique ID if this entry is a sub-technique.",
    )


class NistAiRmfSubcategory(_Base):
    """A NIST AI RMF function/subcategory."""

    function: Literal["GOVERN", "MAP", "MEASURE", "MANAGE"]
