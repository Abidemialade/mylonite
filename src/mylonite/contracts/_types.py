"""Shared Pydantic models for the five extension-point contracts.

These models are the wire format between Mylonite core, plugins, and the
community attack-pattern registry. JSON schemas under ``src/mylonite/schemas/``
are generated from these models — keep them in sync via
``scripts/regenerate_schemas.py``.

All models are frozen and forbid extras to make backwards-compatibility
breakage loud rather than silent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_FROZEN = ConfigDict(frozen=True, extra="forbid")


# --- Compliance tags ---------------------------------------------------------


class ComplianceTags(BaseModel):
    """Standards-framework IDs attached to an attack or exploit record."""

    model_config = _FROZEN

    owasp_llm: list[str] = Field(
        default_factory=list,
        description="OWASP LLM Top 10 (2025) IDs, e.g. ['LLM01'].",
    )
    owasp_asi: list[str] = Field(
        default_factory=list,
        description="OWASP Agentic Security Initiative (2026) IDs, e.g. ['ASI01'].",
    )
    mitre_atlas: list[str] = Field(
        default_factory=list,
        description="MITRE ATLAS technique IDs, e.g. ['AML.T0051'].",
    )
    nist_ai_rmf: list[str] = Field(
        default_factory=list,
        description="NIST AI RMF function/subcategory tags, e.g. ['MEASURE-2.6'].",
    )


# --- Targets -----------------------------------------------------------------


TargetKind = Literal["mcp", "rag", "http-agent", "custom"]


class ToolSpec(BaseModel):
    """A single tool exposed by an agentic target."""

    model_config = _FROZEN

    name: str
    description: str
    json_schema: dict[str, object] = Field(
        default_factory=dict,
        description="JSON Schema for the tool's input.",
    )


class TargetDescriptor(BaseModel):
    """A target's self-description, produced by a TargetAdapter.

    This is the input the exploit-finding agent reasons over: the system
    prompt it can see, the tool surface, the data sources, the planner shape.
    """

    model_config = _FROZEN

    target_id: str = Field(..., description="Stable identifier for this target.")
    kind: TargetKind
    system_prompt: str | None = None
    tools: list[ToolSpec] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    notes: str | None = None


# --- Attacks -----------------------------------------------------------------


class AttackPattern(BaseModel):
    """Static metadata for an attack module."""

    model_config = _FROZEN

    id: str = Field(..., description="Stable pattern ID, e.g. 'indirect-injection-read-note'.")
    name: str
    summary: str
    target_kinds: list[TargetKind]
    compliance: ComplianceTags
    references: list[str] = Field(
        default_factory=list,
        description="External URLs (papers, blog posts, prior write-ups).",
    )


class Payload(BaseModel):
    """A concrete attack payload to deliver to a target."""

    model_config = _FROZEN

    pattern_id: str = Field(..., description="ID of the AttackPattern this payload realises.")
    channel: Literal[
        "user-message",
        "tool-result",
        "rag-document",
        "system-prompt-injection",
        "tool-description",
    ] = Field(..., description="Where the payload is delivered into the target.")
    body: str
    metadata: dict[str, str] = Field(default_factory=dict)


# --- Adapter responses --------------------------------------------------------


class AdapterResponse(BaseModel):
    """The target's response to a payload, as captured by an adapter."""

    model_config = _FROZEN

    payload_pattern_id: str
    raw_response: str
    tool_calls: list[str] = Field(
        default_factory=list,
        description="Names of tools invoked by the target while processing the payload.",
    )
    metadata: dict[str, str] = Field(default_factory=dict)


# --- Exploits and tests -------------------------------------------------------


class ExploitRecord(BaseModel):
    """A confirmed weakness against a target: payload + observed outcome."""

    model_config = _FROZEN

    target_id: str
    pattern_id: str
    payload: Payload
    response: AdapterResponse
    success_reason: str = Field(
        ...,
        description="Human-readable justification of why this counts as a successful exploit.",
    )
    compliance: ComplianceTags


class GeneratedTest(BaseModel):
    """A regression test the test-generator emits from an ExploitRecord."""

    model_config = _FROZEN

    framework: Literal["pytest", "jest"]
    filename: str
    source: str = Field(..., description="The test file's source code.")
    exploit: ExploitRecord


# --- Validation reports -------------------------------------------------------


class ValidationOutcome(BaseModel):
    """One leg of the differential-oracle pipeline."""

    model_config = _FROZEN

    stage: Literal["build", "differential", "flakiness", "metamorphic"]
    passed: bool
    detail: str


class ValidationReport(BaseModel):
    """Validator output for a single GeneratedTest."""

    model_config = _FROZEN

    test_filename: str
    outcomes: list[ValidationOutcome] = Field(default_factory=list)
    kept: bool = Field(
        ...,
        description="True iff the test passes every stage and should be committed.",
    )
    notes: str | None = None
