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
    weakness_classes: list[str] = Field(
        default_factory=list,
        description=(
            "Weakness classes this target opts into, e.g. ['W2', 'W4']. When "
            "non-empty, seed selection resolves from these declared classes "
            "(letting a custom/external target opt into attack shapes) instead "
            "of the legacy family mapping derived from target_id. Empty = use "
            "the family mapping (the bundled reference/filesystem/fetch/github "
            "targets leave it empty and are unaffected)."
        ),
    )


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


class SeedKill(BaseModel):
    """One row of the mutation kill matrix.

    Did the generated test catch this seeded weakness — i.e. did the vulnerable
    twin FIRE this seed while the guarded twin RESISTED it? This is the
    per-seed evidence behind ``ValidationReport.mutation_score``; rendering it
    makes the differential oracle's discrimination legible instead of a bare
    scalar.
    """

    model_config = _FROZEN

    pattern_id: str = Field(..., description="The kitchen-sink seed's pattern_id.")
    weakness: str = Field(..., description="The weakness class (e.g. W1-W4) the seed exercises.")
    killed: bool = Field(
        ...,
        description="True iff vulnerable fired this seed AND guarded resisted it.",
    )


class ReproducibilityEvidence(BaseModel):
    """The per-iteration counts behind the differential/flakiness legs.

    For the reference path both twins run each iteration, so ``vuln_fired`` and
    ``guard_resisted`` are populated. For a custom target (no in-repo guarded
    twin) only the real target is re-driven, so ``vuln_fired`` is the reproduced
    count and ``guard_resisted`` is ``None``.
    """

    model_config = _FROZEN

    iterations: int = Field(..., ge=0, description="Number of differential/flakiness iterations.")
    vuln_fired: int | None = Field(
        default=None,
        ge=0,
        description="Iterations where the vulnerable twin (or the real target) fired the exploit.",
    )
    guard_resisted: int | None = Field(
        default=None,
        ge=0,
        description="Iterations where the guarded twin resisted; None for custom targets.",
    )
    # --- statistical differential evidence (added v0.5.0) ---------------------
    # The success-rate oracle keeps a test on the RATE gap between the twins, not
    # a count threshold. Optional/back-compatible: a report omitting them is still
    # valid (e.g. custom-target or older artefacts).
    guard_fired: int | None = Field(
        default=None,
        ge=0,
        description="Iterations where the guarded twin LEAKED (fired); None for custom targets.",
    )
    rate_gap: float | None = Field(
        default=None,
        ge=-1.0,
        le=1.0,
        description=(
            "Attack success-rate gap = vulnerable-fire-rate minus guarded-leak-rate, "
            "[-1,1]. The headline statistic the differential leg gates on."
        ),
    )


class ValidationOutcome(BaseModel):
    """One leg of the differential-oracle pipeline."""

    model_config = _FROZEN

    stage: Literal[
        "build",
        "differential",
        "flakiness",
        "metamorphic",
        # Custom-target legs (no in-repo guarded twin): re-drive the real target.
        "stability",
        "effect",
        "consensus",
    ]
    passed: bool
    detail: str
    metric: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Optional per-stage numeric — flakiness: reproducibility fraction "
            "[0,1]; differential: agreement fraction; metamorphic: robustness "
            "rate."
        ),
    )


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
    mutation_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Fraction of the seeded-weakness bank the generated test correctly "
            "catches (fails-on-vulnerable), [0,1]."
        ),
    )
    # --- structured evidence (added v0.4.0) -----------------------------------
    # The differential oracle's discrimination evidence, lifted out of the
    # free-text ``notes`` so surfaces (console report, PR body, JSON artefact)
    # can render it. All optional/back-compatible — a report omitting them is
    # still valid and renders as before.
    gating_formula: str | None = Field(
        default=None,
        description=(
            "Human-readable gate, e.g. 'kept = build AND differential AND "
            "flakiness'. The legs that actually decide ``kept``."
        ),
    )
    gating_legs: list[str] = Field(
        default_factory=list,
        description="Ordered stage names that gate ``kept`` (a subset of ``outcomes``).",
    )
    reproducibility: ReproducibilityEvidence | None = Field(
        default=None,
        description="Per-iteration fire/resist counts behind the differential/flakiness legs.",
    )
    mutation_matrix: list[SeedKill] = Field(
        default_factory=list,
        description="Per-seed kill matrix behind ``mutation_score``.",
    )


# --- Scan report --------------------------------------------------------------


ScanAttemptOutcome = Literal[
    "finding",
    "no_finding",
    "skipped_invalid_metadata",
    "skipped_unknown_seed",
    "skipped_planner_failure",
    "skipped_no_seed_arm",
    "skipped_payload_not_delivered",
    "skipped_dry_run",
    "error",
]


class ScanAttempt(BaseModel):
    """One attempt against the target — every seed produces exactly one."""

    model_config = _FROZEN

    seed_id: str = Field(..., description="The originating seed pattern_id.")
    pattern_id: str = Field(..., description="Payload pattern_id (matches the seed in v0.2).")
    outcome: ScanAttemptOutcome
    verdict_mechanism: Literal["predicate", "llm"] | None = Field(
        default=None,
        description="How the verdict was decided; None for skip/error outcomes.",
    )
    verdict_reason: str | None = Field(
        default=None,
        description="Verdict.reason verbatim, or the skip/error explanation.",
    )
    error_detail: str | None = Field(
        default=None,
        description="Captured exception text on outcome=error; None otherwise.",
    )
    tool_call_trace: list[str] = Field(
        default_factory=list,
        description=(
            "Names of tools the target's planner invoked, in order — persisted "
            "for EVERY judged attempt (finding and no_finding) so a finding is "
            "auditable from the report alone."
        ),
    )
    judge_evidence: dict[str, str] = Field(
        default_factory=dict,
        description="Verdict.evidence flattened to strings (recipients, markers, confidence).",
    )


class ScanReport(BaseModel):
    """Run-metadata sibling of ExploitRecord; written to scan_report.json.

    This is schema-validated under ``scripts/regenerate_schemas.py``
    so CI catches drift and downstream consumers can validate the
    report shape without depending on the Python package.
    """

    model_config = _FROZEN

    target_id: str
    attack_modules: list[str] = Field(default_factory=list)
    provider: str
    model: str
    elapsed_seconds: float
    attempts: list[ScanAttempt] = Field(default_factory=list)
    findings_count: int
    inconclusive_attempts: int = Field(
        default=0,
        description=(
            "Number of attempts whose verdict came from an LLM-judge fallback "
            "(the call raised, or its output was unparseable) rather than a real "
            "judgement. A scan where this equals the judged-attempt count found "
            "nothing because it could not judge — not because the target is secure."
        ),
    )
    fallback_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Counts of fallback events by cause, e.g. {'judge_unparseable_output': n, "
            "'judge_call_raised': n, 'customiser_fallback': n}."
        ),
    )
    aborted: str | None = Field(
        default=None,
        description=(
            "Non-null if the scan terminated early or ran nothing. Values: "
            "'budget_exceeded' (--max-llm-calls hit), 'provider_unreachable' "
            "(consecutive LLM failures), 'describe_failed' (adapter.describe() "
            "raised), or 'no_payloads' (no seeds were applicable to the target — "
            "the scan did not actually exercise anything)."
        ),
    )
    single_run: bool = Field(
        default=True,
        description=(
            "A single-shot scan runs each seed once. The 5-run flakiness filter "
            "set this to False when those replays land."
        ),
    )
    mylonite_version: str
