"""The one definition of which metadata keys are trace evidence or verdict output.

``collect`` copies :data:`VERDICT_EVIDENCE_KEYS` into each capture's verdict;
``build_cases`` strips :data:`TRACE_METADATA_KEYS` to make the
``shadow_stripped`` family; ``labels`` hides :data:`BLINDED_KEYS` (both, plus the
verdict's own fields) from review packets. Keeping them here is what stops the
three from drifting apart.
"""

from __future__ import annotations

#: Response metadata keys that carry the recorded trace, the effect probe, or
#: an input to the deterministic trace rule (``EffectEvidence.from_metadata``
#: and the judge's ``_TRACE_METADATA_KEYS``). Removing them makes an MCP
#: response look like a tool-less one.
TRACE_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "effect_trace",
        "mcp_trace_planner",
        "mcp_trace_setup",
        "trace_outcome",
        "link",
        "marker_kind",
        "marker_linked",
        "calibrated",
        "confirm_capable",
        "probe_certified",
        "seed_control",
        "any_deferred",
        "removal_confirmed",
        "removal_note",
        "effect_confirmed",
        "effect_probe_verify_tool",
    }
)

#: The trace keys that hold the planner's tool calls (``{tool, args, result}``
#: lists). Review packets show these parsed, as the raw facts of the attempt.
TRACE_CALL_KEYS: tuple[str, ...] = ("effect_trace", "mcp_trace_planner")

#: Verdict evidence keys a capture keeps when present.
VERDICT_EVIDENCE_KEYS: tuple[str, ...] = (
    "proof_level",
    "trace_outcome",
    "link",
    "effect_confirmed",
    "negative_basis",
    "reason_code",
    "no_adjudicator",
)

#: A verdict's own fields, as a capture records them.
VERDICT_FIELDS: frozenset[str] = frozenset(
    {"success", "mechanism", "verdict", "reason", "confidence", "fallback_cause", "applicable"}
)

#: Everything a blinded reviewer must not see as metadata: the verdict, its
#: evidence, and every input the deterministic rule decides on.
BLINDED_KEYS: frozenset[str] = (
    TRACE_METADATA_KEYS | VERDICT_FIELDS | frozenset(VERDICT_EVIDENCE_KEYS)
)

__all__ = [
    "BLINDED_KEYS",
    "TRACE_CALL_KEYS",
    "TRACE_METADATA_KEYS",
    "VERDICT_EVIDENCE_KEYS",
    "VERDICT_FIELDS",
]
