"""Shared Pydantic data types for the Phase 1 scan loop.

``Verdict`` is the output of a ``SuccessJudge``-or-predicate decision: a single
attempt either succeeded (the exploit landed), was inconclusive (no signal), or
was skipped (planner failure / invalid metadata). Predicates return
``Verdict | None`` — ``None`` means "the predicate did not fire," and the
``SuccessJudge`` falls back to the LLM-judge rubric (PR 2).

These types live under ``scan/_types.py`` rather than ``scan/judge.py`` so the
predicate functions (PR 1) can return ``Verdict`` without forward references to
judge code that lands in PR 2.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class AdapterInvocationSkipped(RuntimeError):
    """Raised by a TargetAdapter's ``invoke()`` when an attempt cannot be judged.

    Phase 1's in-process adapter (and future MCP-wire adapters) raise this on
    planner failure (A3 from the eng review) — the LLM call inside the planner
    threw, so the trace is partial and judging it would produce false signals.

    ScanEngine catches it, records ``outcome="skipped_planner_failure"`` in
    ``scan_report.json``, and moves to the next seed without scoring this one.
    """

    def __init__(self, reason: str, *, attempt_metadata: dict[str, str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.attempt_metadata = attempt_metadata or {}


class Verdict(BaseModel):
    """Outcome of a single judging step.

    ``success=True`` means the attempt produced an actionable exploit. The
    ``mechanism`` field records *how* we concluded that — a deterministic
    predicate fired, or the LLM-judge fallback returned high confidence.
    """

    model_config = _FROZEN

    success: bool
    reason: str = Field(
        ...,
        description="Human-readable justification, surfaced in CLI summary and ExploitRecord.",
    )
    evidence: dict[str, object] = Field(
        default_factory=dict,
        description="Structured evidence (tool calls, recipients, matched markers) keyed by name.",
    )
    mechanism: Literal["predicate", "llm"] = Field(
        ...,
        description="Which judging mechanism produced this verdict.",
    )
