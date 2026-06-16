"""Adaptive attack loop (Driver 1 / Slice 2).

When a single indirect-injection attempt does not fire — typically an aligned
planner refusing a poisoned note — an LLM strategist inspects the planner trace
and the judge's reason, re-crafts the INJECTION payload, and retries against a
fresh session, within a budget. The loop carries the refinement learning across
attempts; each attempt is an isolated session (Slice 1).

Slice 2 consumes an ``AttackPlan`` describing how to plant + drive for the
target; Slice 3 will auto-discover that plan from the tool surface.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from mylonite.contracts._types import AdapterResponse
from mylonite.scan._types import Verdict

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttackPlan:
    """How to deliver an injection to a specific target.

    Templates use the literal tokens ``{id}`` (a freshly minted artefact id) and
    ``{payload}`` (the current injection body). The driver substitutes by literal
    string replacement (not ``str.format``) so arbitrary payload text with braces
    is safe.
    """

    plant_tool: str
    plant_args: dict[str, str]
    drive_message: str


@dataclass(frozen=True)
class AdaptiveOutcome:
    """The result of an adaptive loop run."""

    success: bool
    attempts: int
    final_body: str
    response: AdapterResponse | None
    verdict: Verdict | None
