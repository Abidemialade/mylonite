"""Cross-model durability summary (T2).

A weakness fixed and gated against one model can silently re-emerge when a team
upgrades the model — a blind spot developers have no regression for. Because
Mylonite is model-agnostic (every call flows through LiteLLM), it can re-prove the
SAME differential across several model versions and flag the ones where the
guarantee no longer holds: "the control is load-bearing on A and B, but the weakness
re-emerges on C". This module is the pure summary over per-model validation reports;
the live re-runs are driven by ``mylonite validate --models``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CrossModelRow:
    """One model's validation outcome in the durability table."""

    model: str
    kept: bool
    vuln_fired: int
    guard_resisted: int
    iterations: int


def row_from_report(model: str, report: Any) -> CrossModelRow:
    """Build a durability row from a ``ValidationReport`` (kept + reproducibility)."""
    repro = getattr(report, "reproducibility", None)
    return CrossModelRow(
        model=model,
        kept=bool(getattr(report, "kept", False)),
        vuln_fired=(getattr(repro, "vuln_fired", 0) or 0) if repro is not None else 0,
        guard_resisted=(getattr(repro, "guard_resisted", 0) or 0) if repro is not None else 0,
        iterations=(getattr(repro, "iterations", 0) or 0) if repro is not None else 0,
    )


def summarize_cross_model(rows: Sequence[CrossModelRow]) -> tuple[bool, str]:
    """Return ``(all_durable, rendered_summary)``.

    ``all_durable`` is True iff EVERY tested model keeps the test (the control holds
    across the whole set). Any model that fails is called out by name — that's a
    silent-re-introduction risk a single-model validation can't see.
    """
    all_durable = all(r.kept for r in rows)
    lines = ["Cross-model durability:"]
    for r in rows:
        mark = "✓ durable" if r.kept else "✗ RE-EMERGES"
        lines.append(
            f"  {r.model}: {mark} "
            f"(vulnerable fired {r.vuln_fired}/{r.iterations}, "
            f"guarded resisted {r.guard_resisted}/{r.iterations})"
        )
    if rows and not all_durable:
        failed = ", ".join(r.model for r in rows if not r.kept)
        lines.append(
            f"Durability gap: the guarantee does NOT hold on {failed} — upgrading to that "
            "model could silently re-introduce this weakness. Re-fix and re-validate before "
            "shipping on it."
        )
    elif rows:
        lines.append("The control holds across all tested models — the fix is durable to upgrade.")
    else:
        lines.append("(no models tested)")
    return all_durable, "\n".join(lines)
