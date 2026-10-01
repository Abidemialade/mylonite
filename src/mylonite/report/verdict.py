"""The verdict each export shows for one finding, shared by SARIF and the bundle.

A finding reaches an export in one of four states: never validated (a scan
finding), or validated as KEPT, STABLE, NOT PROVEN or REJECTED
(:func:`mylonite._verdict.verdict_label`). Only a KEPT finding earns the proof
claim and a security severity; the others say what the run showed instead.
"""

from __future__ import annotations

from typing import Any, Final

from mylonite._verdict import KEPT, REJECTED, STABLE_NOT_PROVEN, verdict_label

#: The label for a scan finding that no validation has looked at.
UNVALIDATED: Final = "UNVALIDATED"

STATUS_KEPT: Final = "kept"
STATUS_STABLE_NOT_PROVEN: Final = "stable, not proven"
STATUS_NOT_REPRODUCED: Final = "not reproduced on this model"
STATUS_REJECTED: Final = "rejected"


def finding_verdict(report: Any | None) -> str:
    """``UNVALIDATED`` with no report, else the report's verdict label."""
    if report is None:
        return UNVALIDATED
    return verdict_label(report)


def proof_status(report: Any) -> str:
    """A short phrase for what a validation showed, next to its label."""
    label = verdict_label(report)
    if label == KEPT:
        return STATUS_KEPT
    if label == STABLE_NOT_PROVEN:
        return STATUS_STABLE_NOT_PROVEN
    repro = getattr(report, "reproducibility", None)
    if repro is not None and repro.iterations > 0 and repro.vuln_fired == 0:
        return STATUS_NOT_REPRODUCED
    return STATUS_REJECTED


__all__ = [
    "KEPT",
    "REJECTED",
    "STABLE_NOT_PROVEN",
    "STATUS_KEPT",
    "STATUS_NOT_REPRODUCED",
    "STATUS_REJECTED",
    "STATUS_STABLE_NOT_PROVEN",
    "UNVALIDATED",
    "finding_verdict",
    "proof_status",
]
