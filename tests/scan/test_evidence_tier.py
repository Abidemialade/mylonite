"""The evidence tier: what a verdict rests on (state, trace, or the judge alone)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.contracts import ScanAttempt, ScanReport
from mylonite.scan.evidence_tier import (
    EVIDENCE_TIERS,
    attempt_evidence_tier,
    evidence_tier,
    tier_counts,
)

_FIXTURE_0_10_4 = Path(__file__).resolve().parents[1] / "fixtures" / "scan_report_0_10_4.json"


@pytest.mark.parametrize(
    ("mechanism", "evidence", "expected"),
    [
        # The trace rule's proof level decides first.
        ("predicate", {"proof_level": "effect-confirmed"}, "state"),
        ("predicate", {"proof_level": "dispatched"}, "trace"),
        ("predicate", {"proof_level": "dispatched-tool-linked"}, "trace"),
        # An uncalibrated probe's "true" the rule only credited as a dispatch.
        ("predicate", {"proof_level": "dispatched", "effect_confirmed": "true"}, "trace"),
        # No proof level: a target or report with no trace outcome.
        ("predicate", {"effect_confirmed": "true"}, "state"),
        ("predicate", {"effect_confirmed": "unprobed"}, "trace"),
        ("predicate", {}, "trace"),
        ("llm", {"confidence": "0.95"}, "judge-only"),
        # The judge's rationale disagreed with the trace and the finding was kept.
        ("llm", {"rationale_trace_mismatch": "scaffold_tools_unknown"}, "judge-only"),
        ("llm", {"effect_confirmed": "true"}, "state"),
        (None, {}, None),
    ],
)
def test_evidence_tier_rule(
    mechanism: str | None, evidence: dict[str, object], expected: str | None
) -> None:
    assert evidence_tier(mechanism, evidence) == expected


def _attempt(outcome: str, mechanism: str | None, **evidence: str) -> ScanAttempt:
    return ScanAttempt(
        seed_id="s",
        pattern_id="s",
        outcome=outcome,  # type: ignore[arg-type]
        verdict_mechanism=mechanism,  # type: ignore[arg-type]
        judge_evidence=evidence,
    )


def test_attempt_tier_only_for_decided_outcomes() -> None:
    assert attempt_evidence_tier(_attempt("finding", "llm")) == "judge-only"
    assert attempt_evidence_tier(_attempt("no_finding", "predicate")) == "trace"
    assert attempt_evidence_tier(_attempt("undecided", "llm", fallback_cause="x")) is None
    assert attempt_evidence_tier(_attempt("not_applicable", "llm")) is None
    # A pre-`undecided` report spelled a no-verdict attempt `no_finding`.
    assert attempt_evidence_tier(_attempt("no_finding", "llm", fallback_cause="x")) is None


def test_tier_counts_has_every_tier() -> None:
    attempts = [
        _attempt("finding", "llm"),
        _attempt("finding", "predicate", proof_level="effect-confirmed"),
        _attempt("no_finding", "predicate"),
    ]
    assert tier_counts(attempts) == {"state": 1, "trace": 1, "judge-only": 1}
    assert tuple(tier_counts([])) == EVIDENCE_TIERS


def test_reclassifies_an_older_scan_report_offline() -> None:
    """A scan_report.json written before tiers existed still gets one per finding."""
    report = ScanReport.model_validate_json(_FIXTURE_0_10_4.read_text(encoding="utf-8"))
    tiers = {a.outcome: attempt_evidence_tier(a) for a in report.attempts}
    assert tiers["finding"] == "state"  # its effect probe confirmed the effect
    assert tiers["no_finding"] == "trace"
    assert tiers["undecided"] is None
    assert tiers["not_applicable"] is None


# --- the scan summary ----------------------------------------------------------


def _summary_for(*attempts: ScanAttempt) -> str:
    from mylonite.scan.artefacts import render_summary
    from mylonite.scan.engine import ScanResult

    report = ScanReport(
        target_id="mcp:custom",
        attack_modules=["m"],
        provider="anthropic",
        model="stub",
        elapsed_seconds=1.0,
        attempts=list(attempts),
        findings_count=sum(1 for a in attempts if a.outcome == "finding"),
        mylonite_version="0.10.5",
    )
    return render_summary(ScanResult(report=report, exploits=[]), ascii_safe=True)


def _row(summary: str, seed_id: str) -> str:
    return next(line for line in summary.splitlines() if seed_id in line)


def test_the_found_table_shows_each_tier() -> None:
    summary = _summary_for(
        _attempt("finding", "predicate", proof_level="effect-confirmed").model_copy(
            update={"seed_id": "seed-state"}
        ),
        _attempt("finding", "predicate", proof_level="dispatched").model_copy(
            update={"seed_id": "seed-trace"}
        ),
        _attempt("finding", "llm").model_copy(update={"seed_id": "seed-judge"}),
        _attempt("undecided", "llm", fallback_cause="x").model_copy(
            update={"seed_id": "seed-undecided"}
        ),
    )
    assert "evidence" in summary
    assert "state" in _row(summary, "seed-state")
    assert "trace" in _row(summary, "seed-trace")
    assert "judge-only" in _row(summary, "seed-judge")
    undecided = _row(summary, "seed-undecided")
    assert not any(tier in undecided for tier in EVIDENCE_TIERS)
    assert "findings by evidence: 1 state, 1 trace, 1 judge-only" in summary


def test_the_summary_of_an_older_scan_report_shows_the_derived_tier() -> None:
    """`mylonite report` renders a saved scan_report.json through the same summary."""
    report = ScanReport.model_validate_json(_FIXTURE_0_10_4.read_text(encoding="utf-8"))
    finding = next(a for a in report.attempts if a.outcome == "finding")
    assert "evidence_tier" not in finding.judge_evidence  # written before tiers existed
    summary = _summary_for(*report.attempts)
    assert "state" in _row(summary, finding.seed_id)
