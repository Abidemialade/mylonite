"""Self-contained HTML report renderer (G1)."""

from __future__ import annotations

from typing import Any

from mylonite.report.html import render_scan_html, render_validation_html, severity_for


def _exploit(weakness: str, *, effect: str = "unprobed", nist: list[str] | None = None) -> Any:
    from mylonite.contracts._types import (
        AdapterResponse,
        ComplianceTags,
        ExploitRecord,
        Payload,
    )

    pid = f"finding-{weakness.lower()}"
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(
            pattern_id=pid, channel="tool-result", body="payload", metadata={"weakness": weakness}
        ),
        response=AdapterResponse(
            payload_pattern_id=pid,
            raw_response="the agent followed the injected instruction",
            tool_calls=["read_note", "send_email"],
            metadata={"effect_confirmed": effect},
        ),
        success_reason=f"{weakness} weakness reproduced on the target",
        compliance=ComplianceTags(owasp_llm=["LLM01"], nist_ai_rmf=nist or ["MEASURE-2.7"]),
    )


def _scan_report(findings: int) -> Any:
    from mylonite.contracts._types import ScanReport

    return ScanReport(
        target_id="mcp:myapp",
        attack_modules=["mylonite.prompt-injection"],
        provider="anthropic",
        model="claude-haiku-4-5",
        elapsed_seconds=12.3,
        attempts=[],
        findings_count=findings,
        aborted=None,
        single_run=True,
        mylonite_version="0.7.0-test",
    )


def _is_self_contained(html: str) -> None:
    low = html.lower()
    assert "<!doctype html" in low
    assert "<script" not in low  # no JavaScript
    assert "http://" not in low and "https://" not in low  # no external assets/CDN
    assert "googleapis" not in low and "cdn" not in low and "@import" not in low


# --- severity rule ----------------------------------------------------------


def test_severity_rule() -> None:
    assert severity_for("W4", "true") == "High"
    assert severity_for("W2") == "High"  # exfil/excessive-agency class that landed
    assert severity_for("W3") == "High"
    assert severity_for("W1") == "Medium"  # description-smuggle, no damaging effect
    assert severity_for("W1", situational=True) == "Low"


# --- scan dashboard ---------------------------------------------------------


def test_scan_html_is_structured_and_self_contained() -> None:
    html = render_scan_html(
        _scan_report(2),
        [_exploit("W2", effect="true"), _exploit("W1")],
    )
    _is_self_contained(html)
    assert "Mylonite security report" in html  # exec summary header
    assert "mcp:myapp" in html and "claude-haiku-4-5" in html  # run metadata
    assert "2 findings" in html
    assert "High" in html and "Medium" in html  # severity badges for both
    assert "<details" in html and "<summary" in html  # collapsible evidence, no JS
    assert "NIST MEASURE-2.7" in html  # compliance chips (consistent post-Theme G)
    assert "read_note, send_email" in html  # tool trace in the evidence block


def test_scan_html_clean_scan_is_a_pass() -> None:
    html = render_scan_html(_scan_report(0), [])
    _is_self_contained(html)
    assert "No findings" in html
    assert "verdict pass" in html


def test_scan_html_escapes_dynamic_text() -> None:
    """A payload/response containing HTML must not break the page (escaped)."""
    ex = _exploit("W2")
    ex = ex.model_copy(
        update={
            "response": ex.response.model_copy(
                update={"raw_response": "<script>alert(1)</script> & <b>x</b>"}
            )
        }
    )
    html = render_scan_html(_scan_report(1), [ex])
    assert "<script>alert(1)</script>" not in html  # escaped, not live
    assert "&lt;script&gt;" in html


# --- validation dashboard ---------------------------------------------------


def test_validation_html_renders_verdict() -> None:
    from mylonite.contracts._types import ReproducibilityEvidence, ValidationReport

    report = ValidationReport(
        test_filename="test_security_finding.py",
        kept=True,
        gating_formula="kept = build AND differential AND flakiness",
        reproducibility=ReproducibilityEvidence(iterations=5, vuln_fired=5, guard_resisted=5),
    )
    html = render_validation_html(report, _exploit("W2", effect="true"))
    _is_self_contained(html)
    assert "KEPT" in html
    assert "vulnerable fired 5/5" in html and "guarded resisted 5/5" in html
    assert "test_security_finding.py" in html
