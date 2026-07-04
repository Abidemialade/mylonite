"""The shared finding-severity rule (used by the SARIF + JSON-bundle exports)."""

from __future__ import annotations

from mylonite.report.severity import severity_for


def test_severity_rule() -> None:
    assert severity_for("W4", "true") == "High"
    assert severity_for("W2") == "High"  # exfil/excessive-agency class that landed
    assert severity_for("W3") == "High"
    assert severity_for("W1") == "Medium"  # description-smuggle, no damaging effect
    assert severity_for("W1", situational=True) == "Low"
